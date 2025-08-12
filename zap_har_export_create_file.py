#!/usr/bin/env python3
# zap_har_export_create_file.py
"""
Decode OWASP ZAP HAR export (2xx-only):
• HAR 1.2 (`.har`, JSON) 파일을 읽어 각 응답 본문을 원본 파일로 복원.
• 처음부터 응답 상태가 2xx인 항목만 처리(3xx/4xx/5xx 등은 필터링).
• Content-Disposition의 filename*/filename을 우선 적용해 저장 파일명 결정.
• URL 경로의 퍼센트 인코딩을 디코딩하고, 세그먼트별 sanitize + Unicode NFC 정규화.
• MIME → 확장자 부여(본문 시그니처 스니핑 포함), URL 무확장 시 query-MD5 유일화.
• Summary 출력 후 ZIP 압축(진행률 + 현재 파일명 표시).

Usage:
    python zap_har_export_create_file.py <input.har>
"""

from __future__ import annotations
import sys, json, base64, hashlib, zipfile, urllib.parse, re, unicodedata
from pathlib import Path
from typing import Tuple
from urllib.parse import urlsplit, urlunsplit, unquote

# ── colour (optional)
try:
    from colorama import init as _cinit, Fore, Style
    _cinit(convert=True)
    CLR = Style.RESET_ALL
    GRN, YEL, RED, CYN = Fore.GREEN, Fore.YELLOW, Fore.RED, Fore.CYAN
except ImportError:
    CLR = GRN = YEL = RED = CYN = ""

# ── MIME ↔ 확장자 매핑
MIME_EXT = {
    "text/html": ".html", "html": ".html",
    "text/css": ".css",   "css": ".css",
    "application/javascript": ".js", "text/javascript": ".js",
    "script": ".js", "js": ".js",
    "application/json": ".json", "json": ".json",
    "text/plain": ".txt", "txt": ".txt",
    "image/jpeg": ".jpg", "image/png": ".png", "image/gif": ".gif",
    "image/svg+xml": ".svg",
    "application/pdf": ".pdf",
    "text": ".txt",
}

# ── MIME 추론(본문 시그니처 스니핑)
def guess_mime(body: bytes) -> str:
    if body.startswith(b"%PDF-"):                        # PDF 헤더
        return "application/pdf"
    h = body[:200].lower()
    if h.startswith(b"<!doctype") or b"<html" in h:
        return "text/html"
    if h.startswith(b"{") or h.startswith(b"["):
        return "application/json"
    if h.startswith(b"\xff\xd8"):
        return "image/jpeg"
    if h.startswith(b"\x89png"):
        return "image/png"
    if h.startswith(b"gif8"):
        return "image/gif"
    if b"function(" in h or b"var " in h:
        return "application/javascript"
    if b"body{" in h or b"{font" in h:
        return "text/css"
    return "text/plain"

# ── Content-Disposition filename/filename* 파싱
_ILLEGAL = r'<>:"/\\|?*\x00-\x1F'
_ILLEGAL_RE = re.compile(f"[{re.escape(_ILLEGAL)}]")

def sanitize_filename(name: str) -> str:
    # OS 위험 문자 제거 및 길이 제한
    name = name.strip().replace("\u202e", "")  # RTL override 방지
    name = _ILLEGAL_RE.sub("_", name)
    return name[:255] or "file"

def get_cd_filename(headers: list[dict]) -> str | None:
    """
    HAR entry.response.headers (list of {name,value})에서
    Content-Disposition을 찾아 filename*/filename을 파싱.
    RFC 6266에 따라 filename* 우선.
    """
    if not headers:
        return None
    cd = next((h.get("value") for h in headers
               if h.get("name","").lower() == "content-disposition"), None)
    if not cd:
        return None

    # 파라미터 파싱
    parts = [p.strip() for p in cd.split(";")]
    params: dict[str, str] = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            params[k.strip().lower()] = v.strip().strip('"')

    # RFC 5987: filename*=charset''percent-encoded
    fn_star = params.get("filename*")
    if fn_star:
        try:
            if "'" in fn_star:
                charset, _lang, enc_value = fn_star.split("'", 2)
                raw = urllib.parse.unquote_to_bytes(enc_value)
                return sanitize_filename(raw.decode(charset or "utf-8", "replace"))
        except Exception:
            pass

    # 전통적인 filename=
    fn = params.get("filename")
    if fn:
        try:
            fn = urllib.parse.unquote(fn)
        except Exception:
            pass
        return sanitize_filename(fn)
    return None

# ── 경로 디코딩 + 정규화 + 세그먼트별 sanitize
def _nfc(s: str) -> str:
    try:
        return unicodedata.normalize("NFC", s)
    except Exception:
        return s

def _decode_and_sanitize_path(path: str) -> tuple[Path, str]:
    # 1) percent-decode → 2) 앞의 / 제거 → 3) ., .. 제거
    # 4) 세그먼트별 sanitize → 5) Unicode NFC 정규화
    raw = urllib.parse.unquote(path or "")
    raw = raw.lstrip("/")
    parts = [seg for seg in raw.split("/") if seg not in ("", ".", "..")]
    parts = [_nfc(sanitize_filename(seg)) for seg in parts]
    parent = Path(*parts[:-1]) if len(parts) > 1 else Path()
    leaf = parts[-1] if parts else ""
    return parent, leaf

# ── 표시용(URL 로그용) 디코딩: 경로/쿼리/프래그먼트만 percent-decode
def format_url_for_log(u: str) -> str:
    """
    로그/에러 메시지에 사람이 읽기 좋은 URL을 보여주기 위한 포매터.
    - path/query/fragment만 percent-decode (UTF-8, errors='replace')
    - netloc(도메인)은 그대로 둠(처리에 영향 없도록)
    주의: 예약문자 디코딩은 해석을 바꿀 수 있으므로 실제 처리에는 raw URL을 유지.
    """
    try:
        p = urlsplit(u)
        path = unquote(p.path, encoding="utf-8", errors="replace")
        query = unquote(p.query, encoding="utf-8", errors="replace")
        frag  = unquote(p.fragment, encoding="utf-8", errors="replace")
        return urlunsplit((p.scheme, p.netloc, path, query, frag))
    except Exception:
        try:
            return unquote(u, encoding="utf-8", errors="replace")
        except Exception:
            return u

# ── URL 기반 파일 경로 결정
def make_filepath(url: str, mime: str, out_dir: Path) -> Tuple[Path, bool]:
    p = urllib.parse.urlparse(url)
    parent, leaf = _decode_and_sanitize_path(p.path)
    if leaf and Path(leaf).suffix:
        filename = leaf
    else:
        ext = MIME_EXT.get(mime) or (f".{mime}" if mime and "/" not in mime else ".bin")
        stem = Path(leaf).stem or "index"
        if p.query:
            md5 = hashlib.md5(p.query.encode()).hexdigest()
            stem = f"{stem}_{md5}"
        filename = stem + ext
    dest = out_dir / parent / filename
    return dest, dest.exists()

# ── 진행률/로그 출력
def log(msg: str, idx: int, tot: int) -> None:
    prog = f"{CYN}{idx}/{tot}{CLR}  ({idx / tot * 100:5.1f}%)" if tot else ""
    sys.stdout.write("\r" + " " * 120 + "\r")
    if msg:
        sys.stdout.write(f"{msg}\n")
    if prog:
        sys.stdout.write(f"\r{prog}")
    sys.stdout.flush()

# ── Summary 출력 (2xx 필터링 정보 포함)
def print_summary(total_all: int, total_2xx: int, succ: int, skip: int, fail: int,
                  filtered_non2xx: int, out_dir: Path, zip_name: Path) -> None:
    sys.stdout.write("\n\n")
    print(f"{CYN}{'─'*8}  Summary {'─'*8}{CLR}")
    print(f"Total entries  : {total_all}")
    print(f"{CYN}Processed (2xx): {total_2xx}{CLR}")
    print(f"{YEL}Filtered (!2xx): {filtered_non2xx}{CLR}")
    print(f"{GRN}Success        : {succ}{CLR}")
    print(f"{YEL}Skipped        : {skip}{CLR}")
    print(f"{RED}Failure        : {fail}{CLR}")
    print(f"Output dir     : {out_dir}\n")

# ── HAR entries 추출(표준/조각 JSON 모두 수용)
def extract_entries(data: dict | list) -> list[dict]:
    if isinstance(data, dict) and "log" in data and isinstance(data["log"], dict) and "entries" in data["log"]:
        return data["log"]["entries"] or []
    if isinstance(data, dict) and "response" in data and "request" in data:
        return [data]
    if isinstance(data, list) and data and isinstance(data[0], dict) and "response" in data[0]:
        return data
    raise ValueError("HAR 형식이 아님: log.entries / entry 구조를 찾지 못했습니다.")

# ── 메인
def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python zap_har_export_create_file.py <export.har>")
        return
    in_har = Path(sys.argv[1]).resolve()
    if not in_har.is_file():
        print(f"{RED}[!] File not found:{CLR} {in_har}")
        return

    out_dir = in_har.with_name(in_har.stem + "_decoded")
    zip_name = out_dir.with_suffix(".zip")
    out_dir.mkdir(exist_ok=True)

    # HAR 로딩
    with in_har.open("r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)

    try:
        entries_all = extract_entries(data)
    except Exception as e:
        print(f"{RED}[!] {e}{CLR}")
        return

    # ── 2xx 필터링 (RFC 9110: 200–299은 Successful class) ──
    # 참고: 2xx는 요청이 성공적으로 수신·이해·수락되었음을 의미. (RFC 9110 §15.3, MDN)
    eligible: list[dict] = []
    for ent in entries_all:
        resp = ent.get("response", {}) or {}
        status = resp.get("status")
        if isinstance(status, int) and 200 <= status < 300:
            eligible.append(ent)

    total_all = len(entries_all)
    filtered_non2xx = total_all - len(eligible)
    tot = len(eligible)

    succ = fail = skip = 0
    fails: list[str] = []

    log(f"{CYN}[i] Processing {tot} entries (2xx only)…{CLR}", 0, tot)

    for idx, ent in enumerate(eligible, 1):
        url_raw  = ent.get("request", {}).get("url", "").strip()
        url_disp = format_url_for_log(url_raw)  # 로그 출력용 디코딩 URL
        resp = ent.get("response", {})
        cont = resp.get("content", {}) if isinstance(resp, dict) else {}
        raw  = cont.get("text")
        enc  = cont.get("encoding")
        mime = (cont.get("mimeType") or "").lower().split(";", 1)[0]

        msg_prefix = f"[{idx:>3}/{tot}] "

        # 유효성 검사
        if not url_raw or raw is None:
            fail += 1
            fails.append(url_raw or "<no-url>")
            log(f"{msg_prefix}{RED}[X] Invalid                  {CLR}→ {RED}(Failure){CLR} {url_disp}", idx, tot)
            continue

        # base64 / utf-8 변환
        try:
            body_bytes = (
                base64.b64decode(raw, validate=False)
                if enc == "base64"
                else raw.encode("utf-8", errors="ignore")
            )
        except Exception:
            fail += 1
            fails.append(url_raw)
            log(f"{msg_prefix}{RED}[X] Decode-Error             {CLR}→ {RED}(Failure){CLR} {url_disp}", idx, tot)
            continue

        # MIME 보정
        mime = mime or guess_mime(body_bytes)

        # Content-Disposition 기반 파일명 우선 적용
        cd_name = get_cd_filename(resp.get("headers", []))
        if cd_name:
            p = urllib.parse.urlparse(url_raw)
            parent, _leaf = _decode_and_sanitize_path(p.path)
            dest = out_dir / parent / cd_name
            exists = dest.exists()
        else:
            # URL 기반 규칙(퍼센트 디코딩 + sanitize + NFC)
            dest, exists = make_filepath(url_raw, mime, out_dir)

        if exists:
            skip += 1
            rel = dest.relative_to(out_dir)
            log(
                f"{msg_prefix}{YEL}[―] {mime:<25}{CLR}→ {YEL}(Skipped){CLR} {rel}",
                idx, tot
            )
            continue

        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            dest.write_bytes(body_bytes)
            succ += 1
            rel = dest.relative_to(out_dir)
            log(
                f"{msg_prefix}{GRN}[v] {mime:<25}{CLR}→ {GRN}(Success){CLR} {rel}",
                idx, tot
            )
        except Exception:
            fail += 1
            fails.append(url_raw)
            log(f"{msg_prefix}{RED}[X] Create-Failure           {CLR}→ {RED}(Failure){CLR} {url_disp}", idx, tot)

    # Summary (2xx 필터링 정보 포함)
    print_summary(total_all, tot, succ, skip, fail, filtered_non2xx, out_dir, zip_name)

    # ZIP 압축 (파일명 표시)
    files = [fp for fp in out_dir.rglob("*") if fp.is_file()]
    ztot  = len(files)

    if ztot == 0:
        print(f"{YEL}[!] No files to zip.{CLR}")
    else:
        print(f"{CYN}{'─'*8}  Compressing to ZIP ({ztot} files) {'─'*8}{CLR}")
        max_disp = 60
        with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as zf:
            for zi, fp in enumerate(files, 1):
                zf.write(fp, fp.relative_to(out_dir))
                prog = f"{zi}/{ztot} ({zi / ztot * 100:5.1f}%)"
                rel  = str(fp.relative_to(out_dir))
                disp = rel if len(rel) <= max_disp else "…" + rel[-(max_disp-1):]
                sys.stdout.write(f"\r[ZIP] {prog:<18} {disp:<{max_disp}}")
                sys.stdout.flush()
        sys.stdout.write("\r[ZIP] Done. " + " " * (max_disp + 20) + "\n")
    print(f"ZIP file  : {zip_name}")

    # 실패 로그
    if fails:
        flog = out_dir / "failure.log"
        flog.write_text("\n".join(fails), encoding="utf-8")
        print(f"{RED}[!] Failure log → {flog}{CLR}")

if __name__ == "__main__":
    main()
