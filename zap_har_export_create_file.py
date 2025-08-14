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
• NEW: 성공한 항목의 url, referer, saved_rel을 url_map.csv로 저장(UTF-8 with BOM).
"""

from __future__ import annotations
import sys, json, base64, hashlib, zipfile, urllib.parse, re, unicodedata, csv, io
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

# ── 안전/위험 확장자 정책
SAFE_EXTS = {
    # Office / 문서 / 데이터
    "txt","csv","json","xml","pdf",
    "xlsx","xls","docx","doc","pptx","ppt",
    # 웹/이미지/압축
    "html","htm","css","js","png","jpg","jpeg","gif","webp","svg","zip"
}
DANGEROUS_EXTS = {"exe","dll","com","bat","cmd","msi","vbs","ps1","sh"}

# ── MIME ↔ 확장자 매핑(헤더 또는 스니핑 결과용)
MIME_EXT = {
    # 웹
    "text/html": ".html", "html": ".html",
    "text/css": ".css",   "css": ".css",
    "application/javascript": ".js", "text/javascript": ".js",
    "script": ".js", "js": ".js",
    "application/json": ".json", "json": ".json",
    "text/plain": ".txt", "txt": ".txt",
    # 이미지
    "image/jpeg": ".jpg", "image/jpg": ".jpg",
    "image/png": ".png", "image/gif": ".gif",
    "image/svg+xml": ".svg", "image/webp": ".webp",
    # 문서
    "application/pdf": ".pdf",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    "application/msword": ".doc",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.ms-powerpoint": ".ppt",
    # 압축/바이너리
    "application/zip": ".zip",
    "application/octet-stream": "",  # 스니핑/보정 대상
    "text": ".txt",
}

# ── 본문 시그니처 스니핑: MIME/확장자 추론
def sniff_ext_from_bytes(b: bytes) -> tuple[str|None, str|None]:
    """
    Returns (mime, ext) if confidently detected, else (None, None)
    """
    # ZIP(OpenXML: xlsx/docx/pptx 등)
    if b[:4] == b'PK\x03\x04':
        try:
            with zipfile.ZipFile(io.BytesIO(b)) as zf:
                names = zf.namelist()
            if any(n.startswith('xl/') for n in names):
                return ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx")
            if any(n.startswith('word/') for n in names):
                return ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".docx")
            if any(n.startswith('ppt/') for n in names):
                return ("application/vnd.openxmlformats-officedocument.presentationml.presentation", ".pptx")
            return ("application/zip", ".zip")
        except zipfile.BadZipFile:
            # 헤더는 ZIP인데 손상 — 그래도 zip으로 취급
            return ("application/zip", ".zip")

    # OLE CFB (구형 Office)
    if b.startswith(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'):
        # 세부 구분은 어렵지만 xls/doc/ppt 가능성 — 가장 안전한 xls로
        return ("application/vnd.ms-excel", ".xls")

    # PDF
    if b.startswith(b"%PDF-"):
        return ("application/pdf", ".pdf")

    # PNG/JPG/GIF/WEBP
    if b.startswith(b"\x89PNG\r\n\x1a\n"): return ("image/png", ".png")
    if b[0:3] == b'\xff\xd8\xff':         return ("image/jpeg", ".jpg")
    if b.startswith(b"GIF8"):             return ("image/gif", ".gif")
    if b.startswith(b"RIFF") and b[8:12] == b"WEBP": return ("image/webp", ".webp")

    # HTML / JSON / JS / CSS (간단 휴리스틱)
    h = b[:256].lstrip().lower()
    if h.startswith(b"<!doctype") or b"<html" in h: return ("text/html", ".html")
    if h.startswith(b"{") or h.startswith(b"["):     return ("application/json", ".json")
    if b"function(" in h or b"var " in h:            return ("application/javascript", ".js")
    if b"{font" in h or b"body{" in h:               return ("text/css", ".css")

    return (None, None)

# ── 간단 MIME 휴리스틱(헤더 비었을 때만)
def guess_mime(body: bytes) -> str:
    mime, _ = sniff_ext_from_bytes(body)
    if mime:
        return mime
    h = body[:200].lower()
    if h.startswith(b"<!doctype") or b"<html" in h:
        return "text/html"
    if h.startswith(b"{") or h.startswith(b"["):
        return "application/json"
    if b"function(" in h or b"var " in h:
        return "application/javascript"
    if b"body{" in h or b"{font" in h:
        return "text/css"
    return "text/plain"

# ── Content-Disposition filename/filename* 파싱
_ILLEGAL = r'<>:"/\\|?*\x00-\x1F'
_ILLEGAL_RE = re.compile(f"[{re.escape(_ILLEGAL)}]")

def _nfc(s: str) -> str:
    try:
        return unicodedata.normalize("NFC", s)
    except Exception:
        return s

def sanitize_component(s: str) -> str:
    # 경로 세그먼트 및 파일명 공통 정리
    s = s.strip().replace("\u202e", "")  # RTL override 제거
    s = _ILLEGAL_RE.sub("_", s)
    s = re.sub(r"\s+", " ", s).strip()
    # Windows 예약 이름 회피
    reserved = {"con","prn","aux","nul","com1","com2","com3","com4","com5","com6","com7","com8","com9",
                "lpt1","lpt2","lpt3","lpt4","lpt5","lpt6","lpt7","lpt8","lpt9"}
    if s.lower() in reserved:
        s = s + "_"
    return s[:255] or "file"

def sanitize_filename_keep_ext(name: str) -> str:
    name = _nfc(sanitize_component(name))
    if "." in name:
        base, ext = name.rsplit(".", 1)
        base = sanitize_component(base).rstrip(" .")
        ext  = sanitize_component(ext).lower()
        return f"{base}.{ext}" if ext else base
    else:
        return sanitize_component(name)

def get_cd_filename(headers: list[dict]) -> str | None:
    if not headers:
        return None
    cd = next((h.get("value") for h in headers
               if h.get("name","").lower() == "content-disposition"), None)
    if not cd:
        return None
    parts = [p.strip() for p in cd.split(";")]
    params: dict[str, str] = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            params[k.strip().lower()] = v.strip().strip('"')

    fn_star = params.get("filename*")
    if fn_star:
        try:
            if "'" in fn_star:
                charset, _lang, enc_value = fn_star.split("'", 2)
                raw = urllib.parse.unquote_to_bytes(enc_value)
                decoded = raw.decode(charset or "utf-8", "replace")
                print("CD decoded(*) =>", decoded)  # ★ 디버그1
                sanitized = sanitize_filename_keep_ext(decoded)
                print("After sanitize(*) =>", sanitized)  # ★ 디버그2
                return sanitized
        except Exception:
            pass

    fn = params.get("filename")
    if fn:
        try:
            fn = urllib.parse.unquote(fn)
        except Exception:
            pass
        print("CD decoded =>", fn)  # ★ 디버그1
        sanitized = sanitize_filename_keep_ext(fn)
        print("After sanitize =>", sanitized)  # ★ 디버그2
        return sanitized
    return None


# ── 경로 디코딩 + 정규화 + 세그먼트별 sanitize
def _decode_and_sanitize_path(path: str) -> tuple[Path, str]:
    raw = urllib.parse.unquote(path or "")
    raw = raw.lstrip("/")
    parts = [seg for seg in raw.split("/") if seg not in ("", ".", "..")]
    parts = [_nfc(sanitize_component(seg)) for seg in parts]
    parent = Path(*parts[:-1]) if len(parts) > 1 else Path()
    leaf = parts[-1] if parts else ""
    return parent, leaf

# ── 표시용(URL 로그용) 디코딩: 경로/쿼리/프래그먼트만 percent-decode
def format_url_for_log(u: str | None) -> str:
    if not u:
        return ""
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
            return u or ""

# ── URL 기반 파일 경로(초안) 결정: 확장자 보정은 나중에 수행
def make_filepath(url: str, mime: str, out_dir: Path) -> Tuple[Path, bool]:
    p = urllib.parse.urlparse(url)
    parent, leaf = _decode_and_sanitize_path(p.path)

    if leaf and Path(leaf).suffix:
        filename = sanitize_filename_keep_ext(leaf)
    else:
        # 헤더 MIME이 있으면 우선, 없으면 text/plain 등
        ext = MIME_EXT.get(mime, "")
        if not ext:
            # 모호할 때 임시 확장자 — 이후 스니핑 단계에서 교체
            ext = ".bin" if "/" in mime or not mime else f".{mime}"
        stem = Path(leaf).stem or "index"
        if p.query:
            md5 = hashlib.md5(p.query.encode()).hexdigest()
            stem = f"{stem}_{md5}"
        filename = sanitize_filename_keep_ext(stem + ext)

    dest = out_dir / parent / filename
    return dest, dest.exists()

# ── 최종 파일명 결정: CD/URL 이름 + 스니핑/헤더로 확장자 보정
def decide_final_name(raw_name: str, body: bytes, header_mime: str | None) -> tuple[str, str]:
    """
    Returns (final_name, final_mime)
    """
    name = sanitize_filename_keep_ext(raw_name)
    sniff_mime, sniff_ext = sniff_ext_from_bytes(body)

    # 1) 스니핑이 확실하면 스니핑 우선
    if sniff_mime and sniff_ext:
        final_mime = sniff_mime
        if "." in name:
            base, _ = name.rsplit(".", 1)
            name = f"{base}{sniff_ext}"
        else:
            name = f"{name}{sniff_ext}"
        return name, final_mime

    # 2) 스니핑 실패 시 헤더 MIME으로 보정
    final_mime = (header_mime or "").lower()
    ext_from_mime = MIME_EXT.get(final_mime, "")
    if ext_from_mime:
        if "." in name:
            base, _old = name.rsplit(".", 1)
            # 이미 동일 확장자면 유지, 다르면 교체
            if not name.lower().endswith(ext_from_mime):
                name = f"{base}{ext_from_mime}"
        else:
            name = f"{name}{ext_from_mime}"
    else:
        # 헤더도 모호하면 확장자 유지(또는 미지정)
        pass

    # 3) 위험 확장자 중립화 (Office/PDF/이미지는 제외됨)
    if "." in name:
        ext = name.rsplit(".", 1)[1].lower()
        if ext in DANGEROUS_EXTS:
            name = name + ".download"

    return name, final_mime or "application/octet-stream"

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
                  filtered_non2xx: int, out_dir: Path, zip_name: Path, url_map_csv: Path) -> None:
    sys.stdout.write("\n\n")
    print(f"{CYN}{'─'*8}  Summary {'─'*8}{CLR}")
    print(f"Total entries  : {total_all}")
    print(f"{CYN}Processed (2xx): {total_2xx}{CLR}")
    print(f"{YEL}Filtered (!2xx): {filtered_non2xx}{CLR}")
    print(f"{GRN}Success        : {succ}{CLR}")
    print(f"{YEL}Skipped        : {skip}{CLR}")
    print(f"{RED}Failure        : {fail}{CLR}")
    print(f"Output dir     : {out_dir}")
    print(f"URL map CSV    : {url_map_csv}\n")

# ── HAR entries 추출(표준/조각 JSON 모두 수용)
def extract_entries(data: dict | list) -> list[dict]:
    if isinstance(data, dict) and "log" in data and isinstance(data["log"], dict) and "entries" in data["log"]:
        return data["log"]["entries"] or []
    if isinstance(data, dict) and "response" in data and "request" in data:
        return [data]
    if isinstance(data, list) and data and isinstance(data[0], dict) and "response" in data[0]:
        return data
    raise ValueError("HAR 형식이 아님: log.entries / entry 구조를 찾지 못했습니다.")

# ── (NEW) 요청/응답 헤더에서 이름으로 값 추출 (대소문자 무시)
def _get_header(headers: list[dict] | None, name: str) -> str | None:
    if not headers:
        return None
    lname = name.lower()
    for h in headers:
        if (h.get("name") or "").lower() == lname:
            return h.get("value")
    return None

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

    # ── 2xx 필터링
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
    url_map_rows: list[tuple[str, str, str]] = []  # (url_disp, referer_disp, rel)

    log(f"{CYN}[i] Processing {tot} entries (2xx only)…{CLR}", 0, tot)

    for idx, ent in enumerate(eligible, 1):
        req = ent.get("request", {}) or {}
        url_raw   = req.get("url", "").strip()
        url_disp  = format_url_for_log(url_raw)  # 로그/CSV 표시용
        req_hdrs  = req.get("headers", [])       # (NEW)
        ref_raw   = _get_header(req_hdrs, "Referer")
        ref_disp  = format_url_for_log(ref_raw) if ref_raw else ""

        resp = ent.get("response", {})
        cont = resp.get("content", {}) if isinstance(resp, dict) else {}
        raw  = cont.get("text")
        enc  = cont.get("encoding")
        header_mime = (cont.get("mimeType") or "").lower().split(";", 1)[0]

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

        # MIME 보정(헤더 비었으면 휴리스틱)
        eff_mime = header_mime or guess_mime(body_bytes)

        # URL 기반 초안 경로
        dest, exists = make_filepath(url_raw, eff_mime, out_dir)

        # Content-Disposition 이름 우선 (있다면 URL leaf를 대체)
        cd_name = get_cd_filename(resp.get("headers", []))
        raw_name = cd_name if cd_name else dest.name

        # 최종 파일명 결정: 스니핑/헤더 기반 확장자 보정
        final_name, final_mime = decide_final_name(raw_name, body_bytes, header_mime or eff_mime)
        if final_name != dest.name:
            dest = dest.with_name(final_name)

        if dest.exists():
            skip += 1
            rel = dest.relative_to(out_dir)
            log(
                f"{msg_prefix}{YEL}[―] {final_mime:<45}{CLR}→ {YEL}(Skipped){CLR} {rel}",
                idx, tot
            )
            continue

        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            dest.write_bytes(body_bytes)
            succ += 1
            rel = dest.relative_to(out_dir)

            # NEW: URL ↔ Referer ↔ 상대경로 매핑 수집
            url_map_rows.append((url_disp, ref_disp, str(rel)))

            log(
                f"{msg_prefix}{GRN}[v] {final_mime:<45}{CLR}→ {GRN}(Success){CLR} {rel}",
                idx, tot
            )
        except Exception:
            fail += 1
            fails.append(url_raw)
            log(f"{msg_prefix}{RED}[X] Create-Failure           {CLR}→ {RED}(Failure){CLR} {url_disp}", idx, tot)

    # NEW: url, referer, saved_rel 매핑 CSV 저장 (UTF-8 with BOM, newline='')
    url_map_csv = out_dir / "url_map.csv"
    with url_map_csv.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["url", "referer", "saved_rel"])
        w.writerows(url_map_rows)

    # Summary (2xx 필터링 정보 포함)
    print_summary(total_all, tot, succ, skip, fail, filtered_non2xx, out_dir, zip_name, url_map_csv)

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
