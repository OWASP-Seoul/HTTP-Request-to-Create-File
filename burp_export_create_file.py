#!/usr/bin/env python3
# burp_export_create_file.py
"""
Decode Burp Suite XML export (2xx-only) → restore files.

• Burp XML <item> 들을 읽어 응답 본문을 원본 파일로 복원
• 처음부터 응답 상태가 2xx인 항목만 처리
• Content-Disposition 의 filename*/filename 을 우선 적용(퍼센트-디코딩 + NFC + sanitize)
• URL 경로 퍼센트-디코딩 + 세그먼트별 sanitize + Unicode NFC 정규화
• MIME → 확장자 부여(본문 시그니처 스니핑 포함), URL 무확장 시 query-MD5 유일화
• Summary 출력 후 ZIP 압축(진행률 + 현재 파일명 표시)
• url_map.csv (UTF-8 BOM): url, referer, saved_rel
• --trust-cd: CD 디코딩 결과를 그대로 파일명으로 사용(확장자 보정 없음; 불일치시 경고만)

Usage:
    python burp_export_create_file.py <export.xml> [--trust-cd]
"""

from __future__ import annotations
import sys, base64, hashlib, zipfile, urllib.parse, re, unicodedata, csv, io, argparse
from pathlib import Path
import xml.etree.ElementTree as ET
from typing import Tuple

# ── colour ──────────────────────────────────────────
try:
    from colorama import init as _cinit, Fore, Style
    _cinit(convert=True)                      # Win-CMD 지원
    CLR = Style.RESET_ALL
    GRN, YEL, RED, CYN = Fore.GREEN, Fore.YELLOW, Fore.RED, Fore.CYAN
except ImportError:
    CLR = GRN = YEL = RED = CYN = ""

# ── 안전/위험 확장자 정책 ────────────────────────────
SAFE_EXTS = {
    "txt","csv","json","xml","pdf",
    "xlsx","xls","docx","doc","pptx","ppt",
    "html","htm","css","js","png","jpg","jpeg","gif","webp","svg","zip"
}
DANGEROUS_EXTS = {"exe","dll","com","bat","cmd","msi","vbs","ps1","sh"}

# ── MIME ↔ 확장자 매핑 ───────────────────────────────
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

# ── 본문 시그니처 스니핑 ─────────────────────────────
def sniff_ext_from_bytes(b: bytes) -> tuple[str|None, str|None]:
    """
    Returns (mime, ext) if confidently detected, else (None, None)
    """
    # ZIP / OpenXML (xlsx/docx/pptx)
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
            return ("application/zip", ".zip")

    # OLE CFB (구형 Office)
    if b.startswith(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'):
        return ("application/vnd.ms-excel", ".xls")

    # PDF
    if b.startswith(b"%PDF-"):
        return ("application/pdf", ".pdf")

    # 이미지류
    if b.startswith(b"\x89PNG\r\n\x1a\n"): return ("image/png", ".png")
    if b[0:3] == b'\xff\xd8\xff':         return ("image/jpeg", ".jpg")
    if b.startswith(b"GIF8"):             return ("image/gif", ".gif")
    if b.startswith(b"RIFF") and b[8:12] == b"WEBP": return ("image/webp", ".webp")

    # 텍스트류 휴리스틱
    h = b[:256].lstrip().lower()
    if h.startswith(b"<!doctype") or b"<html" in h: return ("text/html", ".html")
    if h.startswith(b"{") or h.startswith(b"["):     return ("application/json", ".json")
    if b"function(" in h or b"var " in h:            return ("application/javascript", ".js")
    if b"{font" in h or b"body{" in h:               return ("text/css", ".css")

    return (None, None)

def guess_mime(body: bytes) -> str:
    mime, _ = sniff_ext_from_bytes(body)
    if mime: return mime
    h = body[:200].lower()
    if h.startswith(b"<!doctype") or b"<html" in h:        return "text/html"
    if h.startswith(b"{") or h.startswith(b"["):           return "application/json"
    if b"function(" in h or b"var " in h:                  return "application/javascript"
    if b"body{" in h or b"{font" in h:                     return "text/css"
    return "text/plain"

# ── 헤더 파서 (raw HTTP) ─────────────────────────────
def split_raw_http(raw: bytes) -> tuple[bytes, bytes]:
    return raw.split(b"\r\n\r\n", 1) if b"\r\n\r\n" in raw else (raw, b"")

def get_header_from_raw(raw: bytes, name: str) -> str | None:
    head, _ = split_raw_http(raw)
    lname = name.lower()
    for line in head.splitlines():
        if line.lower().startswith(lname.encode() + b":"):
            try:
                return line.decode(errors="ignore").split(":", 1)[1].strip()
            except Exception:
                return None
    return None

# ── Content-Disposition 파싱 (RFC 5987/6266) ─────────
_ILLEGAL = r'<>:"/\\|?*\x00-\x1F'
_ILLEGAL_RE = re.compile(f"[{re.escape(_ILLEGAL)}]")

def _nfc(s: str) -> str:
    try:    return unicodedata.normalize("NFC", s)
    except: return s

def sanitize_component(s: str) -> str:
    s = s.strip().replace("\u202e", "")     # RTL override 제거
    s = _ILLEGAL_RE.sub("_", s)             # 금지문자만 치환
    s = re.sub(r"\s+", " ", s).strip()
    reserved = {"con","prn","aux","nul","com1","com2","com3","com4","com5","com6","com7","com8","com9",
                "lpt1","lpt2","lpt3","lpt4","lpt5","lpt6","lpt7","lpt8","lpt9"}
    if s.lower() in reserved: s = s + "_"
    return s[:255] or "file"

def sanitize_filename_keep_ext(name: str) -> str:
    name = _nfc(sanitize_component(name))
    if "." in name:
        base, ext = name.rsplit(".", 1)
        base = sanitize_component(base).rstrip(" .")
        ext  = sanitize_component(ext).lower()
        return f"{base}.{ext}" if ext else base
    return sanitize_component(name)

def parse_cd_filename(cd_value: str | None) -> str | None:
    if not cd_value: return None
    parts = [p.strip() for p in cd_value.split(";")]
    params: dict[str, str] = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            params[k.strip().lower()] = v.strip().strip('"')

    # filename*=
    fn_star = params.get("filename*")
    if fn_star and "'" in fn_star:
        try:
            charset, _lang, enc_value = fn_star.split("'", 2)
            raw = urllib.parse.unquote_to_bytes(enc_value)
            decoded = raw.decode(charset or "utf-8", "replace")
            return sanitize_filename_keep_ext(decoded)
        except Exception:
            pass

    # fallback: filename=
    fn = params.get("filename")
    if fn:
        try:    fn = urllib.parse.unquote(fn)
        except: pass
        return sanitize_filename_keep_ext(fn)
    return None

# ── 경로/URL 처리 ───────────────────────────────────
def decode_and_sanitize_path(path: str) -> tuple[Path, str]:
    raw = urllib.parse.unquote(path or "")
    raw = raw.lstrip("/")
    parts = [seg for seg in raw.split("/") if seg not in ("", ".", "..")]
    parts = [_nfc(sanitize_component(seg)) for seg in parts]
    parent = Path(*parts[:-1]) if len(parts) > 1 else Path()
    leaf = parts[-1] if parts else ""
    return parent, leaf

def format_url_for_log(u: str | None) -> str:
    if not u: return ""
    try:
        p = urllib.parse.urlsplit(u)
        path = urllib.parse.unquote(p.path, encoding="utf-8", errors="replace")
        query = urllib.parse.unquote(p.query, encoding="utf-8", errors="replace")
        frag  = urllib.parse.unquote(p.fragment, encoding="utf-8", errors="replace")
        return urllib.parse.urlunsplit((p.scheme, p.netloc, path, query, frag))
    except Exception:
        try:    return urllib.parse.unquote(u, encoding="utf-8", errors="replace")
        except: return u or ""

def make_filepath(url: str, mime: str, out_dir: Path) -> Tuple[Path, bool]:
    p = urllib.parse.urlparse(url)
    parent, leaf = decode_and_sanitize_path(p.path)

    if leaf and Path(leaf).suffix:
        filename = sanitize_filename_keep_ext(leaf)
    else:
        ext = MIME_EXT.get(mime, "")
        if not ext:
            ext = ".bin" if "/" in mime or not mime else f".{mime}"
        stem = Path(leaf).stem or "index"
        if p.query:
            md5 = hashlib.md5(p.query.encode()).hexdigest()
            stem = f"{stem}_{md5}"
        filename = sanitize_filename_keep_ext(stem + ext)

    dest = out_dir / parent / filename
    return dest, dest.exists()

# ── 최종 파일명 결정 ─────────────────────────────────
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
            if not name.lower().endswith(ext_from_mime):
                name = f"{base}{ext_from_mime}"
        else:
            name = f"{name}{ext_from_mime}"

    # 3) 위험 확장자만 중립화
    if "." in name:
        ext = name.rsplit(".", 1)[1].lower()
        if ext in DANGEROUS_EXTS:
            name = name + ".download"

    return name, final_mime or "application/octet-stream"

# ── 진행률 & 메시지 ───────────────────────────────────
def log(msg: str, idx: int, tot: int) -> None:
    prog = f"{CYN}{idx}/{tot}{CLR}  ({idx / tot * 100:5.1f}%)" if tot else ""
    sys.stdout.write("\r" + " " * 120 + "\r")
    if msg: sys.stdout.write(f"{msg}\n")
    if prog: sys.stdout.write(f"\r{prog}")
    sys.stdout.flush()

# ── Summary 출력 ─────────────────────────────────────
def print_summary(total_all: int, total_2xx: int, succ: int, skip: int, fail: int,
                  filtered_non2xx: int, out_dir: Path, zip_name: Path, url_map_csv: Path) -> None:
    sys.stdout.write("\n\n")
    print(f"{CYN}{'─' * 8}  Summary {'─' * 8}{CLR}")
    print(f"Total entries  : {total_all}")
    print(f"{CYN}Processed (2xx): {total_2xx}{CLR}")
    print(f"{YEL}Filtered (!2xx): {filtered_non2xx}{CLR}")
    print(f"{GRN}Success        : {succ}{CLR}")
    print(f"{YEL}Skipped        : {skip}{CLR}")
    print(f"{RED}Failure        : {fail}{CLR}")
    print(f"Output dir     : {out_dir}")
    print(f"URL map CSV    : {url_map_csv}\n")

# ── 인자 파서 ────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description="Decode Burp XML export to files")
    p.add_argument("xml", help="Burp XML export file")
    p.add_argument("--trust-cd", action="store_true",
                   help="Use decoded Content-Disposition filename as-is (no extension rewrite); still sanitized minimally.")
    return p.parse_args()

# ── 메인 ─────────────────────────────────────────────
def main() -> None:
    args = parse_args()
    in_xml = Path(args.xml).resolve()
    TRUST_CD = args.trust_cd

    if not in_xml.is_file():
        print(f"{RED}[!] File not found:{CLR} {in_xml}")
        return

    out_dir = in_xml.with_name(in_xml.stem + "_decoded")
    zip_name = out_dir.with_suffix(".zip")
    out_dir.mkdir(exist_ok=True)

    root = ET.parse(in_xml).getroot()
    items = root.findall("item")
    total_all = len(items)

    # ── 2xx 필터링
    eligible: list[ET.Element] = []
    for it in items:
        try:
            st = int((it.findtext("status") or "0").strip())
        except Exception:
            st = 0
        if 200 <= st < 300:
            eligible.append(it)

    filtered_non2xx = total_all - len(eligible)
    tot = len(eligible)

    succ = fail = skip = 0
    fails: list[str] = []
    url_map_rows: list[tuple[str, str, str]] = []  # (url_disp, referer_disp, rel)

    log(f"{CYN}[i] Processing {tot} entries (2xx only)…{CLR}", 0, tot)

    for idx, it in enumerate(eligible, 1):
        url = (it.findtext("url") or "").strip()
        url_disp = format_url_for_log(url)

        # 요청/응답 원문
        req_el = it.find("request")
        resp_el = it.find("response")
        if resp_el is None:
            fail += 1
            fails.append(url or "<no-url>")
            log(f"[{idx:>3}/{tot}] {RED}[X] no-response           {CLR}→ {url_disp}", idx, tot)
            continue

        # 요청/응답 base64 여부
        req_raw: bytes | None = None
        if req_el is not None and req_el.attrib.get("base64") == "true":
            try:
                req_raw = base64.b64decode(req_el.text or "", validate=False)
            except Exception:
                req_raw = None

        if resp_el.attrib.get("base64") != "true":
            fail += 1
            fails.append(url or "<no-url>")
            log(f"[{idx:>3}/{tot}] {RED}[X] resp-not-base64       {CLR}→ {url_disp}", idx, tot)
            continue

        try:
            resp_raw = base64.b64decode(resp_el.text or "", validate=False)
        except Exception:
            fail += 1
            fails.append(url or "<no-url>")
            log(f"[{idx:>3}/{tot}] {RED}[X] resp-b64-error        {CLR}→ {url_disp}", idx, tot)
            continue

        # 응답 헤더/본문 분리
        resp_head, resp_body = split_raw_http(resp_raw)
        body = resp_body

        # MIME 결정: 응답 헤더 Content-Type → <mimetype> → guess
        header_ct = get_header_from_raw(resp_raw, "Content-Type") or ""
        header_mime = header_ct.split(";", 1)[0].strip().lower() if header_ct else ""
        xml_mime = (it.findtext("mimetype") or "").strip().lower()
        eff_mime = header_mime or xml_mime or guess_mime(body)

        # Referer (요청 헤더)
        referer = ""
        if req_raw is not None:
            ref = get_header_from_raw(req_raw, "Referer")
            referer = format_url_for_log(ref) if ref else ""

        # URL 기반 초안 경로
        dest, exists = make_filepath(url, eff_mime, out_dir)
        parent_dir = dest.parent

        # Content-Disposition 파일명(응답 헤더)
        cd_value = get_header_from_raw(resp_raw, "Content-Disposition")
        cd_name = parse_cd_filename(cd_value)

        msg_prefix = f"[{idx:>3}/{tot}] "

        # ── --trust-cd 모드: CD 이름 그대로 사용(확장자 보정 없음)
        if TRUST_CD and cd_name:
            final_name = sanitize_filename_keep_ext(cd_name)
            sniff_mime, sniff_ext = sniff_ext_from_bytes(body)
            if sniff_ext:
                has_ext = "." in final_name
                ext_ok = has_ext and final_name.lower().endswith(sniff_ext)
                if not ext_ok:
                    print(f"{YEL}[WARN]{CLR} CD filename ext != sniffed ext: '{final_name}' vs '{sniff_ext}'")
            dest = parent_dir / final_name

        else:
            # 기본 로직: CD 우선 → 스니핑/헤더로 확장자 보정
            raw_name = cd_name if cd_name else dest.name
            final_name, final_mime = decide_final_name(raw_name, body, header_mime or eff_mime)
            if final_name != dest.name:
                dest = dest.with_name(final_name)

        if dest.exists():
            skip += 1
            rel = dest.relative_to(out_dir)
            log(f"{msg_prefix}{YEL}[―] {eff_mime:<45}{CLR}→ {YEL}(Skipped){CLR} {rel}", idx, tot)
            continue

        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            dest.write_bytes(body)
            succ += 1
            rel = dest.relative_to(out_dir)
            url_map_rows.append((url_disp, referer, str(rel)))
            log(f"{msg_prefix}{GRN}[v] {eff_mime:<45}{CLR}→ {GRN}(Success){CLR} {rel}", idx, tot)
        except Exception:
            fail += 1
            fails.append(url or "<no-url>")
            log(f"{msg_prefix}{RED}[X] write-err                 {CLR}→ {url_disp}", idx, tot)

    # url_map.csv (UTF-8 with BOM)
    url_map_csv = out_dir / "url_map.csv"
    with url_map_csv.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["url", "referer", "saved_rel"])
        w.writerows(url_map_rows)

    # Summary
    print_summary(total_all, tot, succ, skip, fail, filtered_non2xx, out_dir, zip_name, url_map_csv)

    # ZIP (진행률 + 현재 파일명)
    files = [fp for fp in out_dir.rglob("*") if fp.is_file()]
    ztot  = len(files)
    if ztot == 0:
        print(f"{YEL}[!] No files to zip.{CLR}")
    else:
        print(f"{CYN}{'─' * 8}  Compressing to ZIP ({ztot} files) {'─' * 8}{CLR}")
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
        flog = out_dir / "failures.log"
        flog.write_text("\n".join(fails), encoding="utf-8")
        print(f"{RED}[!] Failure log → {flog}{CLR}")

if __name__ == "__main__":
    main()
