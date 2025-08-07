#!/usr/bin/env python3
"""
Decode OWASP ZAP HAR export:
• HAR 1.2 (`.har`, JSON) 파일을 읽어 각 응답 본문을 원본 파일로 복원.
• MIME → 확장자 부여, URL 무확장 시 query-MD5 유일화.
• Summary 출력 후 ZIP 압축(진행률 + 현재 파일명 표시).

Usage:
    python zap_har_export_create_file.py <input.har>
"""

from __future__ import annotations
import sys, json, base64, hashlib, zipfile, urllib.parse
from pathlib import Path
from typing import Tuple

# ── colour (Burp 스크립트와 동일) ───────────────────────
try:
    from colorama import init as _cinit, Fore, Style
    _cinit(convert=True)
    CLR = Style.RESET_ALL
    GRN, YEL, RED, CYN = Fore.GREEN, Fore.YELLOW, Fore.RED, Fore.CYAN
except ImportError:
    CLR = GRN = YEL = RED = CYN = ""

# ── MIME ↔ 확장자 매핑 (Burp 스크립트 재사용) ────────────
MIME_EXT = {
    "text/html": ".html", "html": ".html",
    "text/css": ".css",   "css": ".css",
    "application/javascript": ".js", "text/javascript": ".js",
    "script": ".js", "js": ".js",
    "application/json": ".json", "json": ".json",
    "text/plain": ".txt", "txt": ".txt",
    "image/jpeg": ".jpg", "image/png": ".png", "image/gif": ".gif",
    "image/svg+xml": ".svg",
    "text": ".txt",
}

# ── MIME 추론 (Burp 스크립트 재사용) ──────────────────────
def guess_mime(body: bytes) -> str:
    h = body[:200].lower()
    if h.startswith(b"<!doctype") or b"<html" in h:        return "text/html"
    if h.startswith(b"{") or h.startswith(b"["):           return "application/json"
    if h.startswith(b"\xff\xd8"):                          return "image/jpeg"
    if h.startswith(b"\x89png"):                           return "image/png"
    if h.startswith(b"gif8"):                              return "image/gif"
    if b"function(" in h or b"var " in h:                  return "application/javascript"
    if b"body{" in h or b"{font" in h:                     return "text/css"
    return "text/plain"

# ── 파일 경로 결정 (Burp 스크립트 재사용) ────────────────
def make_filepath(url: str, mime: str, out_dir: Path) -> Tuple[Path, bool]:
    p = urllib.parse.urlparse(url)
    upath = Path(p.path.lstrip("/"))
    parent = upath.parent if upath.parent != Path(".") else Path()
    if upath.suffix:
        filename = upath.name
    else:
        ext = MIME_EXT.get(mime) or (f".{mime}" if mime and "/" not in mime else ".bin")
        stem = upath.stem or "index"
        if p.query:
            md5 = hashlib.md5(p.query.encode()).hexdigest()
            stem = f"{stem}_{md5}"
        filename = stem + ext
    dest = out_dir / parent / filename
    return dest, dest.exists()

# ── 진행률/로그 출력 ─────────────────────────────────────
def log(msg: str, idx: int, tot: int) -> None:
    prog = f"{CYN}{idx}/{tot}{CLR}  ({idx / tot * 100:5.1f}%)"
    sys.stdout.write("\r" + " " * 120 + "\r")
    sys.stdout.write(f"{msg}\n")
    sys.stdout.write(f"\r{prog}")
    sys.stdout.flush()

# ── Summary 출력 ────────────────────────────────────────
def print_summary(tot: int, succ: int, skip: int, fail: int,
                  out_dir: Path, zip_name: Path) -> None:
    sys.stdout.write("\n\n")
    print(f"{CYN}{'─'*8}  Summary {'─'*8}{CLR}")
    print(f"Total     : {tot}")
    print(f"{GRN}Success   : {succ}{CLR}")
    print(f"{YEL}Skipped   : {skip}{CLR}")
    print(f"{RED}Failures  : {fail}{CLR}")
    print(f"Output dir: {out_dir}\n")

# ── 메인 ────────────────────────────────────────────────
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
        har = json.load(f)

    entries = har.get("log", {}).get("entries", [])
    tot = len(entries)
    succ = fail = skip = 0
    fails: list[str] = []

    log(f"{CYN}[i] Processing {tot} entries…{CLR}", 0, tot)

    for idx, ent in enumerate(entries, 1):
        url  = ent.get("request", {}).get("url", "").strip()
        resp = ent.get("response", {})
        cont = resp.get("content", {}) if isinstance(resp, dict) else {}
        raw  = cont.get("text")
        enc  = cont.get("encoding")
        mime = (cont.get("mimeType") or "").lower().split(";", 1)[0]

        msg_prefix = f"[{idx:>3}/{tot}] "

        # ── 유효성 검사 ──────────────────────────────────
        if not url or raw is None:
            fail += 1
            fails.append(url or "<no-url>")
            log(f"{msg_prefix}{RED}[✗] invalid           {CLR}→ {url}", idx, tot)
            continue

        # ── base64 / utf-8 변환 ──────────────────────────
        try:
            body_bytes = (
                base64.b64decode(raw, validate=False)
                if enc == "base64"
                else raw.encode("utf-8", errors="ignore")
            )
        except Exception:
            fail += 1
            fails.append(url)
            log(f"{msg_prefix}{RED}[❌] decode-error      {CLR}→ {url}", idx, tot)
            continue

        mime = mime or guess_mime(body_bytes)
        dest, exists = make_filepath(url, mime, out_dir)

        if exists:
            skip += 1
            log(
                f"{msg_prefix}{YEL}[〃] {mime:<20}{CLR}→ {YEL}(Skipped){CLR} {dest.relative_to(out_dir)}",
                idx, tot
            )
            continue

        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            dest.write_bytes(body_bytes)
            succ += 1
            log(
                f"{msg_prefix}{GRN}[✔] {mime:<20}{CLR}→ {GRN}(Success){CLR} {dest.relative_to(out_dir)}",
                idx, tot
            )
        except Exception:
            fail += 1
            fails.append(url)
            log(f"{msg_prefix}{RED}[✗] write-error       {CLR}→ {url}", idx, tot)

    # ── Summary ────────────────────────────────────────
    print_summary(tot, succ, skip, fail, out_dir, zip_name)

    # ── ZIP 압축 (파일명 표시) ───────────────────────────
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

    # ── 실패 로그 ──────────────────────────────────────
    if fails:
        flog = out_dir / "failures.log"
        flog.write_text("\n".join(fails), encoding="utf-8")
        print(f"{RED}[!] Failure log → {flog}{CLR}")

if __name__ == "__main__":
    main()
