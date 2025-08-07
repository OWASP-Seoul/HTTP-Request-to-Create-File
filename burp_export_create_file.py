#!/usr/bin/env python3
# burp_export_create_file.py
"""
Decode Burp Suite XML export:
• Base64-decoded responses are written out mirroring URL paths.
• MIME type is inferred (mimetype tag → header → python-magic → body sniff).
• If the URL has no extension, assign a unique file name in the format file_MD5(query).ext.
• Compress the resulting folder into a ZIP file.

Usage:
• python burp_export_create_file.py <input_file.xml>
"""

from __future__ import annotations
import sys, base64, hashlib, zipfile, urllib.parse
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

# ── MIME → 확장자 매핑 ───────────────────────────────
MIME_EXT = {
    "text/html": ".html", "html": ".html",
    "text/css": ".css",   "css": ".css",
    "application/javascript": ".js", "text/javascript": ".js",
    "script": ".js", "js": ".js",
    "application/json": ".json", "json": ".json",
    "text/plain": ".txt", "txt": ".txt",
    "image/jpeg": ".jpg", "image/png": ".png", "image/gif": ".gif",
    "image/svg+xml": ".svg",
}

# ── MIME 추론 ────────────────────────────────────────
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

def extract_ct(resp: bytes) -> str:
    for line in resp.split(b"\r\n\r\n",1)[0].splitlines():
        if line.lower().startswith(b"content-type:"):
            return line.decode(errors="ignore").split(":",1)[1].split(";",1)[0].strip().lower()
    return ""

# ── 파일 경로 결정 ───────────────────────────────────
def make_filepath(url:str, mime:str, out_dir:Path)->Tuple[Path,bool]:
    p = urllib.parse.urlparse(url)
    upath = Path(p.path.lstrip("/"))
    parent = upath.parent if upath.parent!=Path(".") else Path()
    if upath.suffix:                                  # 이미 확장자 O
        filename = upath.name
    else:                                             # 확장자 부여
        ext = MIME_EXT.get(mime) or (f".{mime}" if mime and "/" not in mime else ".bin")
        stem = upath.stem or "index"
        if p.query:                                   # 쿼리 MD5 → 유일화
            md5 = hashlib.md5(p.query.encode()).hexdigest()
            stem = f"{stem}_{md5}"
        filename = stem + ext
    dest = out_dir / parent / filename
    return dest, dest.exists()

# ── 진행률 & 메시지 ───────────────────────────────────
def log(msg:str, idx:int, tot:int)->None:
    prog = f"{CYN}{idx}/{tot}{CLR}  ({idx/tot*100:5.1f}%)"
    sys.stdout.write("\r"+" "*120+"\r")   # 진행줄 clear
    sys.stdout.write(f"{msg}\n")          # 결과 메시지 고정
    sys.stdout.write(f"\r{prog}")         # 진행률 → 마지막 줄
    sys.stdout.flush()

# ── 메인 ─────────────────────────────────────────────
def main()->None:
    if len(sys.argv)!=2:
        print("Usage: python burp_export_create_file.py <export.xml>"); return
    in_xml = Path(sys.argv[1]).resolve()
    if not in_xml.is_file():
        print(f"{RED}[!] File not found:{CLR} {in_xml}"); return

    out_dir = in_xml.with_name(in_xml.stem + "_decoded")
    zip_name= out_dir.with_suffix(".zip")
    out_dir.mkdir(exist_ok=True)

    items = ET.parse(in_xml).getroot().findall("item")
    tot = len(items)
    succ=fail=skip=0
    fails: list[str]=[]

    log(f"{CYN}[i] Processing {tot} files…{CLR}",0,tot)

    for idx,it in enumerate(items,1):
        url  = it.findtext("url","").strip()
        resp = it.find("response")
        mime = (it.findtext("mimetype") or "").strip().lower()

        msg_prefix = f"[{idx:>3}/{tot}] "

        if not url or resp is None or resp.attrib.get("base64")!="true":
            fail+=1; fails.append(url or "<no-url>")
            log(f"{msg_prefix}{RED}[✗] invalid        {CLR}→ {url}",idx,tot); continue

        try:
            raw = base64.b64decode(resp.text or "", validate=False)
        except Exception:
            fail+=1; fails.append(url)
            log(f"{msg_prefix}{RED}[✗] b64-error      {CLR}→ {url}",idx,tot); continue

        body = raw.split(b"\r\n\r\n",1)[-1]
        mime = mime or extract_ct(raw) or guess_mime(body)
        dest, exists = make_filepath(url,mime,out_dir)

        if exists:
            skip+=1
            log(f"{msg_prefix}{YEL}[→] {mime:<10}{CLR}→ {YEL}(skip) {CLR}{dest.relative_to(out_dir)}",
                idx,tot); continue

        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            dest.write_bytes(body)
            succ+=1
            log(f"{msg_prefix}{GRN}[✔] {mime:<14}{CLR}→ {dest.relative_to(out_dir)}",
                idx,tot)
        except Exception:
            fail+=1; fails.append(url)
            log(f"{msg_prefix}{RED}[✗] write-err     {CLR}→ {url}",idx,tot)

    # ZIP
    with zipfile.ZipFile(zip_name,"w",zipfile.ZIP_DEFLATED) as zf:
        for fp in out_dir.rglob("*"):
            if fp.is_file():
                try: zf.write(fp, fp.relative_to(out_dir))
                except ValueError: pass

    sys.stdout.write("\n")   # 진행줄 끝줄 고정

    # Summary
    print(f"{CYN}{'─'*8} Summary {'─'*8}{CLR}")
    print(f"Total     : {tot}")
    print(f"{GRN}Success   : {succ}{CLR}")
    print(f"{YEL}Skipped   : {skip}{CLR}")
    print(f"{RED}Failures  : {fail}{CLR}")
    print(f"Output dir: {out_dir}")
    print(f"ZIP file  : {zip_name}")

    if fails:
        flog = out_dir/"failures.log"
        flog.write_text("\n".join(fails),encoding="utf-8")
        print(f"{RED}[!] Failure log → {flog}{CLR}")

if __name__ == "__main__":
    main()