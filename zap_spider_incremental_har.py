#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZAP Spider incremental HAR — Patched
- Fix: Define print_above_panel (prevents NameError) and use it safely.
- Fix: Oneline mode finalization clears the progress line before printing DONE.
- Feature: Stop/remove previous Spider scans at start (queue pre-clear).
- Feature: Clear Passive Scanner queue at start (optional, default ON).
- Fix: Pass apikey to /OTHER/* endpoints to avoid 401/403 and "skipped" entries.
- Feature: Only 2xx responses are written to HAR (non-2xx are counted as skipped).
- Windows-safe ANSI handling + selectable UI modes (oneline/twoline/live/scroll).
"""

import argparse
import json
import os
import sys
import time
import shutil
from collections import deque
from urllib.parse import urljoin, urlparse

import requests
from requests.exceptions import ChunkedEncodingError
from http.client import IncompleteRead
from urllib3.exceptions import ProtocolError

# ── Color handling ───────────────────────────────────────────────────────────
class _NoColor:
    RESET = BOLD = DIM = RED = YELLOW = GREEN = CYAN = MAGENTA = BLUE = WHITE = ""

def _init_color():
    try:
        from colorama import init as colorama_init, Fore, Style
        colorama_init()
        class _Color:
            RESET = Style.RESET_ALL
            BOLD = Style.BRIGHT
            DIM = Style.DIM
            RED = Fore.RED
            YELLOW = Fore.YELLOW
            GREEN = Fore.GREEN
            CYAN = Fore.CYAN
            MAGENTA = Fore.MAGENTA
            BLUE = Fore.BLUE
            WHITE = Fore.WHITE
        return _Color()
    except Exception:
        return _NoColor()

COLOR = _init_color()

# ── ANSI/VT support detection (Windows-safe) ─────────────────────────────────
def _enable_windows_vt_if_possible(stream) -> bool:
    try:
        import os, msvcrt, ctypes
        if os.name != "nt":
            return False
        kernel32 = ctypes.windll.kernel32
        handle = msvcrt.get_osfhandle(stream.fileno())
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        new_mode = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if not kernel32.SetConsoleMode(handle, new_mode):
            return False
        return True
    except Exception:
        return False

def _ansi_supported() -> bool:
    try:
        import os
        if not sys.stdout.isatty():
            return False
        if os.environ.get("TERM", "").lower() == "dumb":
            return False
        if os.name == "nt":
            if not getattr(_ansi_supported, "_vt_checked", False):
                _ansi_supported._vt_ok = _enable_windows_vt_if_possible(sys.stdout) or _enable_windows_vt_if_possible(sys.stderr)
                _ansi_supported._vt_checked = True
            return bool(getattr(_ansi_supported, "_vt_ok", False))
        return True
    except Exception:
        return False

def should_use_color(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never":
        return False
    return _ansi_supported()

def colorize(text: str, color: str, enabled: bool) -> str:
    if not enabled or isinstance(COLOR, _NoColor):
        return text
    return f"{color}{text}{COLOR.RESET}"

def pct_color(p: float) -> str:
    if p < 50: return COLOR.RED
    if p < 90: return COLOR.YELLOW
    return COLOR.GREEN

# ── Console helpers ──────────────────────────────────────────────────────────
_PANEL_LINES_SHOWN = 0
_PANEL_LAST_CONTENT = []

def _clear_line():
    try:
        sys.stdout.write("\033[2K")
    except Exception:
        pass

def _render_panel(lines):
    """Redraws the N-line panel safely."""
    global _PANEL_LINES_SHOWN, _PANEL_LAST_CONTENT
    n_prev = _PANEL_LINES_SHOWN
    n_new = len(lines)
    if n_prev > 0:
        try:
            sys.stdout.write(f"\033[{n_prev}F")
        except Exception:
            pass
    for i in range(n_new):
        _clear_line()
        try:
            sys.stdout.write("\r" + lines[i] + "\n")
        except Exception:
            print(lines[i])
    if n_new < n_prev:
        for _ in range(n_prev - n_new):
            _clear_line(); sys.stdout.write("\r\n")
        try:
            sys.stdout.write(f"\033[{(n_prev - n_new)}F")
        except Exception:
            pass
    try:
        sys.stdout.flush()
    except Exception:
        pass
    _PANEL_LINES_SHOWN = n_new
    _PANEL_LAST_CONTENT = list(lines)

def _repaint_panel():
    if _PANEL_LINES_SHOWN > 0:
        _render_panel(_PANEL_LAST_CONTENT)

# 안전한 상단 출력(패널이 있으면 패널 위에, 없으면 일반 print)
def print_above_panel(msg: str):
    try:
        if _PANEL_LINES_SHOWN > 0:
            sys.stdout.write(f"\033[{_PANEL_LINES_SHOWN}F")
            sys.stdout.write("\r")
            _clear_line()
            print(msg)
            _repaint_panel()
        else:
            print(msg)
    except Exception:
        # 어떤 경우든 출력은 되게 보장
        print(msg)

# ── One-line UI (\r only) ───────────────────────────────────────────────────
_ONELINE_PREV_LEN = 0

def _term_width(default=120) -> int:
    try:
        return shutil.get_terminal_size((default, 20)).columns
    except Exception:
        return default

def _print_oneline(s: str):
    global _ONELINE_PREV_LEN
    try:
        sys.stdout.write("\r" + s)
        pad = max(0, _ONELINE_PREV_LEN - len(s))
        if pad: sys.stdout.write(" " * pad)
        sys.stdout.flush()
        _ONELINE_PREV_LEN = len(s)
    except Exception:
        print(s)

def _clear_oneline():
    """Clear the current oneline using spaces (no ANSI required)."""
    global _ONELINE_PREV_LEN
    try:
        if _ONELINE_PREV_LEN > 0:
            sys.stdout.write("\r" + (" " * _ONELINE_PREV_LEN) + "\r")
            sys.stdout.flush()
    except Exception:
        pass
    _ONELINE_PREV_LEN = 0

# ── ZAP API helpers ─────────────────────────────────────────────────────────
SESSION = requests.Session()

def zap_get(endpoint, **params):
    r = SESSION.get(endpoint, params=params, timeout=60)
    r.raise_for_status()
    return r

# --- Spider queue helpers ---
def spider_scans(base, apikey):
    """Return list of previous spider scans (any status)."""
    u = urljoin(base, "/JSON/spider/view/scans/")
    data = zap_get(u, apikey=apikey).json()
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, list):
                return v
    return []

def spider_stop_all(base, apikey):
    u = urljoin(base, "/JSON/spider/action/stopAllScans/")
    try:
        zap_get(u, apikey=apikey)
    except Exception:
        pass

def spider_remove_all(base, apikey):
    u = urljoin(base, "/JSON/spider/action/removeAllScans/")
    try:
        zap_get(u, apikey=apikey)
    except Exception:
        pass

def spider_start(base, apikey, url, recurse=True, subtree_only=False, max_children=None, context_id=None, user_id=None):
    if user_id is not None and context_id is not None:
        u = urljoin(base, "/JSON/spider/action/scanAsUser/")
        params = dict(apikey=apikey, contextId=context_id, userId=user_id, url=url,
                      recurse=str(bool(recurse)).lower(), subtreeOnly=str(bool(subtree_only)).lower())
        if max_children is not None: params["maxChildren"] = max_children
        return int(zap_get(u, **params).json().get("scan", "0"))
    else:
        u = urljoin(base, "/JSON/spider/action/scan/")
        params = dict(apikey=apikey, url=url, recurse=str(bool(recurse)).lower(),
                      subtreeOnly=str(bool(subtree_only)).lower())
        if max_children is not None: params["maxChildren"] = max_children
        return int(zap_get(u, **params).json().get("scan", "0"))

def spider_status(base, apikey, scan_id):
    u = urljoin(base, "/JSON/spider/view/status/")
    return int(zap_get(u, apikey=apikey, scanId=scan_id).json().get("status", "0"))

def number_of_messages(base, apikey, baseurl=None):
    u = urljoin(base, "/JSON/core/view/numberOfMessages/")
    params = {"apikey": apikey}
    if baseurl: params["baseurl"] = baseurl
    return int(zap_get(u, **params).json().get("numberOfMessages", "0"))

# ── Lightweight IDs + HAR ───────────────────────────────────────────────────
def list_message_ids(base, apikey, start, count, baseurl=None):
    u = urljoin(base, "/JSON/core/view/messagesIds/")
    params = {"apikey": apikey, "start": start, "count": count}
    if baseurl: params["baseurl"] = baseurl
    r = zap_get(u, **params)
    data = r.json()
    for k in ("messagesIds", "messageIds", "ids"):
        if k in data and isinstance(data[k], list):
            return [str(x) for x in data[k]]
    for v in data.values():
        if isinstance(v, list):
            return [str(x) for x in v]
    return []

def list_messages_heavy(base, apikey, start, count, baseurl=None):
    u = urljoin(base, "/JSON/core/view/messages/")
    params = {"apikey": apikey, "start": start, "count": count}
    if baseurl: params["baseurl"] = baseurl
    return zap_get(u, **params).json().get("messages", [])

def har_entry_by_id(base, apikey, mid):
    # Prefer Import/Export add-on
    u1 = urljoin(base, "/OTHER/importexport/other/exportHarById/")
    try:
        r1 = SESSION.get(u1, params=dict(apikey=apikey, id=mid), timeout=60)
        if r1.ok:
            har = r1.json()
            ent = har.get("log", {}).get("entries", [])
            if ent: return ent[0]
    except Exception:
        pass
    # Fallback: core/other/messageHar
    u2 = urljoin(base, "/OTHER/core/other/messageHar/")
    try:
        r2 = SESSION.get(u2, params=dict(apikey=apikey, id=mid), timeout=60)
        if r2.ok:
            har = r2.json()
            ent = har.get("log", {}).get("entries", [])
            if ent: return ent[0]
    except Exception:
        pass
    return None

def get_spider_options_safe(base, apikey):
    summary = {}
    try:
        u = urljoin(base, "/JSON/spider/view/options/")
        r = SESSION.get(u, params=dict(apikey=apikey), timeout=20)
        if r.ok:
            data = r.json()
            if isinstance(data, dict) and data:
                summary.update(data)
    except Exception:
        pass
    option_views = [
        "optionMaxDepth", "optionThreadCount", "optionMaxDuration",
        "optionMaxChildren", "optionSendRefererHeader", "optionAcceptCookies",
        "optionHandleODataParametersVisited", "optionHandleParameters",
        "optionLogoutAvoidance", "optionMaxParseSizeBytes", "optionParseComments",
        "optionParseDsStore", "optionParseGit", "optionParseRobotsTxt",
        "optionParseSVNEntries", "optionParseSitemapXml", "optionPostForm",
        "optionProcessForm", "optionShowAdvancedDialog", "optionSkipURLString",
        "optionUserAgent", "optionMaxScansInUI"
    ]
    for view in option_views:
        try:
            u = urljoin(base, f"/JSON/spider/view/{view}/")
            data = zap_get(u, apikey=apikey).json()
            for k, v in data.items():
                summary[k] = v
        except Exception:
            pass
    return summary

def clear_pscan_queue(base, apikey):
    u = urljoin(base, "/JSON/pscan/action/clearQueue/")
    try:
        zap_get(u, apikey=apikey)
    except Exception:
        pass

def pscan_records_to_scan(base, apikey) -> int:
    u = urljoin(base, "/JSON/pscan/view/recordsToScan/")
    try:
        return int(zap_get(u, apikey=apikey).json().get("recordsToScan", "0"))
    except Exception:
        return 0

def write_ndjson(path, obj):
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False))
        f.write("\n")

def finalize_har(ndjson_path, out_har_path, meta=None):
    entries = []
    if os.path.exists(ndjson_path):
        with open(ndjson_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "ZAP", "version": "2.x"},
            "browser": {},
            "pages": [],
            "entries": entries,
        }
    }
    if meta: har["log"]["_zap_meta"] = meta
    os.makedirs(os.path.dirname(os.path.abspath(out_har_path)) or ".", exist_ok=True)
    with open(out_har_path, "w", encoding="utf-8") as f:
        json.dump(har, f, ensure_ascii=False, indent=2)

def default_out_from_target(target_url: str) -> str:
    netloc = urlparse(target_url).netloc or "output"
    return f"{netloc}.har"

# ── Formatting ───────────────────────────────────────────────────────────────
def format_eta(seconds: float) -> str:
    if seconds is None or seconds == float("inf") or seconds < 0: return "--:--"
    m, s = divmod(int(seconds), 60); h, m = divmod(m, 60)
    return f"{h:02d}:{m:02d}:{s:02d}" if h>0 else f"{m:02d}:{s:02d}"

def make_progress_text(processed_cnt, skipped_cnt, denom, eps, eta_s, spider_pct):
    done_cnt = processed_cnt + skipped_cnt
    har_pct = 0.0 if denom <= 0 else (done_cnt / max(1, denom) * 100.0)
    counter_txt = f"{processed_cnt}/{denom}" if skipped_cnt == 0 else f"{processed_cnt}+{skipped_cnt}/{denom}"
    pieces = [f"[HAR] {counter_txt} ({har_pct:5.1f}%)"]
    if eps is not None: pieces.append(f"{eps:.1f} eps")
    if eta_s is not None: pieces.append(f"ETA {format_eta(eta_s)}")
    pieces.append(f"[SPIDER] {spider_pct:3d}%")
    return " | ".join(pieces)

def make_progress_text_spider_first(processed_cnt, skipped_cnt, denom, eps, eta_s, spider_pct):
    done_cnt = processed_cnt + skipped_cnt
    har_pct = 0.0 if denom <= 0 else (done_cnt / max(1, denom) * 100.0)
    counter_txt = f"{processed_cnt}/{denom}" if skipped_cnt == 0 else f"{processed_cnt}+{skipped_cnt}/{denom}"
    pieces = [f"[SPIDER] {spider_pct:3d}%"]
    pieces.append(f"[HAR] {counter_txt} ({har_pct:5.1f}%)")
    if eps is not None: pieces.append(f"{eps:.1f} eps")
    if eta_s is not None: pieces.append(f"ETA {format_eta(eta_s)}")
    return " | ".join(pieces)

def format_harplus_compact(mid, status, url, color_on, width, left_reserve=24):
    max_left = max(24, width - left_reserve)
    url_disp = url if len(url) <= max_left else (url[:max_left-3] + "...")
    left = colorize("[HAR+]", COLOR.GREEN, color_on)
    if status: left += f" {status}"
    return f"{left} id={mid} {url_disp}"

def make_har_segment(processed_cnt, skipped_cnt, denom, eps, eta_s):
    done_cnt = processed_cnt + skipped_cnt
    har_pct = 0.0 if denom <= 0 else (done_cnt / max(1, denom) * 100.0)
    counter_txt = f"{processed_cnt}/{denom}" if skipped_cnt == 0 else f"{processed_cnt}+{skipped_cnt}/{denom}"
    right = f"[HAR] {counter_txt} ({har_pct:5.1f}%)"
    if eps is not None: right += f" | {eps:.1f} eps"
    if eta_s is not None: right += f" | ETA {format_eta(eta_s)}"
    return right

# ── Context/user helpers ─────────────────────────────────────────────────────
def context_id_by_name(base, apikey, context_name):
    u = urljoin(base, "/JSON/context/view/contextList/")
    data = zap_get(u, apikey=apikey).json()
    names = data.get("contextList", [])
    if context_name not in names: return None
    u2 = urljoin(base, "/JSON/context/view/context/")
    ctx = zap_get(u2, apikey=apikey, contextName=context_name).json().get("context", {})
    return int(ctx.get("id")) if "id" in ctx else None

def user_id_by_name(base, apikey, context_id, user_name):
    u = urljoin(base, "/JSON/users/view/usersList/")
    data = zap_get(u, apikey=apikey, contextId=context_id).json()
    for uinfo in data.get("usersList", []):
        if uinfo.get("name") == user_name:
            return int(uinfo.get("id"))
    return None

def decide_baseurl_auto(base, apikey, target):
    u = urlparse(target)
    host = u.netloc
    candidates = []
    t = target.rstrip("/")
    if t: candidates.append(t + "/")
    if host:
        candidates.append(f"http://{host}/")
        candidates.append(f"https://{host}/")
    def count_for(bu):
        try:
            return number_of_messages(base, apikey, baseurl=bu)
        except Exception:
            return 0
    best, bestc = None, -1
    for bu in candidates:
        c = count_for(bu)
        if c > bestc: best, bestc = bu, c
    if bestc <= 0:
        return None, count_for(None)
    return best, bestc

# ── Status filter (2xx only) ─────────────────────────────────────────────────
def _get_status(entry):
    try:
        return int(entry.get("response", {}).get("status"))
    except Exception:
        return None

def _is_2xx(entry):
    s = _get_status(entry)
    return s is not None and 200 <= s <= 299

# ── Main ────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8090", help="ZAP API base URL")
    ap.add_argument("--apikey", default="SECRET", help="ZAP API Key")
    ap.add_argument("--target", required=True, help="Starting Point URL")
    ap.add_argument("--out", default=None, help="Output HAR path (default: <domain>.har)")
    ap.add_argument("--page-size", type=int, default=200, help="Fetch page size for message id list")
    ap.add_argument("--pscan-wait", action="store_true", help="Wait until passive scanner queue drains")
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--pscan-clear-on-start", dest="pscan_clear_on_start", action="store_true",
                       help="Clear passive scan queue at start (default: ON)")
    group.add_argument("--no-pscan-clear-on-start", dest="pscan_clear_on_start", action="store_false",
                       help="Do NOT clear pscan queue at start")
    ap.set_defaults(pscan_clear_on_start=True)
    ap.add_argument("--filter-baseurl", default=None, help="History filter baseurl (override)")
    ap.add_argument("--history-filter", choices=["auto","target","host","none"], default="auto",
                    help="Strategy to pick history baseurl when --filter-baseurl not set")
    ap.add_argument("--panel", choices=["twoline","oneline","live","scroll"], default="twoline",
                    help="UI mode")
    ap.add_argument("--color", choices=["auto","always","never"], default="auto", help="Color output mode")
    ap.add_argument("--tail-pages", type=int, default=1, help="Only fetch from the last N pages")
    ap.add_argument("--refresh-sec", type=float, default=0.25, help="UI/Fetch interval seconds")
    ap.add_argument("--eps-window-sec", type=float, default=10.0, help="EPS window seconds")
    ap.add_argument("--idle-exit-sec", type=float, default=30.0, help="After spider=100%%, exit if idle for N seconds")
    ap.add_argument("--ids-mode", choices=["auto","ids","messages"], default="auto",
                    help="How to list message ids")
    ap.add_argument("--context-name", default=None)
    ap.add_argument("--context-id", type=int, default=None)
    ap.add_argument("--user-id", type=int, default=None)
    ap.add_argument("--user-name", default=None)
    ap.add_argument("--max-children", type=int, default=None)
    ap.add_argument("--subtree-only", action="store_true")
    ap.add_argument("--no-recurse", action="store_true")
    args = ap.parse_args()

    ansi_ok = _ansi_supported()
    if not ansi_ok and args.panel in ("twoline", "live", "scroll"):
        args.panel = "oneline"

    color_on = should_use_color(args.color)
    if args.out is None:
        args.out = default_out_from_target(args.target)

    # 0) Spider queue pre-clear (stop + remove) if leftovers exist
    try:
        leftover = spider_scans(args.base, args.apikey)
        left_cnt = len(leftover)
        if left_cnt > 0:
            spider_stop_all(args.base, args.apikey)
            spider_remove_all(args.base, args.apikey)
            print(colorize(f"[SPIDER] previous scans cleared: {left_cnt}", COLOR.DIM, color_on))
        else:
            print(colorize("[SPIDER] no previous scans", COLOR.DIM, color_on))
    except Exception as e:
        print(colorize(f"[SPIDER] pre-clear skipped (API not available?): {e}", COLOR.DIM, color_on))

    # 1) History filter
    if args.filter_baseurl is not None:
        filter_base = args.filter_baseurl
        denom = number_of_messages(args.base, args.apikey, baseurl=filter_base)
        print(colorize(f"[HISTORY] filter-baseurl={filter_base}", COLOR.DIM, color_on))
    else:
        if args.history_filter == "none":
            filter_base, denom = None, number_of_messages(args.base, args.apikey, baseurl=None)
        elif args.history_filter == "target":
            filter_base, denom = args.target, number_of_messages(args.base, args.apikey, baseurl=args.target)
        elif args.history_filter == "host":
            host = urlparse(args.target).netloc
            candidates = [f"http://{host}/", f"https://{host}/"]
            c0 = number_of_messages(args.base, args.apikey, baseurl=candidates[0])
            c1 = number_of_messages(args.base, args.apikey, baseurl=candidates[1])
            filter_base = candidates[0] if c0 >= c1 else candidates[1]
            denom = max(c0, c1)
        else:
            filter_base, denom = decide_baseurl_auto(args.base, args.apikey, args.target)
            if filter_base is None:
                denom = number_of_messages(args.base, args.apikey, baseurl=None)
        fb_disp = filter_base if filter_base else "ALL"
        print(colorize(f"[HISTORY] baseurl={fb_disp} (auto)", COLOR.DIM, color_on))

    # 2) PSCAN queue clear (default ON)
    if args.pscan_clear_on_start:
        clear_pscan_queue(args.base, args.apikey)
        left = pscan_records_to_scan(args.base, args.apikey)
        print(colorize(f"[PSCAN] queue cleared, remain={left}", COLOR.DIM, color_on))

    # 3) Scope / options log
    recurse = not args.no_recurse
    scope_bits = [f"url={args.target}"]
    if args.context_name: scope_bits.append(f"contextName={args.context_name}")
    if args.context_id:  scope_bits.append(f"contextId={args.context_id}")
    if args.user_id:     scope_bits.append(f"userId={args.user_id}")
    if args.max_children is not None: scope_bits.append(f"maxChildren={args.max_children}")
    scope_bits += [f"recurse={str(recurse).lower()}", f"subtreeOnly={str(bool(args.subtree_only)).lower()}"]
    print(colorize("[SCOPE] " + ", ".join(scope_bits), COLOR.BOLD, color_on))

    opts = get_spider_options_safe(args.base, args.apikey)
    opt_summary_parts = []
    for key in ("MaxDepth", "ThreadCount", "MaxDuration", "MaxChildren", "SendRefererHeader"):
        found = None
        for k, v in opts.items():
            if key.lower() in k.lower():
                found = v; break
        if found is not None:
            opt_summary_parts.append(f"{key}={found}")
    if opt_summary_parts:
        print(colorize("[SPIDER OPTIONS] " + ", ".join(opt_summary_parts), COLOR.DIM, color_on))

    # 4) Start spider
    scan_id = spider_start(args.base, args.apikey, args.target,
                           recurse=recurse, subtree_only=args.subtree_only,
                           max_children=args.max_children,
                           context_id=args.context_id, user_id=args.user_id)
    print(colorize(f"[SPIDER] scanId={scan_id}", COLOR.CYAN, color_on))

    # temp ndjson
    tmp_dir = os.path.dirname(os.path.abspath(args.out)) or "."
    ndjson_path = os.path.join(tmp_dir, ".entries.ndjson")
    if os.path.exists(ndjson_path): os.remove(ndjson_path)

    processed_ids = set()
    skipped_ids = set()
    attempts = {}

    last_total_for_fetch = 0
    last_progress_ts = time.time()
    last_mid, last_status, last_url = None, "", ""

    seen_total_monotonic = 0
    effective_page = int(args.page_size)
    eps_window = deque()

    header_meta = {"target": args.target, "filterBase": filter_base, "idsMode": args.ids_mode}

    def get_ids_range(start, count):
        mode = args.ids_mode
        if mode in ("auto", "ids"):
            try:
                return list_message_ids(args.base, args.apikey, start, count, baseurl=filter_base)
            except Exception:
                if mode == "ids":
                    raise
        try:
            msgs = list_messages_heavy(args.base, args.apikey, start, count, baseurl=filter_base)
            return [str(m.get("id")) for m in msgs if m.get("id") is not None]
        except (ChunkedEncodingError, ProtocolError, IncompleteRead) as e:
            nonlocal effective_page
            effective_page = max(10, effective_page // 2)
            print_above_panel(colorize(f"[WARN] Heavy list failed ({e}); shrinking page-size -> {effective_page}", COLOR.YELLOW, color_on))
            return []
        except Exception as e:
            print_above_panel(colorize(f"[WARN] list messages failed: {e}", COLOR.YELLOW, color_on))
            return []

    try:
        while True:
            try:
                sp_pct = spider_status(args.base, args.apikey, scan_id)
            except Exception:
                sp_pct = 0

            try:
                total_now = number_of_messages(args.base, args.apikey, baseurl=filter_base)
            except Exception:
                total_now = seen_total_monotonic
            if total_now > seen_total_monotonic:
                seen_total_monotonic = total_now

            done_cnt = len(processed_ids) + len(skipped_ids)
            eps_window.append((time.time(), done_cnt))
            while eps_window and (time.time() - eps_window[0][0]) > float(args.eps_window_sec):
                eps_window.popleft()
            if len(eps_window) >= 2:
                dt = max(0.001, eps_window[-1][0] - eps_window[0][0])
                dn = max(0, eps_window[-1][1] - eps_window[0][1])
                eps = dn / dt
            else:
                eps = 0.0
            remaining = max(0, seen_total_monotonic - done_cnt)
            eta_s = (remaining / eps) if eps > 0 else float("inf")

            width = _term_width()
            har_seg = make_har_segment(len(processed_ids), len(skipped_ids), seen_total_monotonic, eps, eta_s)
            progress_plain = make_progress_text_spider_first(len(processed_ids), len(skipped_ids), seen_total_monotonic, eps, eta_s, sp_pct)

            if args.panel == "oneline":
                _print_oneline(colorize(progress_plain, COLOR.WHITE, color_on))
            elif args.panel in ("twoline", "live"):
                if last_mid is None:
                    har_plus_line = colorize("[HAR+] (waiting for first HAR...)", COLOR.DIM, color_on)
                else:
                    har_plus_line = format_harplus_compact(last_mid, last_status, last_url, color_on, width, 0)
                prog_line = (
                    colorize(f"[SPIDER] {sp_pct:3d}%", pct_color(float(sp_pct)), color_on)
                    + colorize(" | ", COLOR.DIM, color_on)
                    + colorize(har_seg, COLOR.WHITE, color_on)
                )
                _render_panel([har_plus_line, prog_line])
            else:
                _render_panel([colorize(progress_plain, COLOR.WHITE, color_on)])

            do_fetch = (total_now > 0)
            if getattr(args, "fetch_only_on_growth", False):
                do_fetch = do_fetch and (total_now > last_total_for_fetch)

            if do_fetch:
                tail_pages = max(1, int(args.tail_pages))
                page = max(10, int(effective_page))
                fetch_from = max(0, total_now - (page * tail_pages))
                for chunk_start in range(fetch_from, total_now, page):
                    ids = get_ids_range(chunk_start, page)
                    for mid in ids:
                        if mid in processed_ids or mid in skipped_ids:
                            continue
                        try:
                            entry = har_entry_by_id(args.base, args.apikey, mid)
                            if entry:
                                # 2xx-only filter
                                if _is_2xx(entry):
                                    write_ndjson(ndjson_path, entry)
                                    processed_ids.add(mid)
                                    last_progress_ts = time.time()
                                    last_mid = mid
                                    last_status = entry.get("response", {}).get("status", "")
                                    last_url = entry.get("request", {}).get("url", "")
                                    if args.panel == "scroll":
                                        print_above_panel(colorize("[HAR+]", COLOR.GREEN, color_on) + f" id={mid} {last_status} {last_url}")
                                else:
                                    skipped_ids.add(mid)
                            else:
                                attempts[mid] = attempts.get(mid, 0) + 1
                                if attempts[mid] >= 3:
                                    skipped_ids.add(mid)
                        except KeyboardInterrupt:
                            raise
                        except Exception as e:
                            attempts[mid] = attempts.get(mid, 0) + 1
                            if attempts[mid] >= 3:
                                skipped_ids.add(mid)

            last_total_for_fetch = total_now

            # 종료 조건
            if sp_pct >= 100:
                if done_cnt >= seen_total_monotonic:
                    break
                if (time.time() - last_progress_ts) >= float(args.idle_exit_sec):
                    print_above_panel(colorize(f"[IDLE] no progress for {int(args.idle_exit_sec)}s after SPIDER=100% → exit", COLOR.DIM, color_on))
                    break

            time.sleep(max(0.02, float(args.refresh_sec)))

        if args.pscan_wait:
            while True:
                left = pscan_records_to_scan(args.base, args.apikey)
                msg = f"[PSCAN] remaining: {left}"
                if args.panel == "oneline":
                    _print_oneline(msg)
                elif args.panel in ("twoline","live"):
                    width = _term_width()
                    if last_mid is None:
                        har_plus_line = colorize("[HAR+] (waiting for first HAR...)", COLOR.DIM, color_on)
                    else:
                        har_plus_line = format_harplus_compact(last_mid, last_status, last_url, color_on, width, 0)
                    har_seg = make_har_segment(len(processed_ids), len(skipped_ids), seen_total_monotonic, eps, eta_s)
                    prog_line = (
                        colorize(f"[SPIDER] {sp_pct:3d}%", pct_color(float(sp_pct)), color_on)
                        + colorize(" | ", COLOR.DIM, color_on)
                        + colorize(har_seg, COLOR.WHITE, color_on)
                    )
                    _render_panel([har_plus_line, prog_line, colorize(msg, COLOR.BLUE, color_on)])
                else:
                    _render_panel([msg])
                if left == 0:
                    break
                time.sleep(max(0.02, float(args.refresh_sec)))

    except KeyboardInterrupt:
        if args.panel != "oneline":
            print_above_panel(colorize("[INFO] Interrupted by user. Finalizing partial HAR...", COLOR.YELLOW, color_on))
        else:
            _print_oneline("[INFO] Interrupted by user. Finalizing partial HAR...")

    finally:
        finalize_har(ndjson_path, args.out, meta={"target": args.target, "filterBase": filter_base})
        if args.panel == "oneline":
            # Hard clear the progress line, then print DONE on a fresh line
            _clear_oneline()
            print(colorize(
                f"[DONE] HAR saved → {args.out}  (entries: {len(processed_ids)}, skipped: {len(skipped_ids)})",
                COLOR.GREEN, color_on
            ))
        else:
            _render_panel([])
            print(colorize(
                f"[DONE] HAR saved → {args.out}  (entries: {len(processed_ids)}, skipped: {len(skipped_ids)})",
                COLOR.GREEN, color_on
            ))

if __name__ == "__main__":
    main()
