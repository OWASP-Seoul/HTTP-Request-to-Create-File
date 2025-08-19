#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZAP Spider incremental HAR — clean session + spider stats + HAR title/format
+ denom-refresh throttle + messagesIds auto-detect + clamped % + done-seen exit
+ TIMESTAMPED LOGGING
+ FORWARD SWEEP (auto) + RESILIENT messages paging

- NEW: --scan-mode {auto,forward,tail} (default: auto)
- NEW: --pages-per-loop N  → forward 모드에서 한 루프당 처리할 페이지 수 제한 (기본 10)
- NEW: --min-page-size M   → messages 실패 시 M까지 절반 단위로 축소 재시도 (기본 25)

2025-08-19
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import urllib.parse
import urllib.request

# ──────────────────────────────────────────────────────────────────────────────
# Console/ANSI utilities
# ──────────────────────────────────────────────────────────────────────────────

class COLOR:
    RESET = "\x1b[0m"; RED = "\x1b[31m"; GREEN = "\x1b[32m"; YELLOW = "\x1b[33m"
    BLUE = "\x1b[34m"; MAGENTA = "\x1b[35m"; CYAN = "\x1b[36m"; WHITE = "\x1b[37m"; DIM = "\x1b[2m"

def _isatty() -> bool:
    try: return sys.stdout.isatty()
    except Exception: return False

def _term_width(default=100):
    try:
        import shutil
        return shutil.get_terminal_size((default, 24)).columns
    except Exception:
        return default

def _is_windows() -> bool: return os.name == "nt"

def _enable_vt_mode() -> bool:
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        h = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(h, ctypes.byref(mode)) == 0: return False
        new_mode = ctypes.c_uint32(mode.value | 0x0004)
        if kernel32.SetConsoleMode(h, new_mode) == 0: return False
        return True
    except Exception:
        return False

class _AnsiSupported: _checked=False; _ok=False; _vt_checked=False; _vt_ok=False
_ansi_supported = _AnsiSupported()

def _ansi_ok() -> bool:
    if not _ansi_supported._checked:
        _ansi_supported._checked = True
        _ansi_supported._ok = _isatty() and not os.environ.get("NO_COLOR")
        if _is_windows() and _ansi_supported._ok and not _ansi_supported._vt_checked:
            _ansi_supported._vt_checked = True
            _ansi_supported._vt_ok = _enable_vt_mode()
    return bool(_ansi_supported._ok)

def colorize(s: str, color: str, on: bool) -> str:
    if on and _ansi_ok(): return f"{color}{s}{COLOR.RESET}"
    return s

def _clear_oneline():
    if _ansi_ok():
        sys.stdout.write("\r\033[K"); sys.stdout.flush()

def _println(line: str):
    width = _term_width()
    if _ansi_ok(): print("\r\033[K", end="")
    print(line[:width])

# ──────────────────────────────────────────────────────────────────────────────
# Timestamp helpers
# ──────────────────────────────────────────────────────────────────────────────

def _ts(fmt: str = "%H:%M:%S") -> str:
    try: return time.strftime(fmt, time.localtime())
    except Exception: return time.strftime(fmt)

def stamp(s: str) -> str: return f"[{_ts()}] {s}"

# ──────────────────────────────────────────────────────────────────────────────
# ZAP API helpers
# ──────────────────────────────────────────────────────────────────────────────

JSON_TIMEOUT = 60
OTHER_TIMEOUT = 120

def _zap_build_url(base: str, path: str, params: Dict[str, Any]) -> str:
    if not base.endswith("/"): base += "/"
    q = urllib.parse.urlencode(params or {}, doseq=True)
    return urllib.parse.urljoin(base, path) + ("?" + q if q else "")

def _zap_json(base: str, path: str, params: Dict[str, Any], timeout: int = JSON_TIMEOUT) -> Dict[str, Any]:
    url = _zap_build_url(base, path, params)
    with urllib.request.urlopen(url, timeout=timeout) as r:
        body = r.read().decode("utf-8", "replace")
        try: return json.loads(body)
        except Exception: return {"_raw": body}

def _zap_other(base: str, path: str, params: Dict[str, Any], timeout: int = OTHER_TIMEOUT) -> bytes:
    url = _zap_build_url(base, path, params)
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()

def spider_scans(base, apikey): 
    try: return _zap_json(base, "JSON/spider/view/scans/", {"apikey": apikey}).get("scans", [])
    except Exception: return []

def spider_stop_all(base, apikey):
    try: _zap_json(base, "JSON/spider/action/stopAllScans/", {"apikey": apikey})
    except Exception: pass

def spider_remove_all(base, apikey):
    try: _zap_json(base, "JSON/spider/action/removeAllScans/", {"apikey": apikey})
    except Exception: pass

def pscan_clear_queue(base, apikey):
    try: _zap_json(base, "JSON/pscan/action/clearQueue/", {"apikey": apikey})
    except Exception: pass

def pscan_records_to_scan(base, apikey) -> int:
    try: return int(_zap_json(base, "JSON/pscan/view/recordsToScan/", {"apikey": apikey}).get("recordsToScan", 0))
    except Exception: return 0

def new_session(base, apikey, name: Optional[str] = None, overwrite: bool = True) -> bool:
    if not name: name = f"auto_{int(time.time())}"
    try:
        _zap_json(base, "JSON/core/action/newSession/", {"apikey": apikey, "name": name, "overwrite": "true" if overwrite else "false"})
        return True
    except Exception:
        return False

def spider_start(base, apikey, url, recurse=True, subtreeOnly=False, maxChildren=0, contextId=None, userId=None, userAgent=None):
    params = {"apikey": apikey, "url": url, "recurse": "true" if recurse else "false",
              "subtreeOnly": "true" if subtreeOnly else "false", "maxChildren": str(int(maxChildren or 0))}
    if contextId is not None: params["contextId"] = str(contextId)
    if userId is not None: params["userId"] = str(userId)
    if userAgent: params["userAgent"] = userAgent
    j = _zap_json(base, "JSON/spider/action/scan/", params)
    return int(j.get("scan", 0))

def spider_status(base, apikey, scan_id: int) -> int:
    try: return int(_zap_json(base, "JSON/spider/view/status/", {"apikey": apikey, "scanId": str(scan_id)}).get("status", 0))
    except Exception: return 0

def spider_results_count(base, apikey, scan_id: int) -> Optional[int]:
    try:
        res = _zap_json(base, "JSON/spider/view/results/", {"apikey": apikey, "scanId": str(scan_id)}).get("results", [])
        if isinstance(res, list): return len(res)
        if isinstance(res, dict):
            for k in ("URLs","urls","Results","results"):
                if k in res and isinstance(res[k], list): return len(res[k])
        return None
    except Exception:
        return None

def spider_added_nodes_count(base, apikey, scan_id: int) -> Optional[int]:
    try:
        res = _zap_json(base, "JSON/spider/view/addedNodes/", {"apikey": apikey, "scanId": str(scan_id)}).get("addedNodes", [])
        if isinstance(res, list): return len(res)
        return None
    except Exception:
        return None

def number_of_messages(base, apikey, baseurl: Optional[str]) -> int:
    params = {"apikey": apikey}
    if baseurl: params["baseurl"] = baseurl
    return int(_zap_json(base, "JSON/core/view/numberOfMessages/", params).get("numberOfMessages", 0))

def messages_ids(base, apikey, baseurl: Optional[str], start: int, count: int) -> List[int]:
    params = {"apikey": apikey, "start": str(start), "count": str(count)}
    if baseurl: params["baseurl"] = baseurl
    j = _zap_json(base, "JSON/core/view/messagesIds/", params)
    ids = j.get("ids")
    if isinstance(ids, list):
        try: return [int(x) for x in ids]
        except Exception: return []
    raise RuntimeError("messagesIds unsupported or bad_view")

def supports_messages_ids(base, apikey) -> bool:
    try: _ = messages_ids(base, apikey, None, 0, 1); return True
    except Exception: return False

def message_har_by_id(base, apikey, msg_id: int) -> Optional[Dict[str, Any]]:
    try:
        raw = _zap_other(base, "OTHER/importexport/other/exportHarById/", {"apikey": apikey, "id": str(msg_id)})
        return json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        pass
    try:
        raw = _zap_other(base, "OTHER/core/other/messageHar/", {"apikey": apikey, "id": str(msg_id)})
        return json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return None

def messages(base, apikey, baseurl: Optional[str], start: int, count: int) -> List[Dict[str, Any]]:
    params = {"apikey": apikey, "start": str(start), "count": str(count)}
    if baseurl: params["baseurl"] = baseurl
    return _zap_json(base, "JSON/core/view/messages/", params).get("messages", [])

# ──────────────────────────────────────────────────────────────────────────────
# HAR helpers
# ──────────────────────────────────────────────────────────────────────────────

def _is_2xx(entry: Dict[str, Any]) -> bool:
    try:
        status = int(entry["response"]["status"])
        return 200 <= status <= 299
    except Exception:
        return False

def finalize_har(ndjson_path: Path, out_har_path: Path, meta=None):
    har = {"log": {"version": "1.2", "creator": {"name": "ZAP", "version": ""}, "browser": {}, "pages": [], "entries": []}}
    entries = []
    if ndjson_path.exists():
        with ndjson_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    obj = json.loads(line)
                    if "log" in obj and "entries" in obj["log"]:
                        entries.extend(obj["log"]["entries"])
                    elif "entries" in obj:
                        entries.extend(obj["entries"])
                    elif "request" in obj and "response" in obj:
                        entries.append(obj)
                except Exception:
                    continue
    har["log"]["entries"] = entries
    if meta: har["log"]["_zap_meta"] = meta
    with out_har_path.open("w", encoding="utf-8") as f:
        json.dump(har, f, ensure_ascii=False, indent=2)

# ──────────────────────────────────────────────────────────────────────────────
# Progress segments (titles) — SPIDER & HAR
# ──────────────────────────────────────────────────────────────────────────────

def make_spider_segment(spider_pct: int, urls_found: Optional[int], nodes_added: Optional[int]) -> str:
    seg = f"[SPIDER] {spider_pct:3d}%"
    extras = []
    if urls_found is not None: extras.append(f"URLs {urls_found}")
    if nodes_added is not None: extras.append(f"Nodes {nodes_added}")
    if extras: seg += " (" + ", ".join(extras) + ")"
    return seg

def make_har_segment(processed_cnt: int, skipped_cnt: int, denom: int, mode: str = "compact") -> str:
    done_cnt = processed_cnt + skipped_cnt
    denom_eff = max(denom, done_cnt, 1)
    pct = (done_cnt / denom_eff) * 100.0
    if mode == "verbose":
        return f"[HAR] {pct:4.1f}% (2xx={processed_cnt}, skipped={skipped_cnt}, seen={denom_eff}, done={done_cnt})"
    pct_str = f"{pct:3.0f}%" if pct >= 10 else f"{pct:3.1f}%"
    return f"[HAR] {pct_str} (2xx {processed_cnt}, Skipped {skipped_cnt}, Seen {denom_eff})"

# ──────────────────────────────────────────────────────────────────────────────
# Denominator throttler
# ──────────────────────────────────────────────────────────────────────────────

class DenomFetcher:
    def __init__(self, base: str, apikey: str, baseurl: Optional[str], refresh_sec: float = 0.0):
        self.base = base; self.apikey = apikey; self.baseurl = baseurl
        self.refresh_sec = max(0.0, float(refresh_sec or 0.0))
        self._last_ts: float = 0.0; self._last_val: int = 0

    def get(self, force: bool = False) -> int:
        now = time.time()
        if not force and self.refresh_sec > 0 and (now - self._last_ts) < self.refresh_sec and self._last_val > 0:
            return self._last_val
        try:
            val = number_of_messages(self.base, self.apikey, self.baseurl)
            if val < self._last_val: val = self._last_val  # monotonic
            self._last_val = val; self._last_ts = now
            return val
        except Exception:
            return self._last_val

# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="ZAP Spider → incremental HAR exporter (clean session + spider stats + HAR title/format + denom throttle + timestamps + forward sweep)")
    ap.add_argument("--base", default="http://127.0.0.1:8090", help="ZAP base URL")
    ap.add_argument("--apikey", default="SECRET", help="ZAP apikey")
    ap.add_argument("--target", required=True, help="Target URL to spider")
    ap.add_argument("--out", default=None, help="Output HAR path (default: <host>.har)")
    ap.add_argument("--page-size", type=int, default=200, help="Page size (IDs/messages fetch)")
    ap.add_argument("--min-page-size", type=int, default=25, help="Minimum page size for resilient fallback")
    ap.add_argument("--tail-pages", type=int, default=5, help="How many last pages to sweep (tail mode)")
    ap.add_argument("--pages-per-loop", type=int, default=10, help="Forward mode: max pages to fetch per loop")
    ap.add_argument("--scan-mode", choices=["auto","forward","tail"], default="auto", help="Forward first then tail, forward only, or tail only")
    ap.add_argument("--refresh-sec", type=float, default=0.25, help="UI refresh interval")
    ap.add_argument("--panel", choices=["oneline","twoline","live","scroll"], default="twoline", help="Progress panel style")
    ap.add_argument("--color", choices=["auto","always","never"], default="auto", help="Color output")
    ap.add_argument("--pscan-clear-on-start", action="store_true", default=True, help="Clear passive scanner queue at start")
    ap.add_argument("--no-pscan-clear-on-start", action="store_false", dest="pscan_clear_on_start")
    ap.add_argument("--pscan-wait", action="store_true", help="Wait until passive scanner queue drains at the end")
    ap.add_argument("--no-recurse", action="store_true", help="Spider without recursion")
    ap.add_argument("--subtree-only", action="store_true", help="Restrict to subtree")
    ap.add_argument("--max-children", type=int, default=0, help="Max children for spider")
    ap.add_argument("--user-agent", default=None, help="Override user agent for spider")
    ap.add_argument("--history-filter", choices=["auto","target","host","none"], default="auto")
    ap.add_argument("--filter-baseurl", default=None, help="Explicit baseurl filter for history APIs")
    ap.add_argument("--ids-mode", choices=["ids","messages","auto"], default="auto",
                    help="Use lightweight IDs list, full messages, or auto-detect (default: auto)")
    ap.add_argument("--context-id", type=int, default=None); ap.add_argument("--user-id", type=int, default=None)
    ap.add_argument("--new-session", action="store_true", default=True, help="Start with a NEW ZAP session (clears history)")
    ap.add_argument("--no-new-session", action="store_false", dest="new_session")
    ap.add_argument("--session-name", default="auto_session", help="Name for the new session (used when --new-session)")
    ap.add_argument("--exit-when-done-seen", action="store_true", default=True,
                    help="When spider=100% and processed+skipped==current history size, exit immediately (default on)")
    ap.add_argument("--no-exit-when-done-seen", action="store_false", dest="exit_when_done_seen")
    ap.add_argument("--har-format", choices=["compact","verbose"], default="compact", help="HAR progress format")
    ap.add_argument("--denom-refresh-sec", type=float, default=0.0, help="Throttle numberOfMessages() polling")
    ap.add_argument("--diag", action="store_true", help="Print diagnostic counters per loop")
    args = ap.parse_args()

    # Output default
    if not args.out:
        parsed = urllib.parse.urlparse(args.target)
        host = parsed.hostname or "output"
        args.out = f"{host}.har"

    color_on = (args.color == "always") or (args.color == "auto" and _ansi_ok())

    # (1) New session
    if args.new_session:
        ok = new_session(args.base, args.apikey, name=args.session_name, overwrite=True)
        print(colorize(stamp(f"[SESSION] new session {'created' if ok else 'failed'}: {args.session_name}"), COLOR.DIM if ok else COLOR.YELLOW, color_on))

    # (2) Stop & remove any pre-existing spider scans
    scans = spider_scans(args.base, args.apikey)
    if scans:
        spider_stop_all(args.base, args.apikey); spider_remove_all(args.base, args.apikey)
        print(colorize(stamp(f"[SPIDER] previous scans cleared: {len(scans)}"), COLOR.DIM, color_on))
    else:
        print(colorize(stamp("[SPIDER] no previous scans"), COLOR.DIM, color_on))

    # (3) Optional: clear Passive Scanner queue
    if args.pscan_clear_on_start:
        pscan_clear_queue(args.base, args.apikey)
        remain = pscan_records_to_scan(args.base, args.apikey)
        print(colorize(stamp(f"[PSCAN] queue cleared, remain={remain}"), COLOR.DIM, color_on))

    # (4) Scope & options
    print(colorize(stamp(f"[SCOPE] url={args.target}, recurse={not args.no_recurse}, subtreeOnly={args.subtree_only}"), COLOR.CYAN, color_on))
    print(colorize(stamp(f"[SPIDER OPTIONS] MaxDepth=0, ThreadCount=16, MaxDuration=0, MaxChildren={args.max_children}, SendRefererHeader=true"), COLOR.CYAN, color_on))

    # (5) Start spider
    scan_id = spider_start(args.base, args.apikey, args.target, recurse=not args.no_recurse,
                           subtreeOnly=args.subtree_only, maxChildren=args.max_children,
                           contextId=args.context_id, userId=args.user_id, userAgent=args.user_agent)
    print(colorize(stamp(f"[SPIDER] scanId={scan_id}"), COLOR.GREEN, color_on))

    # (6) Resolve history filter baseurl
    filter_base = args.filter_baseurl
    if not filter_base:
        parsed = urllib.parse.urlparse(args.target); host = parsed.hostname or ""
        schemes = ["https","http"]; candidates = []
        if args.history_filter in ("auto","host"):
            for sch in schemes: candidates.append(f"{sch}://{host}/")
        if args.history_filter in ("auto","target"):
            base_target = f"{parsed.scheme}://{host}/"
            if base_target not in candidates: candidates.append(base_target)
        best, best_n = None, -1
        for c in candidates:
            try: n = number_of_messages(args.base, args.apikey, c)
            except Exception: n = -1
            if n > best_n: best, best_n = c, n
        filter_base = None if args.history_filter == "none" else (best if best_n >= 0 else None)
    print(colorize(stamp(f"[HISTORY] baseurl={'ALL' if not filter_base else filter_base} ({args.history_filter})"), COLOR.DIM, color_on))

    # (7) Auto-detect messagesIds support when args.ids_mode=auto
    ids_mode = args.ids_mode
    if ids_mode == "auto":
        if supports_messages_ids(args.base, args.apikey):
            ids_mode = "ids"; print(colorize(stamp("[CAPS] messagesIds view: supported → using ids mode"), COLOR.DIM, color_on))
        else:
            ids_mode = "messages"; print(colorize(stamp("[CAPS] messagesIds view: unsupported → using messages mode"), COLOR.YELLOW, color_on))
    else:
        print(colorize(stamp(f"[CAPS] ids_mode={ids_mode}"), COLOR.DIM, color_on))

    # Prepare work
    processed_ids, skipped_ids = set(), set()
    ndjson_path = Path(args.out).with_suffix(".ndjson")
    if ndjson_path.exists(): ndjson_path.unlink()

    # Denominator throttler
    denom_fetcher = DenomFetcher(args.base, args.apikey, filter_base, refresh_sec=args.denom_refresh_sec)
    last_seen_total = 0
    last_diag_ts = 0.0
    diag_interval = 5.0  # seconds

    # Forward sweep state
    forward_cursor = 0
    forward_phase = (args.scan_mode in ("auto","forward"))

    # Resilient fetcher
    def fetch_ids_chunk(offs: int, size: int) -> Tuple[List[int], int]:
        """Return (ids, used_size). On failure shrink size/2 until min-page-size; if all fail, return ([], 0)."""
        s = max(args.min_page_size, size)
        tried = s
        while s >= args.min_page_size:
            try:
                if ids_mode == "ids":
                    ids = messages_ids(args.base, args.apikey, filter_base, offs, s)
                else:
                    msgs = messages(args.base, args.apikey, filter_base, offs, s)
                    ids = [int(m.get("id")) for m in msgs if "id" in m]
                return ids, s
            except Exception:
                s //= 2
        return [], 0  # failed

    def fetch_ids_range(total_now: int) -> Tuple[List[int], str]:
        """Return (deduped ids, mode_label) according to scan mode/state."""
        size = max(1, int(args.page_size))
        if forward_phase:
            ids: List[int] = []
            end = total_now
            pages = max(1, int(args.pages_per_loop))
            offs = forward_cursor
            count = 0
            while offs < end and count < pages:
                chunk, used = fetch_ids_chunk(offs, size)
                if not chunk and used == 0:
                    # failed this offset; skip forward by min-page-size to avoid deadlock
                    offs += max(args.min_page_size, 1)
                    count += 1
                    continue
                ids.extend(chunk)
                offs += used
                count += 1
            # dedup preserve order
            seen_local = set(); dedup = []
            for i in ids:
                if i not in seen_local: dedup.append(i); seen_local.add(i)
            return dedup, "forward"
        else:
            # tail mode
            size = max(1, int(args.page_size))
            pages = max(1, int(args.tail_pages))
            start = max(0, total_now - size * pages)
            ids: List[int] = []
            offs = start
            while offs < total_now:
                chunk, used = fetch_ids_chunk(offs, size)
                if not chunk and used == 0:
                    # skip this page to avoid stalling
                    offs += max(args.min_page_size, 1)
                    continue
                ids.extend(chunk)
                offs += used
            seen_local = set(); dedup = []
            for i in ids:
                if i not in seen_local: dedup.append(i); seen_local.add(i)
            return dedup, "tail"

    # polling
    while True:
        # Spider status
        try: sp_pct = spider_status(args.base, args.apikey, scan_id)
        except Exception: sp_pct = 0

        # Denominator BEFORE processing (throttled)
        denom_before = denom_fetcher.get(force=(last_seen_total == 0))
        denom_monotonic = max(last_seen_total, denom_before)

        # Spider metrics
        urls_found = spider_results_count(args.base, args.apikey, scan_id)
        nodes_added = spider_added_nodes_count(args.base, args.apikey, scan_id)

        # Fetch and process IDs
        ids, mode_label = fetch_ids_range(denom_monotonic)
        new_ids = [i for i in ids if i not in processed_ids and i not in skipped_ids]
        new_processed = new_skipped = 0
        last_url = None

        with ndjson_path.open("a", encoding="utf-8") as f_out:
            for mid in ids:
                if mid in processed_ids or mid in skipped_ids: continue
                har = message_har_by_id(args.base, args.apikey, mid)
                if not har:
                    skipped_ids.add(mid); new_skipped += 1; continue
                try:
                    entries = har["log"]["entries"] if "log" in har else har["entries"]
                except Exception:
                    skipped_ids.add(mid); new_skipped += 1; continue
                if not entries:
                    skipped_ids.add(mid); new_skipped += 1; continue
                if any(_is_2xx(e) for e in entries):
                    f_out.write(json.dumps(har, ensure_ascii=False) + "\n")
                    processed_ids.add(mid); new_processed += 1
                    try: last_url = entries[0]["request"]["url"]
                    except Exception: last_url = None
                else:
                    skipped_ids.add(mid); new_skipped += 1

        done_cnt = len(processed_ids) + len(skipped_ids)

        # Advance forward cursor if in forward phase
        if forward_phase:
            # cursor moves to the highest offset we attempted (monotonic)
            forward_cursor = max(forward_cursor, denom_monotonic if not new_ids else max(new_ids)+1)
            # switch to tail if we've caught up
            if forward_cursor >= denom_monotonic:
                if args.scan_mode == "auto":
                    forward_phase = False
                    print(stamp("[MODE] switched to tail (caught up)"))

        # Denominator AFTER processing (throttled)
        denom_after = denom_fetcher.get(force=False)
        denom_fresh = max(denom_monotonic, denom_after)

        # DIAG (throttled every 5s)
        if args.diag and (time.time() - last_diag_ts >= diag_interval):
            window = (args.page_size * (args.pages_per_loop if forward_phase else args.tail_pages))
            mode_hint = f"{mode_label}, cursor={forward_cursor}" if forward_phase else mode_label
            _println(colorize(stamp(f"[DIAG] mode={mode_hint}, fetched={len(ids)}, new={len(new_ids)}, window={window}, done={done_cnt}, denom={denom_fresh}"), COLOR.DIM, True))
            last_diag_ts = time.time()

        # Early-exit when spider=100% and we've processed what's visible
        if sp_pct >= 100 and args.exit_when_done_seen and done_cnt >= denom_fresh:
            spider_seg = make_spider_segment(spider_pct=sp_pct, urls_found=urls_found, nodes_added=nodes_added)
            har_seg = make_har_segment(len(processed_ids), len(skipped_ids), denom_fresh, mode=args.har_format)
            if _isatty() and args.panel == "oneline":
                _clear_oneline()
                sys.stdout.write(stamp(f"{spider_seg} | {har_seg}")[:_term_width()] + "\r"); sys.stdout.flush()
            break

        # Render panel
        spider_seg = make_spider_segment(spider_pct=sp_pct, urls_found=urls_found, nodes_added=nodes_added)
        har_seg   = make_har_segment(len(processed_ids), len(skipped_ids), denom_fresh, mode=args.har_format)

        if args.panel == "oneline":
            _clear_oneline(); sys.stdout.write(stamp(f"{spider_seg} | {har_seg}")[:_term_width()] + "\r"); sys.stdout.flush()
        elif args.panel in ("twoline","live"):
            if last_url: _println(colorize(stamp(f"[HAR+] {last_url}"), COLOR.WHITE, color_on))
            _println(colorize(stamp(f"{spider_seg} | {har_seg}"), COLOR.CYAN, color_on))
        elif args.panel == "scroll":
            if last_url: print(colorize(stamp(f"[HAR+] {last_url}"), COLOR.WHITE, color_on))
            print(colorize(stamp(f"{spider_seg} | {har_seg}"), COLOR.CYAN, color_on))

        last_seen_total = denom_fresh
        time.sleep(float(args.refresh_sec))

    # finalize
    finalize_har(Path(args.out).with_suffix(".ndjson"), Path(args.out), meta={"target": args.target, "filterBase": filter_base})
    print(colorize(stamp(f"[DONE] HAR saved → {args.out}  (entries: {len(processed_ids)}, skipped: {len(skipped_ids)})"), COLOR.GREEN, True))

if __name__ == "__main__":
    main()
