#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZAP Spider incremental HAR
- Clean session (optional)
- Spider stats (URLs Found, Nodes Added)
- HAR progress with titles (compact/verbose)
- Denominator refresh throttle (numberOfMessages)
- messagesIds auto-detect with fallback to messages
- Timestamped logging
- Forward sweep + resilient paging
- Early-exit when spider=100 and processed==seen
- Snapshot/Reseed/Segment + optional session rolling
- Stream mode (offset 0부터 순차 처리)
- NEW: Bad host 패턴 자동 제외(스파이더 exclude regex) + HAR 루프 2차 방어 스킵

2025-08-21
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set
import urllib.parse
import urllib.request
from collections import deque

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

def spider_results(base, apikey, scan_id: int) -> List[str]:
    try:
        res = _zap_json(base, "JSON/spider/view/results/", {"apikey": apikey, "scanId": str(scan_id)}).get("results", [])
        if isinstance(res, list): return [str(u) for u in res]
        if isinstance(res, dict):
            for k in ("URLs","urls","Results","results"):
                if k in res and isinstance(res[k], list):
                    return [str(u) for u in res[k]]
        return []
    except Exception:
        return []

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

def spider_add_exclude_regex(base, apikey, regex: str):
    try:
        _zap_json(base, "JSON/spider/action/excludeFromScan/", {"apikey": apikey, "regex": regex})
        print(stamp(f"[SPIDER] exclude regex added: {regex}"))
    except Exception as e:
        print(stamp(f"[SPIDER] exclude add failed: {e}"))

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

    def reset(self):
        self._last_ts = 0.0
        self._last_val = 0

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
# Snapshot / Reseed helpers
# ──────────────────────────────────────────────────────────────────────────────

def _host_of(url: str) -> Optional[str]:
    try:
        return urllib.parse.urlparse(url).hostname
    except Exception:
        return None

def save_checkpoint(path: Path, target: str, discovered: Set[str], processed: Set[str]):
    data = {
        "version": 1,
        "timestamp": int(time.time()),
        "target": target,
        "discovered_urls": sorted(discovered),
        "processed_urls": sorted(processed),
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    tmp.replace(path)

def load_checkpoint(path: Path) -> Tuple[str, Set[str], Set[str]]:
    with path.open("r", encoding="utf-8") as f:
        j = json.load(f)
    target = j.get("target", "")
    discovered = set(j.get("discovered_urls", []))
    processed = set(j.get("processed_urls", []))
    return target, discovered, processed

def filter_seeds(candidates: List[str], target_host: str, same_host_only: bool) -> List[str]:
    out = []
    for u in candidates:
        if not (u.startswith("http://") or u.startswith("https://")):
            continue
        if same_host_only:
            h = _host_of(u)
            if h and h.lower() != target_host.lower():
                continue
        out.append(u)
    return out

# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="ZAP Spider → incremental HAR exporter (+ snapshot/reseed/segment/stream + bad-host exclude)")
    ap.add_argument("--base", default="http://127.0.0.1:8090", help="ZAP base URL")
    ap.add_argument("--apikey", default="SECRET", help="ZAP apikey")
    ap.add_argument("--target", required=True, help="Target URL to spider")
    ap.add_argument("--out", default=None, help="Output HAR path (default: <host>.har)")

    # Fetching / polling
    ap.add_argument("--page-size", type=int, default=200, help="Page size (IDs/messages fetch)")
    ap.add_argument("--min-page-size", type=int, default=25, help="Minimum page size for resilient fallback")
    ap.add_argument("--tail-pages", type=int, default=5, help="How many last pages to sweep (tail mode)")
    ap.add_argument("--pages-per-loop", type=int, default=10, help="Forward mode: max pages to fetch per loop")
    ap.add_argument("--scan-mode", choices=["auto","forward","tail","stream"], default="auto",
                    help="forward→tail(기본), forward만, tail만, 또는 stream(오프셋 0부터 순차)")
    ap.add_argument("--stream-batch", type=int, default=1, help="Stream 모드에서 한 번에 가져올 개수(기본 1)")
    ap.add_argument("--stream-start-offset", type=int, default=0, help="Stream 모드 시작 오프셋(기본 0)")
    ap.add_argument("--refresh-sec", type=float, default=0.25, help="UI refresh interval")
    ap.add_argument("--panel", choices=["oneline","twoline","live","scroll"], default="twoline", help="Progress panel style")
    ap.add_argument("--color", choices=["auto","always","never"], default="auto", help="Color output")

    # Spider behavior
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

    # Clean session controls
    ap.add_argument("--new-session", action="store_true", default=True, help="Start with a NEW ZAP session (clears history)")
    ap.add_argument("--no-new-session", action="store_false", dest="new_session")
    ap.add_argument("--session-name", default="auto_session", help="Name for the new session (used when --new-session)")

    # Early-exit policy
    ap.add_argument("--exit-when-done-seen", action="store_true", default=True,
                    help="When spider=100% and processed+skipped==current history size, exit immediately (default on)")
    ap.add_argument("--no-exit-when-done-seen", action="store_false", dest="exit_when_done_seen")

    # HAR display format
    ap.add_argument("--har-format", choices=["compact","verbose"], default="compact", help="HAR progress format")

    # Denominator refresh throttle
    ap.add_argument("--denom-refresh-sec", type=float, default=0.0, help="Throttle numberOfMessages() polling")

    # Diagnostics
    ap.add_argument("--diag", action="store_true", help="Print diagnostic counters per loop")

    # Snapshot & Reseed
    ap.add_argument("--checkpoint-file", default=None, help="Path to save/load snapshot (discovered/processed URLs)")
    ap.add_argument("--checkpoint-interval-sec", type=int, default=60, help="How often to save snapshot (0=only on exit/roll)")
    ap.add_argument("--reseed-from-checkpoint", action="store_true", help="On start, seed spider with outstanding URLs from checkpoint")
    ap.add_argument("--reseed-limit", type=int, default=100, help="Max number of seed URLs to use per reseed wave/roll (0=unlimited)")
    ap.add_argument("--reseed-same-host-only", action="store_true", default=True, help="Use only seeds on the same host as target")
    ap.add_argument("--no-reseed-same-host-only", action="store_false", dest="reseed_same_host_only")
    ap.add_argument("--reseed-subtree-only", action="store_true", default=True, help="Use subtreeOnly=true when reseeding")
    ap.add_argument("--no-reseed-subtree-only", action="store_false", dest="reseed_subtree_only")
    ap.add_argument("--seed-file", default=None, help="Optional file containing extra seed URLs (one per line)")

    # Optional session rolling (by denom threshold)
    ap.add_argument("--roll-denom-threshold", type=int, default=0, help="If >0, when seen>=threshold then start a new session and reseed")
    ap.add_argument("--roll-interval-sec", type=int, default=900, help="Minimum seconds between rolls (default 15m)")

    # NEW: bad host 자동 제외 토글 / 추가 정규식
    ap.add_argument("--auto-exclude-bad-hosts", action="store_true", default=True,
                    help="호스트에 '_' 포함 & '.' 없는 형태를 Spider에서 제외(기본 ON)")
    ap.add_argument("--no-auto-exclude-bad-hosts", action="store_false", dest="auto_exclude_bad_hosts")
    ap.add_argument("--extra-exclude-regex", action="append", default=[],
                    help="추가로 Spider exclude regex를 등록(옵션 반복 가능)")

    args = ap.parse_args()

    # Output default
    if not args.out:
        parsed = urllib.parse.urlparse(args.target)
        host = parsed.hostname or "output"
        args.out = f"{host}.har"
    ndjson_path = Path(args.out).with_suffix(".ndjson")
    if ndjson_path.exists(): ndjson_path.unlink()

    color_on = (args.color == "always") or (args.color == "auto" and _ansi_ok())

    # Snapshot state
    checkpoint_path = Path(args.checkpoint_file) if args.checkpoint_file else None
    discovered_urls: Set[str] = set()
    processed_urls: Set[str]  = set()
    last_checkpoint_ts = 0.0

    def maybe_save_checkpoint(force: bool = False):
        nonlocal last_checkpoint_ts
        if not checkpoint_path: return
        if args.checkpoint_interval_sec <= 0 and not force: return
        now = time.time()
        if force or (now - last_checkpoint_ts) >= args.checkpoint_interval_sec:
            try:
                save_checkpoint(checkpoint_path, args.target, discovered_urls, processed_urls)
                last_checkpoint_ts = now
                print(colorize(stamp(f"[CKPT] saved → {checkpoint_path} (disc={len(discovered_urls)}, proc={len(processed_urls)})"), COLOR.DIM, color_on))
            except Exception as e:
                print(colorize(stamp(f"[CKPT] save failed: {e}"), COLOR.YELLOW, color_on))

    def load_seeds_from_checkpoint() -> List[str]:
        if not checkpoint_path or not checkpoint_path.exists():
            return []
        try:
            with checkpoint_path.open("r", encoding="utf-8") as f:
                j = json.load(f)
            disc = set(j.get("discovered_urls", []))
            proc = set(j.get("processed_urls", []))
            discovered_urls.update(disc)
            processed_urls.update(proc)
            target_host = urllib.parse.urlparse(args.target).hostname or ""
            outstanding = list(disc - proc)
            seeds = filter_seeds(outstanding, target_host, args.reseed_same_host_only)
            if args.reseed_limit > 0:
                seeds = seeds[:args.reseed_limit]
            print(colorize(stamp(f"[CKPT] loaded ← {checkpoint_path} (outstanding seeds={len(seeds)})"), COLOR.DIM, color_on))
            return seeds
        except Exception as e:
            print(colorize(stamp(f"[CKPT] load failed: {e}"), COLOR.YELLOW, color_on))
            return []

    def load_seeds_from_file() -> List[str]:
        if not args.seed_file: return []
        p = Path(args.seed_file)
        if not p.exists(): return []
        lines = [ln.strip() for ln in p.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
        target_host = urllib.parse.urlparse(args.target).hostname or ""
        seeds = filter_seeds(lines, target_host, args.reseed_same_host_only)
        return seeds

    # ── Fetcher utilities ─────────────────────────────────────────────────────

    def fetch_ids_chunk(ids_mode: str, filter_base: Optional[str], offs: int, size: int) -> Tuple[List[int], int]:
        """Resilient page fetch used by forward/tail modes."""
        s = max(args.min_page_size, size)
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
        return [], 0

    def fetch_ids_range(ids_mode: str, filter_base: Optional[str], total_now: int, forward_phase: bool,
                        forward_cursor: int) -> Tuple[List[int], str, int]:
        """Forward/Tail용."""
        size = max(1, int(args.page_size))
        if forward_phase:
            ids: List[int] = []
            end = total_now
            pages = max(1, int(args.pages_per_loop))
            offs = forward_cursor
            count = 0
            while offs < end and count < pages:
                chunk, used = fetch_ids_chunk(ids_mode, filter_base, offs, size)
                if not chunk and used == 0:
                    offs += max(args.min_page_size, 1)
                    count += 1
                    continue
                ids.extend(chunk); offs += used; count += 1
            seen_local = set(); dedup = []
            for i in ids:
                if i not in seen_local: dedup.append(i); seen_local.add(i)
            return dedup, "forward", offs
        else:
            pages = max(1, int(args.tail_pages))
            start = max(0, total_now - size * pages)
            ids: List[int] = []
            offs = start
            while offs < total_now:
                chunk, used = fetch_ids_chunk(ids_mode, filter_base, offs, size)
                if not chunk and used == 0:
                    offs += max(args.min_page_size, 1)
                    continue
                ids.extend(chunk); offs += used
            seen_local = set(); dedup = []
            for i in ids:
                if i not in seen_local: dedup.append(i); seen_local.add(i)
            return dedup, "tail", forward_cursor

    def fetch_ids_stream(ids_mode: str, filter_base: Optional[str], stream_offset: int, batch: int) -> Tuple[List[int], int]:
        """
        Stream 모드: start=stream_offset, count=batch 로 딱 그 구간만 가져와 바로 처리.
        반환: (ids, new_stream_offset)
        """
        count = max(1, int(batch))
        if ids_mode == "ids":
            try:
                ids = messages_ids(args.base, args.apikey, filter_base, stream_offset, count)
            except Exception:
                ids = []
        else:
            try:
                msgs = messages(args.base, args.apikey, filter_base, stream_offset, count)
                ids = [int(m.get("id")) for m in msgs if "id" in m]
            except Exception:
                ids = []
        return ids, stream_offset + len(ids)

    # ── One scan runner (scan a single seed/target) ───────────────────────────

    def run_one_scan(start_url: str,
                     processed_ids: Set[int],
                     skipped_ids: Set[int],
                     ndjson_path: Path,
                     filter_base: Optional[str],
                     ids_mode: str,
                     denom_fetcher: DenomFetcher,
                     forward_mode_first: bool = True) -> Tuple[int, int, int]:
        """
        Run spider scan for start_url (subtreeOnly per args).
        Returns tuple(processed_count_inc, skipped_count_inc, spider_scan_id_last).
        """
        # Start spider
        scan_id = spider_start(
            args.base, args.apikey, start_url,
            recurse=not args.no_recurse, subtreeOnly=args.subtree_only or args.reseed_subtree_only,
            maxChildren=args.max_children, contextId=args.context_id, userId=args.user_id,
            userAgent=args.user_agent
        )
        print(colorize(stamp(f"[SPIDER] scanId={scan_id}  (seed: {start_url})"), COLOR.GREEN, color_on))

        # State for loop
        last_seen_total = 0
        forward_phase = (args.scan_mode in ("auto","forward")) and forward_mode_first
        tail_phase = (args.scan_mode == "tail")
        stream_phase = (args.scan_mode == "stream")
        forward_cursor = 0
        stream_offset = max(0, int(args.stream_start_offset))
        last_diag_ts = 0.0
        diag_interval = 5.0

        while True:
            try: sp_pct = spider_status(args.base, args.apikey, scan_id)
            except Exception: sp_pct = 0

            # Update discovered URLs snapshot (for checkpoint)
            try:
                res_urls = spider_results(args.base, args.apikey, scan_id)
                if res_urls: discovered_urls.update(res_urls)
            except Exception:
                pass

            # Denominator BEFORE
            denom_before = denom_fetcher.get(force=(last_seen_total == 0))
            denom_monotonic = max(last_seen_total, denom_before)

            # Spider metrics
            urls_found = spider_results_count(args.base, args.apikey, scan_id)
            nodes_added = spider_added_nodes_count(args.base, args.apikey, scan_id)

            # Fetch & process HAR
            if stream_phase:
                ids, stream_offset = fetch_ids_stream(ids_mode, filter_base, stream_offset, args.stream_batch)
                mode_label = "stream"
            else:
                ids, mode_label, forward_cursor = fetch_ids_range(
                    ids_mode, filter_base, denom_monotonic,
                    forward_phase, forward_cursor
                )

            new_processed = 0; new_skipped = 0; last_url_har = None

            with ndjson_path.open("a", encoding="utf-8") as f_out:
                for mid in ids:
                    if mid in processed_ids or mid in skipped_ids: continue
                    har = message_har_by_id(args.base, args.apikey, mid)
                    if not har:
                        skipped_ids.add(mid); new_skipped += 1; continue

                    # entries 추출
                    try:
                        entries = har["log"]["entries"] if "log" in har else har["entries"]
                    except Exception:
                        skipped_ids.add(mid); new_skipped += 1; continue
                    if not entries:
                        skipped_ids.add(mid); new_skipped += 1; continue

                    # ── NEW: HAR 2차 방어 — 가짜 호스트 스킵 ────────────────────
                    try:
                        req_url = entries[0]["request"]["url"]
                        host = urllib.parse.urlparse(req_url).hostname or ""
                        # 호스트에 '_' 포함 && '.' 없음 → 가짜 호스트로 판단하여 스킵
                        if "_" in host and "." not in host:
                            skipped_ids.add(mid); new_skipped += 1; continue
                    except Exception:
                        pass
                    # ───────────────────────────────────────────────────────────

                    if any(_is_2xx(e) for e in entries):
                        f_out.write(json.dumps(har, ensure_ascii=False) + "\n")
                        processed_ids.add(mid); new_processed += 1
                        try:
                            last_url_har = entries[0]["request"]["url"]
                            if last_url_har:
                                processed_urls.add(last_url_har)
                        except Exception:
                            last_url_har = None
                    else:
                        skipped_ids.add(mid); new_skipped += 1

            done_cnt = len(processed_ids) + len(skipped_ids)

            # Mode transitions
            if not stream_phase:
                if forward_phase and (forward_cursor >= denom_monotonic):
                    if args.scan_mode == "auto":
                        forward_phase = False
                        tail_phase = True
                        print(stamp("[MODE] switched to tail (caught up)"))

            # Denominator AFTER
            denom_after = denom_fetcher.get(force=False)
            denom_fresh = max(denom_monotonic, denom_after)

            # DIAG (throttled)
            now = time.time()
            if args.diag and (now - last_diag_ts >= diag_interval):
                if stream_phase:
                    window = args.stream_batch
                else:
                    window = (args.page_size * (args.pages_per_loop if forward_phase else args.tail_pages))
                mode_hint = f"{mode_label}, cursor={forward_cursor}" if forward_phase else mode_label
                _println(colorize(stamp(f"[DIAG] mode={mode_hint}, fetched={len(ids)}, done={done_cnt}, denom={denom_fresh}"), COLOR.DIM, True))
                last_diag_ts = now

            # Checkpoint
            maybe_save_checkpoint(force=False)

            # Early exit for this scan
            if sp_pct >= 100 and args.exit_when_done_seen and done_cnt >= denom_fresh:
                spider_seg = make_spider_segment(spider_pct=sp_pct, urls_found=urls_found, nodes_added=nodes_added)
                har_seg   = make_har_segment(len(processed_ids), len(skipped_ids), denom_fresh, mode=args.har_format)
                if _isatty() and args.panel == "oneline":
                    _clear_oneline(); sys.stdout.write(stamp(f"{spider_seg} | {har_seg}")[:_term_width()] + "\r"); sys.stdout.flush()
                break

            # Render panel
            spider_seg = make_spider_segment(spider_pct=sp_pct, urls_found=urls_found, nodes_added=nodes_added)
            har_seg   = make_har_segment(len(processed_ids), len(skipped_ids), denom_fresh, mode=args.har_format)

            if args.panel == "oneline":
                _clear_oneline(); sys.stdout.write(stamp(f"{spider_seg} | {har_seg}")[:_term_width()] + "\r"); sys.stdout.flush()
            elif args.panel in ("twoline","live"):
                if last_url_har: _println(colorize(stamp(f"[HAR+] {last_url_har}"), COLOR.WHITE, color_on))
                _println(colorize(stamp(f"{spider_seg} | {har_seg}"), COLOR.CYAN, color_on))
            elif args.panel == "scroll":
                if last_url_har: print(colorize(stamp(f"[HAR+] {last_url_har}"), COLOR.WHITE, color_on))
                print(colorize(stamp(f"{spider_seg} | {har_seg}"), COLOR.CYAN, color_on))

            last_seen_total = denom_fresh
            # Stream 모드에서 아직 새 항목이 없으면(=빈 페이지) 살짝 쉼
            if stream_phase and not ids:
                time.sleep(max(0.25, float(args.refresh_sec)))
            else:
                time.sleep(float(args.refresh_sec))

        return new_processed, new_skipped, scan_id

    # ── Session init / common setup ───────────────────────────────────────────

    def init_session_and_common():
        # 새 세션
        if args.new_session:
            ok = new_session(args.base, args.apikey, name=args.session_name, overwrite=True)
            print(colorize(stamp(f"[SESSION] new session {'created' if ok else 'failed'}: {args.session_name}"), COLOR.DIM if ok else COLOR.YELLOW, color_on))

        # 기존 스파이더 스캔 제거
        scans = spider_scans(args.base, args.apikey)
        if scans:
            spider_stop_all(args.base, args.apikey); spider_remove_all(args.base, args.apikey)
            print(colorize(stamp(f"[SPIDER] previous scans cleared: {len(scans)}"), COLOR.DIM, color_on))
        else:
            print(colorize(stamp("[SPIDER] no previous scans"), COLOR.DIM, color_on))

        # 패시브 스캐너 큐 비움
        if args.pscan_clear_on_start:
            pscan_clear_queue(args.base, args.apikey)
            remain = pscan_records_to_scan(args.base, args.apikey)
            print(colorize(stamp(f"[PSCAN] queue cleared, remain={remain}"), COLOR.DIM, color_on))

        # 스코프/옵션 출력
        print(colorize(stamp(f"[SCOPE] url={args.target}, recurse={not args.no_recurse}, subtreeOnly={args.subtree_only}"), COLOR.CYAN, color_on))
        print(colorize(stamp(f"[SPIDER OPTIONS] MaxDepth=0, ThreadCount=16, MaxDuration=0, MaxChildren={args.max_children}, SendRefererHeader=true"), COLOR.CYAN, color_on))

        # ── NEW: 스파이더 exclude regex 자동 등록 ────────────────────────────
        if args.auto_exclude_bad_hosts:
            # (1) 호스트에 '_' 포함 + '.' 없는 형태 전부 제외
            spider_add_exclude_regex(args.base, args.apikey, r"^https?://[^/]*_[^./]*(?:/|$)")
            # (2) 선택: 특정 접두어(pc|mo|tab|m)_ 로 시작하는 변종(주석 해제 시 사용)
            # spider_add_exclude_regex(args.base, args.apikey, r"^https?://(?:pc|mo|tab|m)_[^./]*(?:/|$)")
        # 추가 정규식 사용자 지정
        for rx in (args.extra_exclude_regex or []):
            spider_add_exclude_regex(args.base, args.apikey, rx)
        # ──────────────────────────────────────────────────────────────────────

    # ── Resolve history baseurl & ids_mode ────────────────────────────────────

    def resolve_filter_baseurl() -> Optional[str]:
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
        return filter_base

    def resolve_ids_mode() -> str:
        ids_mode = args.ids_mode
        if ids_mode == "auto":
            if supports_messages_ids(args.base, args.apikey):
                ids_mode = "ids"; print(colorize(stamp("[CAPS] messagesIds view: supported → using ids mode"), COLOR.DIM, color_on))
            else:
                ids_mode = "messages"; print(colorize(stamp("[CAPS] messagesIds view: unsupported → using messages mode"), COLOR.YELLOW, color_on))
        else:
            print(colorize(stamp(f"[CAPS] ids_mode={ids_mode}"), COLOR.DIM, color_on))
        return ids_mode

    # ── Main execution flow ───────────────────────────────────────────────────

    init_session_and_common()
    filter_base = resolve_filter_baseurl()
    ids_mode = resolve_ids_mode()
    denom_fetcher = DenomFetcher(args.base, args.apikey, filter_base, refresh_sec=args.denom_refresh_sec)

    # reseed 준비
    seed_queue: deque[str] = deque()
    if args.reseed_from_checkpoint and args.checkpoint_file:
        seed_queue.extend(load_seeds_from_checkpoint())
    if args.seed_file:
        seed_queue.extend(load_seeds_from_file())

    processed_ids: Set[int] = set()
    skipped_ids: Set[int] = set()

    if seed_queue:
        print(colorize(stamp(f"[RESEED] starting with {len(seed_queue)} seed(s)"), COLOR.CYAN, color_on))
        while seed_queue:
            seed = seed_queue.popleft()
            _ = run_one_scan(seed, processed_ids, skipped_ids, ndjson_path, filter_base, ids_mode, denom_fetcher, forward_mode_first=True)
            maybe_save_checkpoint(force=True)

    # main target
    _ = run_one_scan(args.target, processed_ids, skipped_ids, ndjson_path, filter_base, ids_mode, denom_fetcher, forward_mode_first=True)

    # Optional: session rolling by denom threshold
    if args.roll_denom_threshold and args.roll_denom_threshold > 0:
        try:
            current_seen = denom_fetcher.get(force=True)
        except Exception:
            current_seen = 0
        last_roll_ts = time.time()
        if current_seen >= args.roll_denom_threshold:
            maybe_save_checkpoint(force=True)
            target_host = urllib.parse.urlparse(args.target).hostname or ""
            outstanding = list(discovered_urls - processed_urls)
            seeds = filter_seeds(outstanding, target_host, args.reseed_same_host_only)
            if args.reseed_limit > 0:
                seeds = seeds[:args.reseed_limit]
            print(colorize(stamp(f"[ROLL] threshold hit (seen={current_seen} ≥ {args.roll_denom_threshold}), restarting session; seeds={len(seeds)}"), COLOR.YELLOW, color_on))

            args.new_session = True
            init_session_and_common()
            filter_base = resolve_filter_baseurl()
            ids_mode = resolve_ids_mode()
            denom_fetcher = DenomFetcher(args.base, args.apikey, filter_base, refresh_sec=args.denom_refresh_sec)

            for s in seeds:
                _ = run_one_scan(s, processed_ids, skipped_ids, ndjson_path, filter_base, ids_mode, denom_fetcher, forward_mode_first=True)
                maybe_save_checkpoint(force=True)

            _ = run_one_scan(args.target, processed_ids, skipped_ids, ndjson_path, filter_base, ids_mode, denom_fetcher, forward_mode_first=True)

    finalize_har(ndjson_path, Path(args.out), meta={"target": args.target, "filterBase": filter_base})
    print(colorize(stamp(f"[DONE] HAR saved → {args.out}  (entries: {len(processed_ids)}, skipped: {len(skipped_ids)})"), COLOR.GREEN, True))

if __name__ == "__main__":
    main()
