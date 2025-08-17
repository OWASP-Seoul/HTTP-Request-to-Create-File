#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZAP Spider incremental HAR — twoline UI (default) + fast refresh + pre-clear pscan queue (default ON)

패널 모드
- twoline(기본): 2줄 고정 패널
  1) [HAR+] id=... status url
  2) [SPIDER] ..% | [HAR] processed/total (%) | eps | ETA
- oneline : ZIP 스타일(\r) 한 줄 갱신
- live    : 2~3줄 패널(ANSI 커서 이동)
- scroll  : 진행률 1줄 고정 + HAR 이벤트는 스크롤 출력

신규/중요 옵션
- --refresh-sec <float>         : UI 갱신/폴링 주기(초), 기본 0.25
- --tail-pages <int>            : 최근 N 페이지만 가져와 HAR 폴링(기본 1)
- --fetch-only-on-growth        : numberOfMessages 증가시에만 HAR 요청
- --eps-window-sec <float>      : EPS 계산 윈도(초), 기본 10.0 (작을수록 반응성↑)
- (기본 ON) 시작 시 패시브 스캔 큐 삭제: --no-pscan-clear-on-start 로 끌 수 있음

기능
- 증분 HAR 저장(NDJSON) + 최종 HAR 마감
- 히스토리 필터 자동 선택(--history-filter auto/target/host/none) 또는 직접 지정(--filter-baseurl)
- Scope(Starting Point/Context/User/Recurse/SubtreeOnly/MaxChildren) 적용
- Import/Export 애드온 우선 활용 → 미설치 시 core/other/messageHar로 폴백
- 실패 재시도→skip, 분모(monotonic), idle-exit, 색상 출력
- 시작 시 [SCOPE], [SPIDER OPTIONS], [HISTORY], [SPIDER] scanId 로깅
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

def should_use_color(mode: str) -> bool:
    if mode == "always": return True
    if mode == "never": return False
    return sys.stdout.isatty()

def colorize(text: str, color: str, enabled: bool) -> str:
    if not enabled or isinstance(COLOR, _NoColor):
        return text
    return f"{color}{text}{COLOR.RESET}"

def pct_color(p: float) -> str:
    if p < 50: return COLOR.RED
    if p < 90: return COLOR.YELLOW
    return COLOR.GREEN

# ── Console helpers (live/scroll) ────────────────────────────────────────────
_PANEL_LINES_SHOWN = 0
_PANEL_LAST_CONTENT = []

def _clear_line():
    sys.stdout.write("\033[2K")

def _render_panel(lines):
    """Redraw panel in-place (N lines)."""
    global _PANEL_LINES_SHOWN, _PANEL_LAST_CONTENT
    n_prev = _PANEL_LINES_SHOWN
    n_new = len(lines)
    if n_prev > 0:
        sys.stdout.write(f"\033[{n_prev}F")
    for i in range(n_new):
        _clear_line()
        sys.stdout.write("\r" + lines[i] + "\n")
    if n_new < n_prev:
        for _ in range(n_prev - n_new):
            _clear_line(); sys.stdout.write("\r\n")
        sys.stdout.write(f"\033[{(n_prev - n_new)}F")
    sys.stdout.flush()
    _PANEL_LINES_SHOWN = n_new
    _PANEL_LAST_CONTENT = list(lines)

def _repaint_panel():
    if _PANEL_LINES_SHOWN > 0:
        _render_panel(_PANEL_LAST_CONTENT)

def print_above_panel(msg: str):
    if _PANEL_LINES_SHOWN > 0:
        sys.stdout.write(f"\033[{_PANEL_LINES_SHOWN}F"); sys.stdout.write("\r")
    _clear_line(); print(msg); _repaint_panel()

# ── One-line UI (\r only) ───────────────────────────────────────────────────
_ONELINE_PREV_LEN = 0

def _term_width(default=120) -> int:
    try:
        return shutil.get_terminal_size((default, 20)).columns
    except Exception:
        return default

def _print_oneline(s: str):
    global _ONELINE_PREV_LEN
    sys.stdout.write("\r" + s)
    pad = max(0, _ONELINE_PREV_LEN - len(s))
    if pad: sys.stdout.write(" " * pad)
    sys.stdout.flush()
    _ONELINE_PREV_LEN = len(s)

# ── ZAP API helpers ─────────────────────────────────────────────────────────
SESSION = requests.Session()

def zap_get(endpoint, **params):
    r = SESSION.get(endpoint, params=params, timeout=60)
    r.raise_for_status()
    return r

def context_id_by_name(base, apikey, name):
    u = urljoin(base, "/JSON/context/view/context/")
    try:
        r = zap_get(u, apikey=apikey, contextName=name).json()
        ctx = r.get("context") or {}
        cid = ctx.get("id")
        return int(cid) if cid is not None else None
    except Exception:
        return None

def user_id_by_name(base, apikey, context_id, user_name):
    u = urljoin(base, "/JSON/users/view/usersList/")
    try:
        r = zap_get(u, apikey=apikey, contextId=context_id).json()
        users = r.get("usersList") or r.get("users") or []
        for uinfo in users:
            if str(uinfo.get("name","")) == str(user_name):
                uid = uinfo.get("id"); return int(uid) if uid is not None else None
        return None
    except Exception:
        return None

def spider_start(base, apikey, target_url, *,
                 max_children=None, recurse=True,
                 context_name=None, subtree_only=False,
                 context_id=None, user_id=None):
    if user_id is not None:
        if context_id is None and context_name:
            context_id = context_id_by_name(base, apikey, context_name)
        if context_id is None:
            raise RuntimeError("scanAsUser에는 context-id가 필요합니다. (--context-id 또는 --context-name)")
        u = urljoin(base, "/JSON/spider/action/scanAsUser/")
        params = {"contextId": context_id, "userId": user_id}
        if target_url: params["url"] = target_url
        if max_children is not None: params["maxChildren"] = max_children
        params["recurse"] = str(bool(recurse)).lower()
        params["subtreeOnly"] = str(bool(subtree_only)).lower()
        resp = zap_get(u, apikey=apikey, **params).json()
    else:
        u = urljoin(base, "/JSON/spider/action/scan/")
        params = {"url": target_url}
        if max_children is not None: params["maxChildren"] = max_children
        params["recurse"] = str(bool(recurse)).lower()
        if context_name: params["contextName"] = context_name
        params["subtreeOnly"] = str(bool(subtree_only)).lower()
        resp = zap_get(u, apikey=apikey, **params).json()
    if "code" in resp:
        raise RuntimeError(f"Spider start failed: {resp}")
    scan_id = resp.get("scan")
    if scan_id is None or str(scan_id).strip() == "":
        raise RuntimeError(f"Spider did not return scan id: {resp}")
    return scan_id

def spider_status(base, apikey, scan_id):
    u = urljoin(base, "/JSON/spider/view/status/")
    return int(zap_get(u, apikey=apikey, scanId=scan_id).json().get("status", "0"))

def number_of_messages(base, apikey, baseurl=None):
    u = urljoin(base, "/JSON/core/view/numberOfMessages/")
    params = {"apikey": apikey}
    if baseurl: params["baseurl"] = baseurl
    return int(zap_get(u, **params).json().get("numberOfMessages", "0"))

def list_messages(base, apikey, start, count, baseurl=None):
    u = urljoin(base, "/JSON/core/view/messages/")
    params = {"apikey": apikey, "start": start, "count": count}
    if baseurl: params["baseurl"] = baseurl
    return zap_get(u, **params).json().get("messages", [])

def har_entry_by_id(base, apikey, mid):
    # Prefer Import/Export add-on
    u1 = urljoin(base, "/OTHER/importexport/other/exportHarById/")
    try:
        r = SESSION.get(u1, params={"ids": str(mid), "apikey": apikey}, timeout=60)
        if r.status_code == 200 and "json" in r.headers.get("content-type", ""):
            har = r.json()
            entries = har.get("log", {}).get("entries", [])
            if entries: return entries[0]
    except Exception:
        pass
    # Fallback to core
    u2 = urljoin(base, "/OTHER/core/other/messageHar/")
    r = SESSION.get(u2, params={"id": str(mid), "apikey": apikey}, timeout=60)
    r.raise_for_status()
    har = r.json()
    entries = har.get("log", {}).get("entries", [])
    return entries[0] if entries else None

# ── Passive scan helpers ─────────────────────────────────────────────────────
def pscan_records_to_scan(base, apikey):
    u = urljoin(base, "/JSON/pscan/view/recordsToScan/")
    try:
        return int(zap_get(u, apikey=apikey).json().get("recordsToScan", "0"))
    except Exception:
        return 0

def pscan_clear_queue(base, apikey):
    u = urljoin(base, "/JSON/pscan/action/clearQueue/")
    try:
        zap_get(u, apikey=apikey)
        return True
    except Exception:
        return False

# ── Spider options (robust keys) ────────────────────────────────────────────
def get_spider_options(base, apikey):
    keys = [
        "optionMaxDepth","optionThreadCount","optionMaxDuration",
        "optionMaxChildren","optionMaxParseSizeBytes",
        "optionParseRobotsTxt","optionParseSitemapXml",
        "optionHandleParameters","optionPostForm","optionProcessForm",
        "optionSendRefererHeader","optionUserAgent"
    ]
    out = {}
    for k in keys:
        u = urljoin(base, f"/JSON/spider/view/{k}/")
        try:
            d = zap_get(u, apikey=apikey).json()
            out[k] = d.get(k, next(iter(d.values())))
        except Exception:
            out[k] = None
    return out

# ── HAR helpers ─────────────────────────────────────────────────────────────
def write_ndjson(path, obj):
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False)); f.write("\n")

def finalize_har(ndjson_path, out_har_path, meta=None):
    meta = meta or {}
    entries = []
    if os.path.exists(ndjson_path):
        with open(ndjson_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line: entries.append(json.loads(line))
    har = {"log": {"version": "1.2","creator": meta.get("creator", {"name": "ZAP"}),
                   "browser": meta.get("browser", {}),"pages": meta.get("pages", []),
                   "entries": entries}}
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
    """[HAR] ... | eps | ETA ... | [SPIDER] ...  (live/scroll 용 기본 포맷)"""
    done_cnt = processed_cnt + skipped_cnt
    har_pct = 0.0 if denom <= 0 else (done_cnt / max(1, denom) * 100.0)
    counter_txt = f"{processed_cnt}/{denom}" if skipped_cnt == 0 else f"{processed_cnt}+{skipped_cnt}/{denom}"
    pieces = [f"[HAR] {counter_txt} ({har_pct:5.1f}%)"]
    if eps is not None: pieces.append(f"{eps:.1f} eps")
    if eta_s is not None: pieces.append(f"ETA {format_eta(eta_s)}")
    pieces.append(f"[SPIDER] {spider_pct:3d}%")
    return " | ".join(pieces)

def make_progress_text_spider_first(processed_cnt, skipped_cnt, denom, eps, eta_s, spider_pct):
    """[SPIDER] ... | [HAR] ... | eps | ETA ... (oneline/twoline 용)"""
    done_cnt = processed_cnt + skipped_cnt
    har_pct = 0.0 if denom <= 0 else (done_cnt / max(1, denom) * 100.0)
    counter_txt = f"{processed_cnt}/{denom}" if skipped_cnt == 0 else f"{processed_cnt}+{skipped_cnt}/{denom}"
    pieces = [f"[SPIDER] {sp_pct:3d}%"]
    pieces.append(f"[HAR] {counter_txt} ({har_pct:5.1f}%)")
    if eps is not None: pieces.append(f"{eps:.1f} eps")
    if eta_s is not None: pieces.append(f"ETA {format_eta(eta_s)}")
    return " | ".join(pieces)

def make_har_segment(processed_cnt, skipped_cnt, denom, eps, eta_s):
    """[HAR] ... | eps | ETA ... (SPIDER 제외 세그먼트)"""
    done_cnt = processed_cnt + skipped_cnt
    har_pct = 0.0 if denom <= 0 else (done_cnt / max(1, denom) * 100.0)
    counter_txt = f"{processed_cnt}/{denom}" if skipped_cnt == 0 else f"{processed_cnt}+{skipped_cnt}/{denom}"
    pieces = [f"[HAR] {counter_txt} ({har_pct:5.1f}%)"]
    if eps is not None: pieces.append(f"{eps:.1f} eps")
    if eta_s is not None: pieces.append(f"ETA {format_eta(eta_s)}")
    return " | ".join(pieces)

def status_color(status):
    try:
        s = int(status)
    except Exception:
        return COLOR.DIM
    if 200 <= s < 300: return COLOR.GREEN
    if 300 <= s < 400: return COLOR.CYAN
    if 400 <= s < 500: return COLOR.YELLOW
    if 500 <= s < 600: return COLOR.RED
    return COLOR.DIM

def format_harplus_compact(mid, status, url, color_on, width, rhs_len):
    """두 줄 패널의 1줄용 ‘[HAR+] …’ (URL은 tail-ellipsis)"""
    left_prefix = "[HAR+] "
    id_part = f"id={mid} {status} "
    base = left_prefix + id_part
    GAP = 3
    max_left = max(20, width - rhs_len - GAP)
    url_room = max_left - len(base)
    if url_room <= 0:
        url_disp = ""
    else:
        if len(url) <= url_room:
            url_disp = url
        else:
            url_disp = "…" + url[-(url_room-1):]
    left_txt = left_prefix + colorize(f"id={mid}", COLOR.DIM, color_on) + " "
    left_txt += colorize(str(status), status_color(status), color_on) + " " + url_disp
    return left_txt

# ── History filter selector ──────────────────────────────────────────────────
def pick_history_filter(base, apikey, target, mode):
    def count_for(bu):
        try:
            return number_of_messages(base, apikey, bu)
        except Exception:
            return -1
    if mode == "none":
        return None, count_for(None)
    if mode == "target":
        c1 = count_for(target); c2 = count_for(target.rstrip("/"))
        return (target if c1 >= c2 else target.rstrip("/")), max(c1, c2)
    host = urlparse(target).netloc
    https_root = f"https://{host}/"; http_root  = f"http://{host}/"
    if mode == "host":
        c1, c2 = count_for(https_root), count_for(http_root)
        return (https_root if c1 >= c2 else http_root), max(c1, c2)
    candidates = [target, target.rstrip("/"), https_root, http_root]
    best = None; bestc = -1
    for bu in candidates:
        c = count_for(bu)
        if c > bestc: best, bestc = bu, c
    if bestc <= 0:
        return None, count_for(None)
    return best, bestc

# ── Main ────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8090", help="ZAP API base URL")
    ap.add_argument("--apikey", required=True)
    ap.add_argument("--target", required=True, help="Starting Point URL")
    ap.add_argument("--out", default=None, help="Output HAR path (default: <domain>.har)")
    ap.add_argument("--page-size", type=int, default=200, help="Fetch page size for message list")
    ap.add_argument("--pscan-wait", action="store_true", help="Wait until passive scanner queue drains")
    # 기본 ON, 끄고 싶으면 --no-pscan-clear-on-start
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--pscan-clear-on-start", dest="pscan_clear_on_start",
                       action="store_true", help="Clear passive scan queue at start (default: ON)")
    group.add_argument("--no-pscan-clear-on-start", dest="pscan_clear_on_start",
                       action="store_false", help="Do NOT clear passive scan queue at start")
    ap.set_defaults(pscan_clear_on_start=True)

    ap.add_argument("--filter-baseurl", default=None, help="History filter baseurl (override)")
    ap.add_argument("--history-filter", choices=["auto","target","host","none"], default="auto",
                    help="Strategy to pick history baseurl when --filter-baseurl not set")
    ap.add_argument("--panel", choices=["twoline","oneline","live","scroll"], default="twoline",
                    help="twoline(default): 2-line panel; oneline: \\r only; live: multi-line; scroll: classic")
    ap.add_argument("--color", choices=["auto","always","never"], default="auto")
    ap.add_argument("--max-retries", type=int, default=3)
    ap.add_argument("--idle-exit-sec", type=int, default=30)
    # 빠른 갱신 옵션
    ap.add_argument("--refresh-sec", type=float, default=0.25,
                    help="UI refresh / polling interval seconds")
    ap.add_argument("--tail-pages", type=int, default=1,
                    help="How many recent pages to fetch for HAR polling (default: 1)")
    ap.add_argument("--fetch-only-on-growth", action="store_true",
                    help="Only fetch HAR when numberOfMessages increases")
    ap.add_argument("--eps-window-sec", type=float, default=10.0,
                    help="Time window (sec) for EPS calculation (smaller = more reactive)")
    # Scope / scan params
    ap.add_argument("--context-name", default=None)
    ap.add_argument("--context-id", type=int, default=None)
    ap.add_argument("--user-id", type=int, default=None)
    ap.add_argument("--user-name", default=None)
    ap.add_argument("--max-children", type=int, default=None)
    ap.add_argument("--subtree-only", action="store_true")
    ap.add_argument("--no-recurse", action="store_true")
    args = ap.parse_args()

    color_on = should_use_color(args.color)
    if args.out is None:
        args.out = default_out_from_target(args.target)

    # History filter
    if args.filter_baseurl is not None:
        filter_base = args.filter_baseurl or None
        try:
            hist_count = number_of_messages(args.base, args.apikey, filter_base)
        except Exception:
            hist_count = -1
    else:
        filter_base, hist_count = pick_history_filter(args.base, args.apikey, args.target, args.history_filter)

    # Prepare NDJSON
    tmp_dir = os.path.dirname(os.path.abspath(args.out)) or "."
    ndjson_path = os.path.join(tmp_dir, ".entries.ndjson")
    if os.path.exists(ndjson_path): os.remove(ndjson_path)

    # Resolve context/user
    ctx_id = args.context_id
    if ctx_id is None and args.context_name:
        ctx_id = context_id_by_name(args.base, args.apikey, args.context_name)
        if args.context_name and ctx_id is None:
            print(colorize(f"[WARN] Context '{args.context_name}' not found. Ignoring contextName.", COLOR.YELLOW, color_on))
    usr_id = args.user_id
    if usr_id is None and args.user_name and ctx_id is not None:
        maybe_uid = user_id_by_name(args.base, args.apikey, ctx_id, args.user_name)
        if maybe_uid is None:
            print(colorize(f"[WARN] User '{args.user_name}' not found in context {ctx_id}. Ignoring user.", COLOR.YELLOW, color_on))
        else:
            usr_id = maybe_uid

    recurse = not args.no_recurse

    # Show scope/options/history
    scope_bits = [f"url={args.target}"]
    if args.context_name: scope_bits.append(f"contextName={args.context_name}")
    if ctx_id is not None: scope_bits.append(f"contextId={ctx_id}")
    if usr_id is not None: scope_bits.append(f"userId={usr_id}")
    if args.max_children is not None: scope_bits.append(f"maxChildren={args.max_children}")
    scope_bits += [f"recurse={str(recurse).lower()}", f"subtreeOnly={str(bool(args.subtree_only)).lower()}"]
    print(colorize("[SCOPE] " + ", ".join(scope_bits), COLOR.BOLD, color_on))

    opts = get_spider_options(args.base, args.apikey)
    optline = (f"maxDepth={opts.get('optionMaxDepth')}, "
               f"threads={opts.get('optionThreadCount')}, "
               f"maxDuration(min)={opts.get('optionMaxDuration')}, "
               f"maxChildren={opts.get('optionMaxChildren')}, "
               f"robots={opts.get('optionParseRobotsTxt')}, "
               f"sitemap={opts.get('optionParseSitemapXml')}, "
               f"userAgent={opts.get('optionUserAgent')}")
    print(colorize("[SPIDER OPTIONS] " + optline, COLOR.DIM, color_on))
    print(colorize(f"[HISTORY] filter={filter_base or 'None'} (messages now={hist_count})", COLOR.DIM, color_on))

    # ★ 시작 시 패시브 스캔 큐 정리 (기본 ON)
    if args.pscan_clear_on_start:
        pre = pscan_records_to_scan(args.base, args.apikey)
        if pre > 0:
            print(colorize(f"[PSCAN] pre-existing queue: {pre} → clearing...", COLOR.YELLOW, color_on))
            ok = pscan_clear_queue(args.base, args.apikey)
            if ok:
                # 최대 5초 동안 0 될 때까지 확인
                t_end = time.time() + 5.0
                left = pre
                while time.time() < t_end:
                    left = pscan_records_to_scan(args.base, args.apikey)
                    if left == 0:
                        break
                    time.sleep(0.1)
                if left == 0:
                    print(colorize("[PSCAN] queue cleared.", COLOR.GREEN, color_on))
                else:
                    print(colorize(f"[PSCAN] clear requested, but {left} remain (will drain in background).", COLOR.YELLOW, color_on))
            else:
                print(colorize("[PSCAN] clearQueue failed (API error).", COLOR.RED, color_on))
        else:
            print(colorize("[PSCAN] queue empty on start.", COLOR.DIM, color_on))

    # Start spider
    scan_id = spider_start(
        args.base, args.apikey, args.target,
        max_children=args.max_children,
        recurse=recurse,
        context_name=args.context_name,
        subtree_only=args.subtree_only,
        context_id=ctx_id,
        user_id=usr_id
    )
    print(colorize(f"[SPIDER] scanId={scan_id}", COLOR.DIM, color_on))

    processed_ids, skipped_ids, attempts = set(), set(), {}
    seen_total_monotonic = 0
    header_meta = {"creator": {"name": "ZAP"}}
    recent = deque(maxlen=300)  # 시간 윈도우로 관리하므로 큐 길이는 넉넉히
    t0 = time.time(); recent.append((t0, 0))
    last_done_count = 0
    last_progress_ts = t0

    # 빠른 폴링 제어
    last_total_for_fetch = 0

    # 최근 HAR 이벤트
    last_mid, last_status, last_url = None, None, None

    try:
        while True:
            # Spider %
            try:
                sp_pct = spider_status(args.base, args.apikey, scan_id)
            except Exception:
                sp_pct = 0

            # Message counts
            try:
                total_now = number_of_messages(args.base, args.apikey, filter_base)
            except Exception:
                total_now = seen_total_monotonic
            if total_now > seen_total_monotonic:
                seen_total_monotonic = total_now

            processed_cnt = len(processed_ids)
            skipped_cnt = len(skipped_ids)
            done_cnt = processed_cnt + skipped_cnt

            # EPS/ETA (윈도우 기반)
            now = time.time()
            recent.append((now, processed_cnt))
            while len(recent) >= 2 and (now - recent[0][0]) > float(args.eps_window_sec):
                recent.popleft()

            eps = eta_s = None
            if len(recent) >= 2:
                t_old, c_old = recent[0]
                dt = max(1e-6, now - t_old)
                dc = processed_cnt - c_old
                eps = dc / dt if dc >= 0 else 0.0
                remaining = max(0, seen_total_monotonic - done_cnt)
                if eps and eps > 0:
                    eta_s = remaining / eps

            # === Panel rendering =================================================
            if args.panel == "oneline":
                prog_spider_first = make_progress_text_spider_first(
                    processed_cnt, skipped_cnt, seen_total_monotonic, eps, eta_s, sp_pct
                )
                width = _term_width()
                rhs_len = len(prog_spider_first) + 3
                if last_mid is None:
                    left_txt = "[HAR+] (waiting for first HAR...)"
                else:
                    left_txt = format_harplus_compact(last_mid, last_status, last_url, color_on, width, rhs_len)
                _print_oneline(f"{left_txt}   |   {prog_spider_first}")

            elif args.panel == "twoline":
                width = _term_width()
                if last_mid is None:
                    har_plus_line = colorize("[HAR+] (waiting for first HAR...)", COLOR.DIM, color_on)
                else:
                    har_plus_line = format_harplus_compact(last_mid, last_status, last_url, color_on, width, 0)

                har_seg = make_har_segment(processed_cnt, skipped_cnt, seen_total_monotonic, eps, eta_s)
                prog_line = (
                    colorize(f"[SPIDER] {sp_pct:3d}%", pct_color(float(sp_pct)), color_on)
                    + colorize(" | ", COLOR.DIM, color_on)
                    + colorize(har_seg, COLOR.WHITE, color_on)
                )
                _render_panel([har_plus_line, prog_line])

            elif args.panel == "live":
                width = _term_width()
                if last_mid is None:
                    har_plus_line = colorize("[HAR+] (waiting for first HAR...)", COLOR.DIM, color_on)
                else:
                    har_plus_line = format_harplus_compact(last_mid, last_status, last_url, color_on, width, 0)
                har_seg = make_har_segment(processed_cnt, skipped_cnt, seen_total_monotonic, eps, eta_s)
                prog_line = (
                    colorize(f"[SPIDER] {sp_pct:3d}%", pct_color(float(sp_pct)), color_on)
                    + colorize(" | ", COLOR.DIM, color_on)
                    + colorize(har_seg, COLOR.WHITE, color_on)
                )
                _render_panel([har_plus_line, prog_line])

            else:  # scroll
                progress_plain = make_progress_text(processed_cnt, skipped_cnt, seen_total_monotonic, eps, eta_s, sp_pct)
                _render_panel([progress_plain])

            # New messages -> fetch + write HAR
            do_fetch = (total_now > 0)
            if args.fetch_only_on_growth:
                do_fetch = do_fetch and (total_now > last_total_for_fetch)

            if do_fetch:
                page_size = max(50, int(args.page_size))
                tail_pages = max(1, int(args.tail_pages))
                fetch_from = max(0, total_now - (page_size * tail_pages))
                for chunk_start in range(fetch_from, total_now, page_size):
                    msgs = list_messages(args.base, args.apikey, start=chunk_start, count=page_size, baseurl=filter_base)
                    for m in msgs:
                        mid = m.get("id")
                        if mid is None or mid in processed_ids or mid in skipped_ids:
                            continue
                        try:
                            entry = har_entry_by_id(args.base, args.apikey, mid)
                            if entry:
                                write_ndjson(ndjson_path, entry)
                                processed_ids.add(mid)
                                last_progress_ts = time.time()
                                last_mid = mid
                                last_status = entry.get("response", {}).get("status", "")
                                last_url = entry.get("request", {}).get("url", "")
                                if args.panel == "scroll":
                                    print_above_panel(colorize("[HAR+]", COLOR.GREEN, color_on) + f" id={mid} {last_status} {last_url}")
                            else:
                                attempts[mid] = attempts.get(mid, 0) + 1
                                if attempts[mid] >= args.max_retries:
                                    skipped_ids.add(mid)
                                    if args.panel == "scroll":
                                        print_above_panel(colorize("[SKIP]", COLOR.YELLOW, color_on) + f" id={mid} (no HAR after {attempts[mid]} tries)")
                        except Exception as e:
                            attempts[mid] = attempts.get(mid, 0) + 1
                            if attempts[mid] >= args.max_retries:
                                skipped_ids.add(mid)
                                if args.panel == "scroll":
                                    print_above_panel(colorize("[SKIP]", COLOR.YELLOW, color_on) + f" id={mid} ({e}) after {attempts[mid]} tries")
                            else:
                                if args.panel != "oneline":
                                    print_above_panel(colorize(f"[WARN] HAR by id failed ({mid}, try {attempts[mid]}/{args.max_retries}): {e}", COLOR.YELLOW, color_on))
                # 이번 루프의 총 메시지 수 기록 (증가 감지용)
                last_total_for_fetch = total_now

            # Idle-exit after spider 100%
            if done_cnt != last_done_count:
                last_done_count = done_cnt; last_progress_ts = time.time()
            else:
                if sp_pct >= 100 and (time.time() - last_progress_ts) >= float(args.idle_exit_sec):
                    if args.panel != "oneline":
                        print_above_panel(colorize(f"[INFO] No progress for {args.idle_exit_sec}s with SPIDER=100%. Exiting.", COLOR.DIM, color_on))
                    break

            # Normal exit condition
            if sp_pct >= 100 and done_cnt >= seen_total_monotonic:
                break

            time.sleep(max(0.02, float(args.refresh_sec)))

        # Optional: passive scan drain
        if args.pscan_wait:
            u = urljoin(args.base, "/JSON/pscan/view/recordsToScan/")
            while True:
                try:
                    left = int(zap_get(u, apikey=args.apikey).json().get("recordsToScan", "0"))
                except Exception:
                    left = 0
                msg = f"[PSCAN] remaining: {left}"
                if args.panel == "oneline":
                    _print_oneline(msg)
                elif args.panel in ("twoline","live"):
                    # 3줄로 확장 표시
                    width = _term_width()
                    if last_mid is None:
                        har_plus_line = colorize("[HAR+] (waiting for first HAR...)", COLOR.DIM, color_on)
                    else:
                        har_plus_line = format_harplus_compact(last_mid, last_status, last_url, color_on, width, 0)
                    har_seg = make_har_segment(processed_cnt, skipped_cnt, seen_total_monotonic, eps, eta_s)
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
        finalize_har(ndjson_path, args.out, meta=header_meta)
        # twoline/live: 패널 유지, 그 아래에 DONE 출력
        if args.panel in ("twoline","live"):
            sys.stdout.write("\n")
            print(colorize(
                f"[DONE] HAR saved → {args.out}  (entries: {len(processed_ids)}, skipped: {len(skipped_ids)})",
                COLOR.GREEN, color_on
            ))
        elif args.panel == "oneline":
            _print_oneline(colorize(
                f"[DONE] HAR saved → {args.out}  (entries: {len(processed_ids)}, skipped: {len(skipped_ids)})",
                COLOR.GREEN, color_on
            ))
            sys.stdout.write("\n"); sys.stdout.flush()
        else:  # scroll
            _render_panel([])
            print(colorize(
                f"[DONE] HAR saved → {args.out}  (entries: {len(processed_ids)}, skipped: {len(skipped_ids)})",
                COLOR.GREEN, color_on
            ))

if __name__ == "__main__":
    main()
