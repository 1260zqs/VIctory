"""
ida_bridge.py — HTTP bridge for driving IDA Pro from an external agent.

Tested on IDA 7.7.220118 (IDAPython 3 / Python 3.8) and on IDA 8.3.

HOW TO USE
  As a plugin (no Alt+F7, recommended): the payload lives in IDA's plugins folder,
  self-contained, with no absolute source path anywhere:

      <IDA>/plugins/ida_bridge_plugin.py      loader, imported by IDA
      <IDA>/plugins/ida_bridge/ida_bridge.py  this implementation

  PLUGIN_PROC starts the bridge whenever a database opens and term() stops it when
  the database closes; Edit -> Plugins -> IDA Bridge (Ctrl-Shift-B) prints the
  current URL. After editing this file, copy it into <IDA>/plugins/ida_bridge/ and
  restart IDA — the loader logs the payload path and timestamp it actually used.

  As a script (one-shot):
  1. Open the target in IDA (let auto-analysis finish).
  2. File -> Script file...  -> select this file.   (or Alt+F7)
  3. The Output window prints:  [ida_bridge] listening on http://127.0.0.1:<port>
     <port> is the first free port at or above 13337, so it is normally 13337 but
     moves up if that one is taken. /whoami and /status both report it.
  4. Leave IDA open. Re-run the script any time to restart (it stops the old one).

ENDPOINTS (all GET unless noted)
  /whoami                          this instance's port + pid (no IDA API touched)
  /status                          port, pid, executable path, imagebase, counts
  /func?ea=0x...                   function record for the containing function
  /decompile?ea=0x...              Hex-Rays pseudocode
  /disasm?ea=0x...&n=40            disassembly lines: "addr  bytes  text"
  /xrefs?ea=0x...&dir=to|from      all cross references
  /callers?ea=0x...                direct callers
  /callees?ea=0x...                direct callees (call xrefs only)
  /names?like=substr&limit=50      symbol search
  /bytes?ea=0x...&n=64             hex bytes
  /cstr?ea=0x...                   C string at address
  /segments                        segment map
  /search?pat=DEADBEEF&limit=16    binary pattern search (per segment)
  /log?limit=50                    recent request log, oldest first
  /shutdown                        stop the bridge
  POST /exec                       body = python, run with the ida api in scope

Debugger (needs a live session — Debugger -> Start/Attach in the GUI, or /dbg/start)
  /dbg                             session state, threads, breakpoint count
  /dbg/options                     Debugger -> Process options
  /dbg/regs?tid=                   every register of one thread
  /dbg/reg?name=eax                one register
  /dbg/mem?ea=0x...&n=64           read debuggee memory
  /dbg/bpts                        breakpoint list
  /dbg/stack?tid=                  call stack
  POST /dbg/start?path=&args=&sdir=   launch (off by default: ALLOW_DBG_LAUNCH)
  POST /dbg/attach?pid=            attach (off by default: ALLOW_DBG_LAUNCH)
  POST /dbg/continue | /dbg/suspend
  POST /dbg/step?kind=into|over|out
  POST /dbg/runto?ea=0x...
  POST /dbg/wait?timeout_ms=3000   block until the target stops (capped by DBG_WAIT_MAX)
  POST /dbg/bpt/add?ea=&type=&size=   type: exec|read|write|rw|soft
  POST /dbg/bpt/del?ea= | /dbg/bpt/enable?ea=&on=0|1
  POST /dbg/reg/set?name=&value= | /dbg/write?ea=&hex=
  POST /dbg/thread?tid=            select the current thread
  POST /dbg/exit | /dbg/detach

NOTES
  * Every handler runs on IDA's main thread via idaapi.execute_sync() — except
    /ping, /whoami and /log, which stay off it so a client can find the instance
    without waiting for a busy UI.
  * Only listens on 127.0.0.1. Nothing is sent off the machine.
  * The port is not fixed: PORT is only the first candidate, the server walks
    upwards until it finds a free one, and reports the real port in /whoami,
    /status and the startup line.
  * Debugger control uses IDA's synchronous debugger API, so /dbg/start and
    /dbg/step return once the target has stopped (just like the GUI buttons) —
    that is what makes "step, then read registers" work without polling.
  * Every request is logged to the Output window, e.g.
        [ida_bridge] GET /func?ea=0x20c0 -> 200  0.9 ms  214 B
    Set LOG_REQUESTS = False to silence it; the last LOG_KEEP lines stay readable
    through /log either way.
"""

import http.client
import json
import os
import socket
import sys
import threading
import time
import traceback
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import idaapi
import ida_idaapi
import idc
import ida_funcs
import ida_bytes
import ida_hexrays
import ida_xref
import ida_name
import ida_nalt
import ida_segment
import ida_ua
import ida_ida

# Debugger API. Present as separate modules from IDA 7.4 on; keep the bridge
# usable (read-only endpoints) if an older build lacks them.
try:
    import ida_dbg
except ImportError:                                     # pragma: no cover
    ida_dbg = None
try:
    import ida_idd
except ImportError:                                     # pragma: no cover
    ida_idd = None

PORT = 13337            # first port to try; the server walks upwards from here
PORT_SCAN = 64          # how many ports to try before giving up
LOG_REQUESTS = True     # mirror the request log into IDA's Output window
LOG_KEEP = 500          # how many lines to keep for /log
ALLOW_DBG_LAUNCH = True   # /dbg/start + /dbg/attach are enabled
# Measured on IDA 8.3: start_process() works when the target matches the loaded
# database — it stops at ntdll's initial breakpoint, and /dbg/continue runs on to
# your own breakpoint; /dbg/exit ends the session cleanly. What does NOT work is
# starting a *different* exe than the database (cmd/notepad/ping were tried): the
# process ran without ever stopping, suspend_process() had no effect, and that
# half-attached session could not be ended. Attaching to a foreign process is
# therefore the risky path, not launching the database's own target.
DBG_WAIT_MAX = 60000    # ceiling for /dbg/wait, milliseconds

_server = None
_port = None            # port this instance actually bound to
_starting = False       # a start is in flight on the worker thread
_log_buf = deque(maxlen=LOG_KEEP)

# Failed writes/reads after the peer went away. Always swallowed: a client that
# closes the socket early is normal (timeout, Ctrl-C, keep-alive teardown) and
# must not spray tracebacks into IDA's Output window.
_CONN_ERRORS = (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)

# xref types that denote an actual call, as opposed to a jump or fall-through.
_CALL_XREFS = (ida_xref.fl_CN, ida_xref.fl_CF)


def log(msg):
    """Append to the in-memory log and echo to IDA's Output window."""
    line = "[ida_bridge] %s" % msg
    _log_buf.append(line)
    if LOG_REQUESTS:
        try:
            print(line)
        except Exception:
            pass
        try:
            sys.stdout.flush()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# main-thread marshalling
# --------------------------------------------------------------------------- #
def on_main(fn):
    """Run fn() on IDA's main thread and return its value."""
    box = {}

    def wrapper():
        try:
            box["v"] = fn()
        except Exception:
            box["e"] = traceback.format_exc()
        return 0

    idaapi.execute_sync(wrapper, idaapi.MFF_WRITE)
    if "e" in box:
        raise RuntimeError(box["e"])
    return box.get("v")


def parse_ea(s, default=None):
    if s is None:
        return default
    s = str(s).strip()
    try:
        return int(s, 16)
    except Exception:
        try:
            ea = idc.get_name_ea_simple(s)
            return ea if ea != idaapi.BADADDR else default
        except Exception:
            return default


def _ref_row(ea, kind):
    """One /xrefs row. Every row carries the same keys, both directions."""
    f = ida_funcs.get_func(ea)
    return {
        "ea": hex(ea),
        "name": ida_name.get_name(ea) or "",
        "type": kind,
        "in_func": hex(f.start_ea) if f else None,
        "func_name": ida_funcs.get_func_name(f.start_ea) if f else None,
    }


def iter_code_refs_from(ea):
    """Yield (target, xref_type) for every code reference out of ea."""
    xb = ida_xref.xrefblk_t()
    ok = xb.first_from(ea, ida_xref.XREF_ALL)
    while ok:
        if xb.iscode:
            yield xb.to, xb.type
        ok = xb.next_from()


def iter_xrefs_to_calls(ea):
    x = ida_xref.get_first_cref_to(ea)
    while x != idaapi.BADADDR:
        yield x
        x = ida_xref.get_next_cref_to(ea, x)


# --------------------------------------------------------------------------- #
# operations (each pure; wrapped by on_main at dispatch time)
# --------------------------------------------------------------------------- #
def op_status():
    return {
        "port": _port,
        "pid": os.getpid(),
        "input": ida_nalt.get_input_file_path(),
        "idb": idc.get_idb_path(),
        "imagebase": hex(idaapi.get_imagebase()),
        "funcs": ida_funcs.get_func_qty(),
        "segments": ida_segment.get_segm_qty(),
        "hexrays": ida_hexrays.init_hexrays_plugin(),
    }


def op_func(ea):
    f = ida_funcs.get_func(ea)
    if not f:
        return {"found": False, "ea": hex(ea)}
    return {
        "found": True,
        "name": ida_funcs.get_func_name(f.start_ea),
        "start": hex(f.start_ea),
        "end": hex(f.end_ea),
        "size": f.end_ea - f.start_ea,
        "flags": f.flags,
        "incoming_calls": sum(1 for _ in iter_xrefs_to_calls(f.start_ea)),
    }


def op_decompile(ea):
    if not ida_hexrays.init_hexrays_plugin():
        return {"ok": False, "error": "Hex-Rays decompiler not available"}
    f = ida_funcs.get_func(ea)
    if not f:
        return {"ok": False, "error": "no function at %#x" % ea}
    try:
        cf = ida_hexrays.decompile(f.start_ea)
    except Exception as e:
        return {"ok": False, "error": "decompile raised: %s" % e}
    if cf is None:
        return {"ok": False, "error": "decompile returned None"}
    return {
        "ok": True,
        "name": ida_funcs.get_func_name(f.start_ea),
        "start": hex(f.start_ea),
        "end": hex(f.end_ea),
        "pseudocode": str(cf),
    }


def op_disasm(ea, n):
    # "addr  bytes  text": the byte column is padded so a long mnemonic/operand
    # string can never run into it.
    out = []
    cur = ea
    for _ in range(n):
        if cur == idaapi.BADADDR:
            break
        raw = idc.get_bytes(cur, idc.get_item_size(cur)) or b""
        out.append("%016X  %-32s  %s" % (
            cur,
            " ".join("%02X" % b for b in raw),
            idc.generate_disasm_line(cur, 0) or ""))
        nxt = idc.next_head(cur, cur + 16)
        if nxt <= cur:
            break
        cur = nxt
    return out


def op_xrefs(ea, direction):
    out = []
    if direction == "from":
        x = ida_xref.get_first_cref_from(ea)
        while x != idaapi.BADADDR:
            out.append(_ref_row(x, "code"))
            x = ida_xref.get_next_cref_from(ea, x)
        x = ida_xref.get_first_dref_from(ea)
        while x != idaapi.BADADDR:
            out.append(_ref_row(x, "data"))
            x = ida_xref.get_next_dref_from(ea, x)
    else:
        x = ida_xref.get_first_cref_to(ea)
        while x != idaapi.BADADDR:
            out.append(_ref_row(x, "code"))
            x = ida_xref.get_next_cref_to(ea, x)
        x = ida_xref.get_first_dref_to(ea)
        while x != idaapi.BADADDR:
            out.append(_ref_row(x, "data"))
            x = ida_xref.get_next_dref_to(ea, x)
    return out


def op_callers(ea):
    f = ida_funcs.get_func(ea)
    if not f:
        return {"ok": False, "error": "no function at %#x" % ea}
    res = []
    for site in iter_xrefs_to_calls(f.start_ea):
        cf = ida_funcs.get_func(site)
        res.append({"call_site": hex(site),
                    "caller": hex(cf.start_ea) if cf else None,
                    "caller_name": ida_funcs.get_func_name(cf.start_ea) if cf else None})
    return {"ok": True, "target": hex(f.start_ea),
            "name": ida_funcs.get_func_name(f.start_ea), "callers": res}


def op_callees(ea):
    f = ida_funcs.get_func(ea)
    if not f:
        return {"ok": False, "error": "no function at %#x" % ea}
    res, seen = [], set()
    cur = f.start_ea
    while cur < f.end_ea and cur != idaapi.BADADDR:
        for tgt, xtype in iter_code_refs_from(cur):
            # Only real calls: skips fall-through (the next instruction) and
            # plain jumps, which get_first_cref_from() reports just the same.
            if xtype not in _CALL_XREFS:
                continue
            key = (cur, tgt)
            if key in seen:
                continue
            seen.add(key)
            tf = ida_funcs.get_func(tgt)
            res.append({
                "call_site": hex(cur),
                "target": hex(tgt),
                "target_name": ida_funcs.get_func_name(tgt) if (tf and tf.start_ea == tgt)
                               else (ida_name.get_name(tgt) or ""),
            })
        cur = idc.next_head(cur, f.end_ea)
        if cur == idaapi.BADADDR:
            break
    return {"ok": True, "target": hex(f.start_ea),
            "name": ida_funcs.get_func_name(f.start_ea), "callees": res}


def op_names(like, limit):
    out = []
    like_l = (like or "").lower()
    n = ida_name.get_nlist_size()
    for i in range(n):
        ea = ida_name.get_nlist_ea(i)
        nm = ida_name.get_nlist_name(i)
        if like_l and like_l not in nm.lower():
            continue
        out.append({"ea": hex(ea), "name": nm})
        if len(out) >= limit:
            break
    return out


def op_bytes(ea, n):
    b = idc.get_bytes(ea, n)
    if b is None:
        return {"ok": False}
    return {"ok": True, "ea": hex(ea), "hex": b.hex(), "len": len(b)}


def op_cstr(ea):
    s = idc.get_strlit_contents(ea, -1, idc.STRTYPE_C)
    if s is None:
        return {"ok": False}
    try:
        s = s.decode("utf-8", "replace")
    except Exception:
        pass
    return {"ok": True, "ea": hex(ea), "string": s}


def op_segments():
    out = []
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        out.append({"name": ida_segment.get_segm_name(s),
                    "start": hex(s.start_ea), "end": hex(s.end_ea),
                    "size": s.end_ea - s.start_ea})
    return out


SEARCH_CHUNK = 1 << 20   # 1 MiB per idc.get_bytes() call while pattern searching


def iter_pattern_hits(pat, seg_start, seg_end, want):
    """Yield addresses of pat inside [seg_start, seg_end), in ascending order.

    Reads the segment in chunks and uses bytes.find(). idaapi.find_binary() is
    deliberately not used: on IDA 7.7 it silently skips matches at/near the
    given start address (a match at 0x20c0 is missed by find_binary(0x20c0, ..)
    and even by find_binary(0x20bf, ..)), which makes it unusable for paging.
    """
    n = len(pat)
    if n == 0 or seg_end <= seg_start:
        return
    found = 0
    start = seg_start
    while start < seg_end and found < want:
        size = min(SEARCH_CHUNK, seg_end - start)
        grab = min(size + n - 1, seg_end - start)   # overlap: match may straddle
        buf = idc.get_bytes(start, grab)
        if buf is None:
            start += size                            # unreadable hole, skip it
            continue
        limit = start + size                         # first address of next chunk
        idx = buf.find(pat)
        while idx != -1 and found < want:
            ea = start + idx
            if ea < limit:
                yield ea
                found += 1
            idx = buf.find(pat, idx + 1)
        if start + size >= seg_end:
            break
        start += size


def op_search(pat_hex, limit):
    try:
        pat = bytes.fromhex(pat_hex)
    except Exception as e:
        return {"ok": False, "error": "bad hex: %s" % e}
    if not pat:
        return {"ok": False, "error": "empty pattern"}
    txt = " ".join("%02X" % b for b in pat)
    res = []
    # Walk the database segment by segment instead of one range from the
    # imagebase: the old code scanned a hardcoded imagebase+0xB06D000, which
    # both misses anything past that offset and is meaningless on other targets.
    for i in range(ida_segment.get_segm_qty()):
        if len(res) >= limit:
            break
        seg = ida_segment.getnseg(i)
        if seg is None:
            continue
        for ea in iter_pattern_hits(pat, seg.start_ea, seg.end_ea, limit - len(res)):
            f = ida_funcs.get_func(ea)
            res.append({"ea": hex(ea), "in_func": hex(f.start_ea) if f else None,
                        "func_name": ida_funcs.get_func_name(f.start_ea) if f else None})
    return {"ok": True, "pattern": txt, "hits": res}


def op_log(limit):
    lines = list(_log_buf)
    return {"ok": True, "lines": lines[-limit:] if limit > 0 else []}


# --------------------------------------------------------------------------- #
# debugger operations
#
# Everything here needs a debugger session (Debugger -> Start/Attach in the GUI,
# or POST /dbg/start). The actions use IDA's *synchronous* debugger API:
# start_process() / step_into() / run_to() drive the debugger's own event loop and
# return once the target stops, exactly like the GUI buttons. The request_*
# variants were tried first and do not work from here — they only enqueue, and
# nothing on the main thread pumps that queue, so the process never started.
# --------------------------------------------------------------------------- #
def _dbg_available():
    """For breakpoint management, which works without a session (like the GUI)."""
    if ida_dbg is None:
        return False, {"ok": False, "error": "this IDA build has no ida_dbg module"}
    return True, None


def _dbg_ready():
    """(True, None) when a debugger session is live, else (False, error dict)."""
    if ida_dbg is None:
        return False, {"ok": False, "error": "this IDA build has no ida_dbg module"}
    if not ida_dbg.is_debugger_on():
        return False, {"ok": False,
                       "error": "no debugger session "
                                "(Debugger -> Start process, or POST /dbg/start)"}
    return True, None


def _dbg_state_name(st):
    return {0: "notask", 1: "run", -1: "suspended"}.get(st, "state_%d" % st)


_REG_WIDTH = None


def _reg_width():
    """Pointer width of the database, needed by idaapi.get_reg_name() in 8.x."""
    global _REG_WIDTH
    if _REG_WIDTH is None:
        _REG_WIDTH = 8
        try:
            _REG_WIDTH = 8 if ida_ida.inf_is_64bit() else 4
        except Exception:
            pass
    return _REG_WIDTH


def _reg_name(idx):
    """Register name for a register index, following the loaded processor module.

    idc has no get_reg_name() here, and idaapi.get_reg_name() needs the register
    width: on 8.3 get_reg_name(0) raises TypeError, get_reg_name(0, 4) is 'eax'.
    """
    fn = getattr(idaapi, "get_reg_name", None)
    if fn is not None:
        for w in (_reg_width(), 4, 8, 2, 1):
            try:
                nm = fn(idx, w)
                if nm:
                    return nm
            except Exception:
                continue
    return "reg_%d" % idx


def _reg_repr(rv):
    """Register value as hex. regval_t.ival is the integer view of the value."""
    try:
        v = rv.ival
        if isinstance(v, int):
            return hex(v)
    except Exception:
        pass
    try:
        p = getattr(rv, "pyval")
        p = p(0) if callable(p) else p          # 8.3: pyval(self, dtype)
        return repr(p)
    except Exception:
        return "?"


def op_dbg_state():
    if ida_dbg is None:
        return {"ok": False, "error": "this IDA build has no ida_dbg module"}
    st = ida_dbg.get_process_state()
    cur = ida_dbg.get_current_thread()
    threads = []
    for i in range(ida_dbg.get_thread_qty()):
        tid = ida_dbg.getn_thread(i)
        threads.append({"index": i, "tid": tid,
                        "name": ida_dbg.getn_thread_name(i) or "",
                        "current": tid == cur})
    opts = ida_dbg.get_process_options()
    return {
        "ok": True,
        "debugger_on": ida_dbg.is_debugger_on(),
        "state": st,
        "state_name": _dbg_state_name(st),
        "can_query": ida_dbg.dbg_can_query(),
        "busy": ida_dbg.is_debugger_busy(),
        "current_thread": cur,
        "threads": threads,
        "bpt_count": ida_dbg.get_bpt_qty(),
        "path": opts[0] or "",
        "args": opts[1] or "",
        "pid": opts[5] if len(opts) > 5 else None,
    }


def op_dbg_options():
    if ida_dbg is None:
        return {"ok": False, "error": "this IDA build has no ida_dbg module"}
    o = ida_dbg.get_process_options()
    return {"ok": True, "path": o[0], "args": o[1], "sdir": o[2], "env": o[3],
            "pid": o[5] if len(o) > 5 else None}


def op_dbg_regs(tid=None):
    ok, err = _dbg_ready()
    if not ok:
        return err
    if tid is None:
        tid = ida_dbg.get_current_thread()
    # get_reg_val() reads the *current* thread, so honour ?tid= when it differs.
    if tid != ida_dbg.get_current_thread():
        try:
            ida_dbg.select_thread(tid)
        except Exception as e:
            return {"ok": False, "error": "select_thread(%s) failed: %s" % (tid, e)}
    try:
        total = len(ida_dbg.get_reg_vals(tid))
    except Exception:
        total = 256
    # Names come from the index, but every value is fetched by name: the index
    # order of get_reg_vals() does not line up with the names (on x86 'esp' and
    # 'er8' came back shifted), while get_reg_val(name) is authoritative.
    regs = {}
    for i in range(total):
        nm = _reg_name(i)
        if not nm or nm.startswith("reg_") or nm in regs:
            continue
        rv = idaapi.regval_t()
        try:
            if ida_dbg.get_reg_val(nm, rv):
                regs[nm] = _reg_repr(rv)
        except Exception:
            continue
    return {"ok": True, "tid": tid, "count": len(regs), "regs": regs}


def op_dbg_reg(name):
    ok, err = _dbg_ready()
    if not ok:
        return err
    if not name:
        return {"ok": False, "error": "missing ?name= (e.g. eip, rax, rsp)"}
    rv = idaapi.regval_t()
    try:
        got = ida_dbg.get_reg_val(name, rv)
    except Exception as e:
        return {"ok": False, "error": "get_reg_val failed: %s" % e}
    if not got:
        return {"ok": False, "error": "no such register, or no current thread: %s" % name}
    return {"ok": True, "name": name, "value": _reg_repr(rv),
            "tid": ida_dbg.get_current_thread()}


def op_dbg_setreg(q):
    ok, err = _dbg_ready()
    if not ok:
        return err
    name = q.get("name", [""])[0]
    raw = q.get("value", [""])[0]
    if not name or not raw:
        return {"ok": False, "error": "need ?name= and ?value= (value in hex or decimal)"}
    try:
        value = int(raw, 0)
    except Exception:
        return {"ok": False, "error": "value must be a number: %r" % raw}
    try:
        if not ida_dbg.set_reg_val(name, value):
            return {"ok": False, "error": "set_reg_val rejected %s" % name}
    except Exception as e:
        return {"ok": False, "error": "set_reg_val failed: %s" % e}
    return {"ok": True, "name": name, "value": hex(value)}


def op_dbg_mem(ea, n):
    ok, err = _dbg_ready()
    if not ok:
        return err
    if not ida_dbg.is_debugger_memory(ea):
        return {"ok": False, "error": "%#x is not mapped in the debugged process" % ea}
    # During a session IDA serves debuggee memory through the normal read call.
    b = idc.get_bytes(ea, n)
    if b is None:
        return {"ok": False, "error": "could not read %d bytes at %#x" % (n, ea)}
    return {"ok": True, "ea": hex(ea), "len": len(b), "hex": b.hex()}


def op_dbg_write(q):
    ok, err = _dbg_ready()
    if not ok:
        return err
    ea = parse_ea(q.get("ea", [None])[0])
    hexstr = q.get("hex", [""])[0]
    if ea is None or not hexstr:
        return {"ok": False, "error": "need ?ea= and ?hex="}
    try:
        buf = bytes.fromhex(hexstr)
    except Exception as e:
        return {"ok": False, "error": "bad hex: %s" % e}
    try:
        written = ida_dbg.write_dbg_memory(ea, buf, len(buf))
    except Exception as e:
        return {"ok": False, "error": "write_dbg_memory failed: %s" % e}
    if written != len(buf):
        return {"ok": False, "error": "wrote %s of %d bytes" % (written, len(buf))}
    return {"ok": True, "ea": hex(ea), "len": written}


def _bpt_enabled(b):
    v = getattr(b, "enabled", None)
    try:
        if callable(v):
            return bool(v())
    except Exception:
        pass
    return bool(v)


def _call_or_value(obj, name, default=None):
    try:
        v = getattr(obj, name)
    except Exception:
        return default
    try:
        return v() if callable(v) else v
    except Exception:
        return default


def _bpt_ea(b):
    """Address of a breakpoint.

    Two shapes exist in 8.x: breakpoints created by IDA itself carry '$<hex>' in
    loc.symbol/loc.path while loc.ea() reports junk, and breakpoints added through
    add_bpt() carry an empty symbol while loc.ea() is correct. Try the string
    first, then the numeric accessors (filtered, since the junk values are small).
    """
    loc = b.loc
    for attr in ("symbol", "path"):
        s = _call_or_value(loc, attr)
        if not isinstance(s, str) or not s:
            continue
        if s.startswith("$"):
            try:
                return int(s[1:], 16)
            except Exception:
                pass
        try:
            ea = idc.get_name_ea_simple(s)
            if ea != idaapi.BADADDR:
                return ea
        except Exception:
            pass
    for attr in ("ea", "offset"):
        v = _call_or_value(loc, attr)
        if isinstance(v, int) and 0x1000 <= v < idaapi.BADADDR:
            return v
    return None


def op_dbg_bpts():
    ok, err = _dbg_available()
    if not ok:
        return err
    out = []
    for i in range(ida_dbg.get_bpt_qty()):
        b = ida_dbg.bpt_t()
        if not ida_dbg.getn_bpt(i, b):
            continue
        ea = _bpt_ea(b)
        out.append({
            "ea": hex(ea) if ea is not None else None,
            "name": (ida_name.get_name(ea) or "") if ea is not None else "",
            "bptid": getattr(b, "bptid", None),
            "type": getattr(b, "type", None),
            "size": _call_or_value(b, "get_size", 0),
            "enabled": _bpt_enabled(b),
            "active": _call_or_value(b, "is_active"),
            "hardware": _call_or_value(b, "is_hwbpt"),
            "condition": getattr(b, "condition", "") or "",
        })
    return {"ok": True, "count": len(out), "bpts": out}


def _bpt_type_from_name(name):
    """Breakpoint type bits.

    'exec'/'default' give a *software* exec breakpoint (BPT_EXEC|BPT_SOFT, which
    equals BPT_DEFAULT). Plain BPT_EXEC on its own is a hardware breakpoint — it
    needs a debug register slot and did not get hit on this target, so it is only
    used when explicitly requested with type=hw.
    """
    if ida_idd is None:
        return 0
    soft_exec = ida_idd.BPT_EXEC | ida_idd.BPT_SOFT
    m = {"exec": soft_exec, "sw": soft_exec,
         "default": ida_idd.BPT_DEFAULT,
         "read": ida_idd.BPT_READ, "write": ida_idd.BPT_WRITE,
         "rw": ida_idd.BPT_RDWR, "soft": ida_idd.BPT_SOFT,
         "hw": ida_idd.BPT_EXEC, "hard": ida_idd.BPT_EXEC}
    return m.get((name or "default").lower(), ida_idd.BPT_DEFAULT)


def op_dbg_bpt_add(q):
    ok, err = _dbg_available()
    if not ok:
        return err
    ea = parse_ea(q.get("ea", [None])[0])
    if ea is None:
        return {"ok": False, "error": "missing ?ea="}
    try:
        size = int(q.get("size", ["0"])[0])
    except Exception:
        size = 0
    btype = _bpt_type_from_name(q.get("type", ["default"])[0])
    return {"ok": bool(ida_dbg.add_bpt(ea, size, btype)),
            "ea": hex(ea), "size": size, "type": btype,
            "bpt_count": ida_dbg.get_bpt_qty()}


def op_dbg_bpt_del(q):
    ok, err = _dbg_available()
    if not ok:
        return err
    ea = parse_ea(q.get("ea", [None])[0])
    if ea is None:
        return {"ok": False, "error": "missing ?ea="}
    return {"ok": bool(ida_dbg.del_bpt(ea)), "ea": hex(ea),
            "bpt_count": ida_dbg.get_bpt_qty()}


def op_dbg_bpt_enable(q):
    ok, err = _dbg_available()
    if not ok:
        return err
    ea = parse_ea(q.get("ea", [None])[0])
    if ea is None:
        return {"ok": False, "error": "missing ?ea="}
    on = (q.get("on", ["1"])[0] or "1").lower() not in ("0", "false", "no")
    return {"ok": bool(ida_dbg.enable_bpt(ea, on)), "ea": hex(ea), "enabled": on}


def op_dbg_continue(q):
    ok, err = _dbg_ready()
    if not ok:
        return err
    # Hands control back to the target and returns; the process keeps running.
    return {"ok": bool(ida_dbg.continue_process()), "state": ida_dbg.get_process_state(),
            "state_name": _dbg_state_name(ida_dbg.get_process_state())}


def op_dbg_suspend(q):
    ok, err = _dbg_ready()
    if not ok:
        return err
    return {"ok": bool(ida_dbg.suspend_process()),
            "state": ida_dbg.get_process_state(),
            "state_name": _dbg_state_name(ida_dbg.get_process_state())}


_STEP_NOTE = ("stepped; the state below is read before IDA's event loop updates it — "
              "GET /dbg for the settled state and /dbg/reg?name=eip for the new PC")


def op_dbg_step(q):
    ok, err = _dbg_ready()
    if not ok:
        return err
    kind = (q.get("kind", ["into"])[0] or "into").lower()
    fn = {"into": getattr(ida_dbg, "step_into", None),
          "over": getattr(ida_dbg, "step_over", None),
          "out": getattr(ida_dbg, "step_until_ret", None)}.get(kind)
    if fn is None:
        return {"ok": False, "error": "kind must be into|over|out"}
    # These wait for the target to stop again, exactly like F7/F8 in the GUI. The
    # state flag itself is only refreshed once this request stops occupying the
    # main thread, so polling it here would never succeed.
    done = bool(fn())
    st = ida_dbg.get_process_state()
    return {"ok": done, "stepped": "step_" + kind,
            "state": st, "state_name": _dbg_state_name(st), "note": _STEP_NOTE}


def op_dbg_runto(q):
    ok, err = _dbg_ready()
    if not ok:
        return err
    ea = parse_ea(q.get("ea", [None])[0])
    if ea is None:
        return {"ok": False, "error": "missing ?ea="}
    done = bool(ida_dbg.run_to(ea))
    st = ida_dbg.get_process_state()
    return {"ok": done, "ran_to": hex(ea),
            "state": st, "state_name": _dbg_state_name(st), "note": _STEP_NOTE}


def op_dbg_thread(q):
    ok, err = _dbg_ready()
    if not ok:
        return err
    try:
        tid = int(q.get("tid", ["-1"])[0], 0)
    except Exception:
        return {"ok": False, "error": "bad ?tid="}
    return {"ok": bool(ida_dbg.select_thread(tid)), "tid": tid,
            "current_thread": ida_dbg.get_current_thread()}


def op_dbg_wait(q):
    """Pump the debugger request queue and report the state afterwards.

    IDA 8.3 refuses wait_for_next_event() from a script context ("Internal error
    40202"), so this uses run_requests() instead: it processes whatever requests
    are pending and returns immediately.
    """
    if ida_dbg is None:
        return {"ok": False, "error": "this IDA build has no ida_dbg module"}
    try:
        ms = int(q.get("timeout_ms", ["3000"])[0])
    except Exception:
        ms = 3000
    ms = max(0, min(ms, DBG_WAIT_MAX))
    try:
        pumped = ida_dbg.run_requests()
    except Exception as e:
        return {"ok": False, "error": "run_requests failed: %s" % e}
    st = ida_dbg.get_process_state()
    return {"ok": bool(pumped), "event": None, "state": st,
            "state_name": _dbg_state_name(st), "timeout_ms": ms,
            "debugger_on": ida_dbg.is_debugger_on()}


def op_dbg_stack(q):
    ok, err = _dbg_ready()
    if not ok:
        return err
    if ida_idd is None:
        return {"ok": False, "error": "this IDA build has no ida_idd module"}
    try:
        tid = int(q.get("tid", [str(ida_dbg.get_current_thread())])[0], 0)
    except Exception:
        return {"ok": False, "error": "bad ?tid="}
    trace = ida_idd.call_stack_t()
    try:
        if not ida_dbg.collect_stack_trace(tid, trace):
            return {"ok": False, "error": "collect_stack_trace failed"}
    except Exception as e:
        return {"ok": False, "error": "collect_stack_trace failed: %s" % e}
    try:
        n = len(trace)
    except Exception:
        n = trace.size()
    frames = []
    for i in range(n):
        ci = trace.at(i)
        funcok = bool(getattr(ci, "funcok", False))
        frames.append({"level": i,
                       "call_ea": hex(ci.callea),
                       "func_ea": hex(ci.funcea) if funcok else None,
                       "func_name": ida_funcs.get_func_name(ci.funcea) if funcok else "",
                       "fp": hex(ci.fp)})
    return {"ok": True, "tid": tid, "count": len(frames), "frames": frames}


_DEBUGGER_LOADED = False


def _ensure_debugger():
    """Try to load a user-mode debugger plugin.

    On the IDA 8.3 tested here this fails for every name (the win*_user plugins
    are present but refuse to load through the API), so /dbg/start and /dbg/attach
    stay disabled by default and the GUI is the way to create a session.
    """
    global _DEBUGGER_LOADED
    if _DEBUGGER_LOADED:
        return True
    fn = getattr(ida_dbg, "load_debugger", None)
    if fn is None:
        _DEBUGGER_LOADED = True
        return True
    for name in ("win32_user", "windbg_user", "win32", "win64", "gdb"):
        try:
            if fn(name, False):
                _DEBUGGER_LOADED = True
                log("debugger plugin loaded: %s" % name)
                return True
        except Exception:
            continue
    log("no debugger plugin could be loaded through load_debugger()")
    return False


def _dbg_stop_now(q):
    """Try to bring a freshly started/attached process to a stop.

    suspend_process() only queues a request, and on this IDA the queue is not
    pumped from a script context (wait_for_next_event() raises 40202 there), so
    this is best-effort and reports False when it did not take.
    """
    if (q.get("stop", ["1"])[0] or "1").lower() in ("0", "false", "no"):
        return False
    try:
        ida_dbg.suspend_process()
        ida_dbg.run_requests()
    except Exception:
        return False
    return ida_dbg.get_process_state() == -1


def op_dbg_start(q):
    if not ALLOW_DBG_LAUNCH:
        return {"ok": False,
                "error": "launching is disabled (ALLOW_DBG_LAUNCH = False)"}
    if ida_dbg is None:
        return {"ok": False, "error": "this IDA build has no ida_dbg module"}
    path = q.get("path", [""])[0]
    if not path:
        return {"ok": False,
                "error": "missing ?path= — refusing to fall back to the loaded "
                         "executable, which may start doing real work"}
    args = q.get("args", [""])[0]
    sdir = q.get("sdir", [""])[0] or None
    # A failed load_debugger() is not fatal: the plugin may already be resident.
    plugin_loaded = _ensure_debugger()
    try:
        ida_dbg.start_process(path, args, sdir)
    except Exception as e:
        return {"ok": False, "error": "start_process failed: %s" % e,
                "debugger_plugin_loaded": plugin_loaded}
    started = ida_dbg.is_debugger_on()
    stopped = _dbg_stop_now(q) if started else False
    st = ida_dbg.get_process_state()
    return {"ok": started, "path": path, "args": args,
            "debugger_plugin_loaded": plugin_loaded,
            "stopped": stopped, "state": st, "state_name": _dbg_state_name(st),
            "threads": ida_dbg.get_thread_qty()}


def op_dbg_attach(q):
    if not ALLOW_DBG_LAUNCH:
        return {"ok": False,
                "error": "attaching is disabled (ALLOW_DBG_LAUNCH = False)"}
    if ida_dbg is None:
        return {"ok": False, "error": "this IDA build has no ida_dbg module"}
    try:
        pid = int(q.get("pid", ["-1"])[0], 0)
    except Exception:
        return {"ok": False, "error": "bad ?pid="}
    if pid < 0:
        return {"ok": False, "error": "missing ?pid= (decimal or 0x...)"}
    plugin_loaded = _ensure_debugger()
    try:
        ida_dbg.attach_process(pid)
    except Exception as e:
        return {"ok": False, "error": "attach_process failed: %s" % e,
                "debugger_plugin_loaded": plugin_loaded}
    attached = ida_dbg.is_debugger_on()
    stopped = _dbg_stop_now(q) if attached else False
    st = ida_dbg.get_process_state()
    return {"ok": attached, "attached_pid": pid,
            "debugger_plugin_loaded": plugin_loaded,
            "stopped": stopped, "state": st, "state_name": _dbg_state_name(st),
            "threads": ida_dbg.get_thread_qty()}


def op_dbg_exit(q):
    ok, err = _dbg_ready()
    if not ok:
        return err
    # Sync API: request_exit_process() only queues the request and nothing pumps
    # the queue from here, so the target used to stay alive after /dbg/exit.
    done = bool(ida_dbg.exit_process())
    st = ida_dbg.get_process_state()
    return {"ok": done, "requested": "exit_process", "state": st,
            "state_name": _dbg_state_name(st), "debugger_on": ida_dbg.is_debugger_on()}


def op_dbg_detach(q):
    ok, err = _dbg_ready()
    if not ok:
        return err
    done = bool(ida_dbg.detach_process())
    st = ida_dbg.get_process_state()
    return {"ok": done, "requested": "detach_process", "state": st,
            "state_name": _dbg_state_name(st), "debugger_on": ida_dbg.is_debugger_on()}


# --------------------------------------------------------------------------- #
# HTTP layer
# --------------------------------------------------------------------------- #
ROUTES = {
    "/func":      lambda q: on_main(lambda: op_func(parse_ea(q.get("ea", [None])[0]))),
    "/decompile": lambda q: on_main(lambda: op_decompile(parse_ea(q.get("ea", [None])[0]))),
    "/disasm":    lambda q: on_main(lambda: op_disasm(parse_ea(q.get("ea", [None])[0]),
                                                      int(q.get("n", ["40"])[0]))),
    "/xrefs":     lambda q: on_main(lambda: op_xrefs(parse_ea(q.get("ea", [None])[0]),
                                                     q.get("dir", ["to"])[0])),
    "/callers":   lambda q: on_main(lambda: op_callers(parse_ea(q.get("ea", [None])[0]))),
    "/callees":   lambda q: on_main(lambda: op_callees(parse_ea(q.get("ea", [None])[0]))),
    "/names":     lambda q: on_main(lambda: op_names(q.get("like", [""])[0],
                                                     int(q.get("limit", ["50"])[0]))),
    "/bytes":     lambda q: on_main(lambda: op_bytes(parse_ea(q.get("ea", [None])[0]),
                                                     int(q.get("n", ["64"])[0]))),
    "/cstr":      lambda q: on_main(lambda: op_cstr(parse_ea(q.get("ea", [None])[0]))),
    "/search":    lambda q: on_main(lambda: op_search(q.get("pat", [""])[0],
                                                      int(q.get("limit", ["16"])[0]))),
    "/log":       lambda q: op_log(int(q.get("limit", ["50"])[0])),
    "/dbg":       lambda q: on_main(op_dbg_state),
    "/dbg/options": lambda q: on_main(op_dbg_options),
    "/dbg/regs":  lambda q: on_main(lambda: op_dbg_regs(
                      int(q["tid"][0], 0) if q.get("tid") else None)),
    "/dbg/reg":   lambda q: on_main(lambda: op_dbg_reg(q.get("name", [""])[0])),
    "/dbg/mem":   lambda q: on_main(lambda: op_dbg_mem(parse_ea(q.get("ea", [None])[0]),
                                                       int(q.get("n", ["64"])[0]))),
    "/dbg/bpts":  lambda q: on_main(op_dbg_bpts),
    "/dbg/stack": lambda q: on_main(lambda: op_dbg_stack(q)),
}


# Actions. Unlike ROUTES these are POST, and each only *requests* work from the
# debugger, so none of them can block on a target that never stops.
DBG_ACTIONS = {
    "/dbg/continue":   lambda q: on_main(lambda: op_dbg_continue(q)),
    "/dbg/suspend":    lambda q: on_main(lambda: op_dbg_suspend(q)),
    "/dbg/step":       lambda q: on_main(lambda: op_dbg_step(q)),
    "/dbg/runto":      lambda q: on_main(lambda: op_dbg_runto(q)),
    "/dbg/wait":       lambda q: on_main(lambda: op_dbg_wait(q)),
    "/dbg/thread":     lambda q: on_main(lambda: op_dbg_thread(q)),
    "/dbg/reg/set":    lambda q: on_main(lambda: op_dbg_setreg(q)),
    "/dbg/write":      lambda q: on_main(lambda: op_dbg_write(q)),
    "/dbg/bpt/add":    lambda q: on_main(lambda: op_dbg_bpt_add(q)),
    "/dbg/bpt/del":    lambda q: on_main(lambda: op_dbg_bpt_del(q)),
    "/dbg/bpt/enable": lambda q: on_main(lambda: op_dbg_bpt_enable(q)),
    "/dbg/start":      lambda q: on_main(lambda: op_dbg_start(q)),
    "/dbg/attach":     lambda q: on_main(lambda: op_dbg_attach(q)),
    "/dbg/exit":       lambda q: on_main(lambda: op_dbg_exit(q)),
    "/dbg/detach":     lambda q: on_main(lambda: op_dbg_detach(q)),
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        # Replaced by the one-line access log emitted from _send().
        pass

    def handle_one_request(self):
        try:
            BaseHTTPRequestHandler.handle_one_request(self)
        except _CONN_ERRORS as e:
            self.close_connection = True
            log("%s %s -> client went away (%s)" %
                (self.command or "-", self.path or "-", e.__class__.__name__))

    def _send(self, obj, code=200):
        body = json.dumps(obj, indent=1, ensure_ascii=False).encode("utf-8", "replace")
        label = getattr(self, "_label", "%s %s" % (self.command, self.path))
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except _CONN_ERRORS as e:
            self.close_connection = True
            log("%s -> client closed the socket (%s)" % (label, e.__class__.__name__))
            return
        except Exception:
            self.close_connection = True
            log("%s -> send failed:\n%s" % (label, traceback.format_exc()))
            return
        t0 = getattr(self, "_t0", None)
        took = (time.time() - t0) * 1000.0 if t0 else 0.0
        log("%s -> %d%s  %.1f ms  %d B" %
            (label, code, "" if code == 200 else "  [error]", took, len(body)))

    def do_GET(self):
        self._t0 = time.time()
        self._label = "GET %s" % (self.path or "/")
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path = u.path.rstrip("/") or "/"
        if path == "/ping":
            return self._send({"ok": True, "pong": True})
        if path == "/whoami":
            # Deliberately does not touch IDA's main thread: clients use this to
            # find the port, and a reload probing its own previous instance would
            # deadlock if the probe needed execute_sync().
            return self._send({"ok": True, "port": _port, "pid": os.getpid()})
        if path == "/shutdown":
            self._send({"ok": True, "stopping": True})
            threading.Thread(target=_shutdown, daemon=True).start()
            return
        try:
            if path == "/status":
                return self._send(on_main(op_status))
            if path == "/segments":
                return self._send(on_main(op_segments))
            fn = ROUTES.get(path)
            if fn is None:
                return self._send({"ok": False, "error": "unknown endpoint %s" % path}, 404)
            return self._send(fn(q))
        except Exception:
            return self._send({"ok": False, "error": traceback.format_exc()}, 500)

    def do_POST(self):
        self._t0 = time.time()
        u = urlparse(self.path)
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode("utf-8", "replace")
        except _CONN_ERRORS as e:
            self.close_connection = True
            log("POST %s -> client went away while sending the body (%s)" %
                (u.path, e.__class__.__name__))
            return
        except Exception:
            body = ""
        self._label = "POST %s" % (u.path or "/")
        if body.strip():
            head = body.strip().splitlines()[0]
            self._label += "  [%s%s]" % (head[:80], "..." if len(head) > 80 else "")
        if u.path.rstrip("/") == "/exec":
            def run():
                g = {"idaapi": idaapi, "idc": idc, "ida_funcs": ida_funcs,
                     "ida_bytes": ida_bytes, "ida_hexrays": ida_hexrays,
                     "ida_xref": ida_xref, "ida_name": ida_name}
                loc = {}
                exec(compile(body, "<ida_bridge>", "exec"), g, loc)
                return {k: repr(v) for k, v in loc.items() if not k.startswith("__")}
            try:
                return self._send({"ok": True, "result": on_main(run)})
            except Exception:
                return self._send({"ok": False, "error": traceback.format_exc()}, 500)
        act = DBG_ACTIONS.get(u.path.rstrip("/"))
        if act is not None:
            try:
                return self._send(act(parse_qs(u.query)))
            except Exception:
                return self._send({"ok": False, "error": traceback.format_exc()}, 500)
        return self._send({"ok": False, "error": "unknown POST %s" % u.path}, 404)


class BridgeServer(ThreadingHTTPServer):
    daemon_threads = True
    # Exclusive bind on purpose: on Windows allow_reuse_address sets SO_REUSEADDR,
    # which lets a second bind of a live port "succeed" and leaves two listeners
    # fighting over it. Without it, a busy port fails immediately instead — which
    # is both what pick_port() needs and free of any timeout.
    allow_reuse_address = False

    def handle_error(self, request, client_address):
        # socketserver's default prints a full traceback for every dead client,
        # which is pure noise in IDA's Output window.
        exc = sys.exc_info()[1]
        host = "%s:%s" % client_address[:2]
        if isinstance(exc, _CONN_ERRORS):
            log("client %s disconnected (%s)" % (host, exc.__class__.__name__))
            return
        log("request from %s failed:\n%s" % (host, traceback.format_exc()))


def _shutdown():
    global _server, _port
    srv, port, _server = _server, _port, None
    try:
        if srv:
            srv.shutdown()      # stop serve_forever()
            srv.server_close()  # and actually release the listening socket
    except Exception:
        pass
    _forget_port(port)
    _port = None


def _http_get(port, path, timeout=0.5):
    """Plain GET against a local port; parsed JSON, or None if nothing is there."""
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        c.request("GET", path)
        r = c.getresponse()
        body = r.read()
        c.close()
        if r.status != 200:
            return None
        return json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return None


def port_is_free(port):
    """True if we can take the port exclusively.

    A bind test, not a connect test, on purpose: on Windows a connect to a port
    nobody listens on usually waits for the whole timeout instead of being
    refused, so probing the range port by port cost ~0.3 s each (tens of seconds
    for the whole window). bind() fails or succeeds immediately.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


# The last port this process bound is parked on the idaapi module: reloading the
# script gives a fresh module namespace, but the module object survives, so a new
# run finds the old listener with one probe instead of scanning the range.
def _remember_port(port):
    try:
        idaapi._ida_bridge_port = port
    except Exception:
        pass


def _recall_port():
    return getattr(idaapi, "_ida_bridge_port", None)


def _forget_port(port):
    try:
        if getattr(idaapi, "_ida_bridge_port", None) == port:
            del idaapi._ida_bridge_port
    except Exception:
        pass


def stop_previous():
    """Stop the bridge this IDA process started earlier (i.e. a script reload).

    Bridges belonging to *other* IDA instances are never touched — they are
    simply avoided, because their port cannot be bound below.
    """
    me = os.getpid()
    p = _recall_port()
    if p is None:
        return
    who = _http_get(p, "/whoami")
    if not who or who.get("pid") != me:
        return
    log("stopping the previous instance on port %d" % p)
    try:
        s = socket.create_connection(("127.0.0.1", p), timeout=0.5)
        s.sendall(b"GET /shutdown HTTP/1.0\r\n\r\n")
        try:
            s.recv(1024)     # drain the reply, so the old server is not left mid-write
        except Exception:
            pass
        s.close()
    except Exception:
        pass
    for _ in range(80):
        if port_is_free(p):
            return
        time.sleep(0.05)
    log("WARNING: port %d is still busy after /shutdown; taking the next free one" % p)


def pick_port():
    """Bind the first port from PORT upwards that we can take exclusively."""
    global _server, _port
    last = None
    for p in range(PORT, PORT + PORT_SCAN):
        try:
            _server = BridgeServer(("127.0.0.1", p), Handler)
        except OSError as e:
            last = e          # somebody else owns it: next candidate, no waiting
            continue
        _port = p
        _remember_port(p)
        return _server
    log("cannot bind any port in %d..%d: %s"
        % (PORT, PORT + PORT_SCAN - 1, last))
    return None


def _run():
    global _server, _starting
    try:
        stop_previous()
        if pick_port() is None:
            return
        log("listening on http://127.0.0.1:%d" % _port)
        log("try: curl http://127.0.0.1:%d/status" % _port)
        _server.serve_forever()
    finally:
        _starting = False


def main():
    """Start the bridge. Idempotent, so it is safe to call from the script entry
    point, from the IDA plugin's init() (PLUGIN_PROC calls it once per database),
    and again after _shutdown() has stopped a previous run.

    Deliberately off the UI thread: binding never needs IDA's main thread, and a
    script that blocks it while waiting on sockets looks like a hung IDA.
    """
    global _starting
    if _starting or _server is not None:
        return
    _starting = True
    threading.Thread(target=_run, daemon=True, name="ida_bridge").start()


# --------------------------------------------------------------------------- #
# IDA plugin wrapper
#
# One file, two ways to use it:
#   * File -> Script file...   — the main() call at the bottom starts the bridge.
#   * IDA plugin (PLUGIN_PROC) — IDA imports the module when a database opens
#     (which also starts the bridge), calls init(), and calls term() when the
#     database closes. No Alt+F7 needed, and closing/reopening an IDB restarts it.
#
# Drop a loader into IDA's plugins directory that imports this file and returns
# IDABridgePlugin from PLUGIN_ENTRY(); see ida_bridge.md §3.
# --------------------------------------------------------------------------- #
class IDABridgePlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC      # load per database, unload with it
    comment = "HTTP bridge: drive IDA from another process (see ida_bridge.md)"
    help = ""
    wanted_name = "IDA Bridge"
    wanted_hotkey = "Ctrl-Shift-B"

    def init(self):
        try:
            main()                      # idempotent
            return ida_idaapi.PLUGIN_KEEP
        except Exception:
            log("plugin init failed:\n%s" % traceback.format_exc())
            return ida_idaapi.PLUGIN_SKIP

    def run(self, arg):
        if _port:
            text = "[ida_bridge] listening on http://127.0.0.1:%d/  (pid %d)\n" % (
                _port, os.getpid())
        else:
            text = "[ida_bridge] not listening (see the Output window)\n"
        try:
            import ida_kernwin
            ida_kernwin.msg(text)
        except Exception:
            log(text.strip())

    def term(self):
        _shutdown()


def PLUGIN_ENTRY():
    return IDABridgePlugin()


main()
