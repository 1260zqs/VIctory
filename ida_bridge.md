# `ida_bridge.py` — driving IDA Pro 8.3 from an external agent

An HTTP bridge that runs **inside** IDA Pro and lets an external process (agent, script,
curl, another notebook) read the currently-open database: decompile functions, walk
xrefs, dump bytes, search patterns, and run arbitrary IDAPython.

It was written to give an automated reverse-engineering assistant the same view of a
target that a human has when sitting in front of IDA — without needing a per-tool plugin,
MCP server, or GUI automation.

---

## 1. What it is / what it is not

| | |
|---|---|
| **Is** | A single-file IDAPython script that starts a loopback-only HTTP server on the first free port at or above `127.0.0.1:13337`, and reports the port it got. Every handler that touches IDA is marshalled onto its main thread with `idaapi.execute_sync(..., MFF_WRITE)`, so all analysis APIs are safe to call. It also drives IDA's debugger — registers, memory, threads, breakpoints, running and stepping (§7). |
| **Is not** | An MCP server. It speaks plain HTTP + JSON so any language can drive it. (Wrapping it in stdio/JSON-RPC is possible but not included.) |
| **Is not** | A sandbox. `POST /exec` executes arbitrary Python inside IDA with full privileges. |
| **Is not** | Multi-target. It serves whatever `.idb` is open in the IDA instance that loaded it. |

Two files:

```
ida_bridge.py     # load this inside IDA  (File -> Script file...)
idac.py           # optional CLI client, run from a normal shell
```

---

## 2. Requirements

- **IDA Pro 7.7 – 8.x** with IDAPython 3.x. Verified on **7.7.220118 (Python 3.8)** and
  on **8.3**. `ida_hexrays` must be licensed for `/decompile` to return pseudocode.
- The database must be **open and auto-analysis finished**. The bridge does not trigger
  analysis; it only queries.
- Python standard library only — no pip installs.

---

## 3. Installing / starting

1. Open the target in IDA and wait for *"The initial autoanalysis has been finished"*.
2. **File → Script file…** (`Alt+F7`) → select `ida_bridge.py`.
3. The Output window prints the port it actually got:

   ```
   [ida_bridge] listening on http://127.0.0.1:13337
   [ida_bridge] try: curl http://127.0.0.1:13337/status
   ```

Leave IDA open. The server runs on a daemon thread, so the UI stays responsive.

### The port is not fixed

`PORT` (13337) is only the **first candidate**. The script walks upwards — up to `PORT_SCAN`
(64) ports — and takes the first one it can bind **exclusively**, so a second IDA instance,
or any other program squatting on 13337, does not fight over it:

```
[ida_bridge] listening on http://127.0.0.1:13338
```

Two details keep that cheap:

- **Binding, not probing.** "Is this port free?" is answered by a bind attempt, which fails
  instantly, rather than by a connect, which on Windows waits for the whole timeout on a
  dead port (0.3 s × 64 ports ≈ 20 s — that was the "script hangs for ages" bug). The
  whole window costs ~2 ms.
- **Off the UI thread.** Stopping/binding happens on a daemon thread, so loading the script
  never freezes IDA, even if a port has to be retried.

`allow_reuse_address` is deliberately **off**: on Windows it sets `SO_REUSEADDR`, which
would let a second bind of a live port "succeed" and leave two listeners competing for it.
Without it a busy port fails immediately, which is exactly the signal needed here.

The real port is always discoverable:

```bash
curl http://127.0.0.1:13337/whoami      # {"ok":true,"port":13337,"pid":19692}
curl http://127.0.0.1:13338/status      # port, pid, and which executable is loaded
```

`/whoami` answers on whichever port you reached it on, so it works as a probe: 13337..13400
and every live bridge identifies itself. That is what `idac.py` does, concurrently (§5), so
you rarely need to care about the number.

### Request log

Every request is echoed to the Output window as one line — method, path, status, wall
time, response size:

```
[ida_bridge] listening on http://127.0.0.1:13337
[ida_bridge] GET /status -> 200  0.6 ms  218 B
[ida_bridge] GET /callees?ea=0x20c0 -> 200  4.1 ms  1304 B
[ida_bridge] POST /exec  [result = hex(idaapi.get_imagebase())] -> 200  0.2 ms  96 B
[ida_bridge] GET /func?ea=0xdead -> 500  [error]  0.3 ms  612 B
```

The last `LOG_KEEP` (500) lines are also kept in memory and served by `/log`, so an agent
can read back what it just did. `LOG_REQUESTS = False` at the top of the file stops the
echo to the Output window; the ring buffer keeps filling either way.

A client that vanishes mid-request is logged in the same breath and never produces a
traceback:

```
[ida_bridge] GET /status -> 200  0.0 ms  218 B
[ida_bridge] GET /status -> client went away (ConnectionResetError)
[ida_bridge] GET /decompile?ea=0x20c0 -> client closed the socket (ConnectionAbortedError)
```

### Restarting

Re-running the script is safe. The port the previous run bound is parked on the `idaapi`
module — which survives a script reload — so the new run finds the old listener with a
single `/whoami` probe instead of scanning the range. If that probe reports **our own pid**
it is a previous run in this same IDA: it gets `GET /shutdown`, the new run waits until the
port can be bound again, then takes it (normally 13337). Bridges of *other* IDA instances
report a different pid and are never touched — their ports simply fail to bind.

Measured on a Windows box: fresh load → answering in ~0.2 s, reload ~0.6 s, and falling
back to the next port ~0.02 s.

### Verifying

```bash
curl http://127.0.0.1:13337/whoami
# {"ok": true, "port": 13337, "pid": 19692}      # the port actually in use

curl http://127.0.0.1:13337/status
# {
#  "port": 13337,
#  "pid": 19692,
#  "input": "D:\\Games\\...\\game_scarlett_master.xex",   # what IDA has loaded
#  "idb":   "D:\\Games\\...\\game_scarlett_master.xex.i64",
#  "imagebase": "0x140000000",
#  "funcs": 433907,
#  "segments": 11,
#  "hexrays": true
# }
```

### Stopping

```bash
curl http://127.0.0.1:13337/shutdown
```

or just close IDA. Closing IDA always releases the port.

---

## 4. Endpoint reference

All endpoints are `GET` except `/exec` and the `/dbg/*` actions (§7). All return JSON.
Unexpected handler failures come back as `{"ok": false, "error": "<traceback>"}` with HTTP
500; expected conditions (no debugger session, unmapped address, no free port) come back as
`{"ok": false, "error": "<reason>"}` with HTTP 200.

| Method | Path | Query / body | Returns |
|---|---|---|---|
| GET | `/ping` | — | `{"ok":true,"pong":true}` |
| GET | `/whoami` | — | `{ok,port,pid}` — no IDA API touched, so it answers even while the UI is busy |
| GET | `/status` | — | `{port,pid,input,idb,imagebase,funcs,segments,hexrays}`; `input` is the loaded executable |
| GET | `/segments` | — | `[{name,start,end,size}, …]` |
| GET | `/func` | `ea` | `{found,name,start,end,size,flags,incoming_calls}` |
| GET | `/decompile` | `ea` | `{ok,name,start,end,pseudocode}` |
| GET | `/disasm` | `ea`, `n` (default 40) | list of `"addr  bytes  text"` strings |
| GET | `/xrefs` | `ea`, `dir=to\|from` | list of `{ea,name,type,in_func,func_name}` |
| GET | `/callers` | `ea` | `{ok,target,name,callers:[{call_site,caller,caller_name}]}` |
| GET | `/callees` | `ea` | `{ok,target,name,callees:[{call_site,target,target_name}]}` |
| GET | `/names` | `like`, `limit` (default 50) | `[{ea,name}]` |
| GET | `/bytes` | `ea`, `n` (default 64) | `{ok,ea,hex,len}` |
| GET | `/cstr` | `ea` | `{ok,ea,string}` |
| GET | `/search` | `pat` (hex, spaces optional), `limit` (default 16) | `{ok,pattern,hits:[{ea,in_func,func_name}]}` |
| GET | `/log` | `limit` (default 50) | `{ok,lines:[str]}`, oldest first |
| GET | `/dbg` | — | debugger session state, threads, breakpoint count |
| GET | `/dbg/regs` `/dbg/reg` `/dbg/mem` `/dbg/bpts` `/dbg/stack` `/dbg/options` | see §7 | debugger reads |
| POST | `/dbg/*` | see §7 | debugger control: start, attach, continue, step, runto, breakpoints, registers, memory |
| POST | `/exec` | Python source in body | `{ok,result:{<varname>: "<repr>", …}}` |
| GET | `/shutdown` | — | `{ok,stopping:true}` |

### `/disasm` line format

```
0000000000002142  E8 61 25 00 00                    call    ??0?$basic_string@_WU…
```

`addr` · `bytes` (padded to 32 columns) · `text`. The padding is on the byte column, so a
long demangled operand never runs into the bytes.

### `/callees` reports calls only

Only genuine call xrefs (`fl_CN`/`fl_CF`) are listed. Fall-through refs — the next
instruction, which `get_first_cref_from()` also returns — and plain jumps are filtered
out, so the list no longer claims `0x20c0 -> 0x20c5` (its own next instruction) is a call.

Not listed: **indirect** calls (`call [rax+3F8h]`, `call [reg]`) — they have no code
xref at all. Search their encoding instead, see §6.2. Tail calls (`jmp other_func`) are
non-call xrefs too, so they are absent as well.

### `/search` scans segments, not a fixed range

The pattern is searched segment by segment over the database's own segment table,
reading 1 MiB chunks with `idc.get_bytes()` and `bytes.find()`. Coverage therefore tracks
whatever is actually in the database — no hardcoded span.

`idaapi.find_binary()` is deliberately not used: on IDA 7.7 it silently skips matches at
or next to the start address it is given. Concretely, with the same 6-byte pattern present
at `0x20c0` and `0x2620`:

```
find_binary(0x20c0, 0x3650, pat) -> 0x2620    # 0x20c0 missed
find_binary(0x261f, 0x3650, pat) -> none      # 0x2620 missed
find_binary(0x20c0, 0x20e0, pat) -> none      # both missed
```

### Address arguments

`ea` accepts either a hex address (`0x1411a89c0`, with or without `0x`) or a symbol name
resolved through `idc.get_name_ea_simple`. Anything that fails to parse becomes `None` and
the handler reports the failure rather than guessing.

### `/exec` semantics

The body is compiled and executed with these names pre-bound:

```python
idaapi  idc  ida_funcs  ida_bytes  ida_hexrays  ida_xref  ida_name
```

It runs on IDA's main thread. **Everything you assign at module level of that snippet is
returned**, `repr()`-ed, minus dunders:

```bash
curl -X POST http://127.0.0.1:13337/exec -d 'result = hex(idaapi.get_imagebase())'
# {"ok": true, "result": {"result": "'0x140000000'"}}
```

`import` works inside the snippet (`import idautils`, `import struct`, …).

#### Gotcha: scanner/disassembly also lands in the returned dict

Everything you assign shows up in the response, including loop variables. Keep snippets
tidy or accept the noise.

#### Gotcha: list comprehensions cannot see `exec` locals

This is a plain Python scoping rule, not a bridge bug, but it bites when writing search
snippets. This fails:

```python
def inrpf(a): ...
rows = [hex(a) for a in hits if inrpf(a)]     # NameError: inrpf is not defined
```

Use an explicit loop instead:

```python
rows = []
for a in hits:
    if inrpf(a):
        rows.append(hex(a))
```

---

## 5. `idac.py` — CLI client

A thin wrapper so shell calls stay short. Exit code is non-zero on transport or server
error, so it chains safely in scripts.

It needs **Python 3**. On Windows `python` on `PATH` is often still 2.x, where this fails
with `SyntaxError: Non-ASCII character '\xe2'` — use the launcher (`py -3.8`) or `python3`.

Because the bridge picks its own port, the client discovers it: it probes
`127.0.0.1:13337..13400` with `/whoami` **concurrently** (~0.3 s — probing one port after
another took ~20 s, because a dead port costs a full timeout) and uses the single bridge it
finds. With more than one IDA bridged, it refuses to guess and lists what it saw instead:

```bash
py -3.8 idac.py status                        # auto-discover
py -3.8 idac.py --exe game_scarlett status    # pick the bridge whose input matches
py -3.8 idac.py --port 13338 status           # talk to one specific port
set IDA_BRIDGE_PORT=13338                     # or pin it in the environment
```

```
python3 idac.py status
python3 idac.py segments
python3 idac.py func       0x1411a89c0
python3 idac.py decompile  0x1411a89c0
python3 idac.py disasm     0x1411a89c0 30
python3 idac.py callers    0x1411a89c0
python3 idac.py callees    0x1411a89c0
python3 idac.py xrefs      0x146301d40 from
python3 idac.py names      rpf 40
python3 idac.py search     FF9050080000 20
python3 idac.py bytes      0x146301d40 128
python3 idac.py cstr       0x14678d1bb
python3 idac.py exec       "result = hex(idaapi.get_imagebase())"
python3 idac.py log        30
python3 idac.py shutdown

python3 idac.py dbg                           # debugger state + threads
python3 idac.py regs       0                  # registers of thread 0 / current
python3 idac.py bpts                          # breakpoint list
python3 idac.py dbgcmd     continue           # any /dbg action, key=value params
python3 idac.py dbgcmd     step kind=over
python3 idac.py dbgcmd     bpt/add ea=0x401000 type=exec
python3 idac.py dbgcmd     wait timeout_ms=3000
```

`decompile`, `callers`, `callees`, `disasm`, `xrefs`, `names`, `search`, `bytes`, `cstr`,
`log`, `dbg`, `regs`, `bpts` print human-readable text and exit 0. The rest — `dbgcmd`
included, since debugger replies vary — print the raw JSON envelope.

Exit codes: `0` ok · `1` server said `ok:false` · `2` bad usage (`--exe` matched nothing,
or several bridges found and neither `--port` nor `--exe` was given) · `3` no bridge found
at all (script not loaded, or listening outside the scanned range).

---

## 6. Workflow examples

### 6.1 Decompile a function and follow its callees

```bash
python3 idac.py decompile 0x1411a89c0
python3 idac.py callees   0x1411a89c0
```

### 6.2 Find every call site of a virtual slot

Virtual calls like `call qword ptr [rax+3F8h]` are invisible to normal xrefs. Search the
encoding directly — and **remember both displacement forms**:

```bash
# disp32 form: FF 90 F8 03 00 00   (call [rax+3F8h])
python3 idac.py search FF90F8030000  40

# disp8 form:  FF 50 08             (call [rax+8h])
python3 idac.py search FF5008        40
```

A frequent miss is searching only one form. Real binaries use both.

### 6.3 Find which function references an address (vtable discovery)

```bash
python3 idac.py xrefs 0x146301d40 to
```

If the slot is filled at runtime the xref list will be empty — that itself is the finding.

### 6.4 Sweep a struct with one request

Use `/exec` when the question needs a loop:

```bash
python3 idac.py exec @'
import struct
vt = 0x1462FD480
rows = []
for slot in range(0x3C0, 0x420, 8):
    p = ida_bytes.get_qword(vt + slot)
    f = ida_funcs.get_func(p) if p else None
    rows.append("%#06x  %s  %s" % (slot, hex(p) if p else "-",
                                   ida_funcs.get_func_name(p) if f else "-"))
result = rows
'@
```

(That `@'…'@` is a PowerShell here-string; bash uses `<<'EOF'`.)

### 6.5 Confirm a recursive function (e.g. a tree walker)

```bash
python3 idac.py exec @'
import idautils
BAD = 0xFFFFFFFFFFFFFFFF
res = []
for f_ea in idautils.Functions(0x140FC0000, 0x140FC3000):
    f = ida_funcs.get_func(f_ea)
    for ea in idautils.Heads(f.start_ea, f.end_ea):
        x = ida_xref.get_first_cref_from(ea)
        while x != BAD:
            if x == f.start_ea:
                res.append(hex(f.start_ea)); break
            x = ida_xref.get_next_cref_from(ea, x)
        else:
            continue
        break
result = res
'@
```

### 6.6 Watch what an agent is doing

```bash
python3 idac.py log 20
```

Prints the newest 20 requests as they were handled — method, path, status, wall time,
response size — without leaving the shell. The same lines appear in IDA's Output window.

---

## 7. Debugger control

Besides the database, the bridge drives IDA's **debugger**: read a stopped target's
registers, memory and stack, walk threads, set and toggle breakpoints, and run/step it. It
goes through the same `ida_dbg` API the GUI uses, so whatever IDA can debug, this can
debug.

A session has to exist first: either **Debugger → Start process** in the GUI, or
`POST /dbg/start?path=…` (verified end to end below). Without one, every debug endpoint
answers

```json
{"ok": false, "error": "no debugger session (Debugger -> Start process, or POST /dbg/start)"}
```

### Reads

| Endpoint | Returns |
|---|---|
| `GET /dbg` | `{debugger_on,state,state_name,can_query,busy,current_thread,threads,bpt_count,path,args,pid}` |
| `GET /dbg/options` | Debugger → Process options: `{path,args,sdir,env,pid}` |
| `GET /dbg/regs?tid=` | `{ok,tid,count,regs:{<name>:"0x…"}}` — every register of a thread |
| `GET /dbg/reg?name=eax` | `{ok,name,value,tid}` |
| `GET /dbg/mem?ea=0x…&n=64` | `{ok,ea,len,hex}` — memory of the debuggee |
| `GET /dbg/bpts` | `{ok,count,bpts:[{ea,name,type,size,enabled,condition}]}` |
| `GET /dbg/stack?tid=` | `{ok,tid,count,frames:[{level,call_ea,func_ea,func_name,fp}]}` |

`state_name` is `notask` (no process), `suspended` (stopped — safe to read) or `run`. A
`tid` of `0` means "whatever thread the debugger has selected".

### Control

Every one of these is `POST`. Step/run/continue use IDA's synchronous debugger API, so they
return once the target has stopped again — that is what makes "step, then read registers"
work.

| Endpoint | Effect |
|---|---|
| `/dbg/continue` · `/dbg/suspend` | run / freeze |
| `/dbg/step?kind=into\|over\|out` | one instruction / one call / until return |
| `/dbg/runto?ea=0x…` | run until that address |
| `/dbg/bpt/add?ea=&type=&size=` | `type`: `exec`/`default` (software exec bpt), `read`, `write`, `rw`, `soft`, `hw` (hardware) |
| `/dbg/bpt/del?ea=` · `/dbg/bpt/enable?ea=&on=0\|1` | remove / toggle |
| `/dbg/thread?tid=` | select the current thread |
| `/dbg/reg/set?name=&value=` · `/dbg/write?ea=&hex=` | poke a register / memory |
| `/dbg/wait?timeout_ms=` | pump the debugger request queue (`run_requests()`) and report state |
| `/dbg/exit` · `/dbg/detach` | kill the target / detach and leave it running |
| `/dbg/start?path=&args=&sdir=` | launch the database's target (`path` mandatory) |
| `/dbg/attach?pid=` | attach to a running process |

`/dbg/start` and `/dbg/attach` sit behind `ALLOW_DBG_LAUNCH` (default **`True`**). Launching
the database's own target works; attaching to a *foreign* process is the unreliable part —
see the notes below.

### Verified end to end (IDA 8.3 / Python 3.8)

The whole flow below was driven **entirely through the bridge** (no GUI clicks), against
`AutoClicker.exe` loaded in the database:

| Step | Result |
|---|---|
| `POST /dbg/bpt/add?ea=0x404830&type=default` — set a breakpoint on `_WinMain@16` **before any session existed** | `bpt_count: 1`, `hardware: false` (software exec bpt) |
| `POST /dbg/start?path=D:\Program Files\AutoClicker.exe` | `ok:true`, `debugger_plugin_loaded:true`; the target stops at **ntdll's initial breakpoint** (Windows behaviour, `eip=0x77da57c0`) |
| `POST /dbg/continue` | runs on and stops at **`eip = 0x404830` = `_WinMain@16`** |
| `GET /dbg/regs` | `eax=0x400000 ecx=0 edx=0x19ff14 ebx=0 esi=0x5c49e2 edi=0x40469e ebp=0x19ff70 esp=0x19fed8 eip=0x404830` |
| `GET /dbg/mem?ea=<esp+4>&n=20` | `hInstance=0x00400000` (the exe's ImageBase), `hPrevInstance=0x0`, `lpCmdLine=0x005C49E2`, `nShowCmd=0xA` (`SW_SHOWDEFAULT`) |
| `GET /dbg/mem?ea=0x5C49E2` | first byte `00` → **empty command line** (`/dbg/mem` reads the debuggee's memory, the rest of the buffer was `0xAB`/`0xFEEEFEEE` fill) |
| `POST /dbg/exit` | `ok:true`, then `/dbg` → `debugger_on:false`, `state:notask`, **no leftover process** |

Additional endpoint results on that session:

| Endpoint | Result |
|---|---|
| `/dbg` | `state_name: suspended`, threads with real names (`AutoClicker.exe` + 3), `bpt_count: 2` |
| `/dbg/mem?ea=0x404830&n=8` | `ff742410ff742410` — identical to `/bytes` from the database |
| `/dbg/bpts` | `0x404830 _WinMain@16`, `0x404848 ?AfxInitialize@@YGHHK@Z` |
| `/dbg/stack` | frame 0 = current DLL address, frame 1 = `0x404763` in `start` |
| `/dbg/bpt/add` → `enable` → `del` | count 2 → 3 → 2, `enabled` toggles |
| `/dbg/step?kind=into` | `eip 0x404848 → 0x40457c` (into the `call`), `esp −4` |

Three things worth knowing:

- **The `state` in a reply is read before IDA's event loop runs**, so a step/run_to reply can
  still say `run`, and polling right after `start` can briefly say `notask`. `GET /dbg` a
  moment later is authoritative; the step reply carries a `note` saying so. Poll with a
  short delay rather than trusting the first answer.
- **A freshly started target first stops at ntdll's initial breakpoint**, not at your
  breakpoint. That is the Windows debugger's DoDebuggerBreak, so one `/dbg/continue` is
  expected before `eip` reaches `_WinMain`.
- **`type=exec` means a software exec breakpoint** (`BPT_EXEC|BPT_SOFT` = 12). A bare
  `BPT_EXEC` is a *hardware* breakpoint: it was set successfully but never got hit on this
  target, which looked like "the breakpoint is ignored". Use `type=default`/`exec`, and
  `hw` only when you really want a debug-register slot.

The one path that stayed unreliable is **starting a different exe than the database**
(`cmd.exe`, `notepad.exe`, `ping.exe` were tried): the process ran without ever stopping,
`suspend_process()` had no effect, and the half-attached session could not be ended by API.
Launching the database's own target is unaffected.

### IDA 8.x API quirks this code works around

- `idc.get_reg_name` does not exist; `idaapi.get_reg_name(reg, width, reghi=-1)` needs the
  width. Values come from `regval_t.ival` (`pyval` is a method that takes a dtype).
- `get_reg_vals()`'s index order does not line up with the register names (on x86 `esp` and
  `er8` came back shifted), so values are fetched by name with `get_reg_val()`.
- `bpt_t.ea` is stale (reads back as 0/1). Breakpoints created by IDA carry `'$<hex>'` in
  `bpt.loc.symbol`; ones added through `add_bpt()` have an empty symbol with a valid
  `bpt.loc.ea()`. `/dbg/bpts` handles both shapes.
- `wait_for_next_event()` raises *Internal error 40202* from a script context, so
  `/dbg/wait` pumps pending requests with `run_requests()` instead.
- `request_exit_process()`/`request_detach_process()` only enqueue, so `/dbg/exit` and
  `/dbg/detach` call the synchronous `exit_process()`/`detach_process()` — otherwise the
  target survived the request.
- Breakpoint management does **not** require a session (like the GUI), so a breakpoint can
  be planted before `start`; only reads and flow control need a live target.

### The step → look → step loop

With a session stopped in the GUI:

```bash
python3 idac.py dbg                            # state, threads, bpt count
python3 idac.py regs 0                         # all registers of thread 0
python3 idac.py dbgcmd step kind=over          # runs and returns when it stopped again
python3 idac.py regs 0                         # where did it land
python3 idac.py disasm 0x401005 20             # that eip
```

`/dbg/wait` only pumps pending requests; if the target is running and not stopping, poll
`GET /dbg` — `state_name` tells you whether it is `run` or `suspended`.

### What it does not do

- **No background polling.** Nothing watches the target between requests; `continue` and
  never wait, and you simply have to ask `GET /dbg` later.
- **No expression evaluation.** This build's `idc` has no `eval_expr`; read registers and
  memory instead, or use `/exec`.
- **No breakpoint conditions.** `condition` is shown by `/dbg/bpts` but cannot be set yet —
  `request_add_bpt()` takes address/size/type only.
- **`/dbg/mem` reads via `idc.get_bytes()`**, which IDA serves from debuggee memory during a
  session; addresses `is_debugger_memory()` calls unmapped are refused.
- **Register names come from `idc.get_reg_name(index)`**, so they follow the loaded
  processor module instead of a hardcoded x86 list.

### Safety

- `ALLOW_DBG_LAUNCH` (top of the file) gates `/dbg/start` and `/dbg/attach` and defaults to
  **`True`**. Launching the database's own target was verified end to end; attaching to a
  foreign process is the unreliable part. Set it to `False` to keep the bridge read-only
  with respect to processes.
- `/dbg/start` requires an explicit `path`; it never falls back to the loaded executable on
  its own, because that file may do real work the moment it runs (an auto-clicker, an
  installer, a game).
- Anything that can reach the port can step, patch and kill a debugged process — see §9.

---

## 8. Limitations

- **One database, one instance.** The bridge serves the `.idb` currently open. To switch
  targets, open the other target and reload the script. Several IDA instances can be
  bridged at once — each takes the next free port from 13337, so `/status` on the wrong
  one tells you which executable it actually serves.
- **No analysis triggering.** Newly undecoded regions are not auto-analysed. Define the
  function or disassemble it in the UI first, or use `/exec` with `idc.create_insn` /
  `ida_funcs.add_func`.
- **`/decompile` needs Hex-Rays.** Without the decompiler licence, it returns
  `{"ok": false, "error": "Hex-Rays decompiler not available"}`.
- **Large results are not paginated.** `/decompile` on a 4000-byte function can return tens
  of thousands of characters. Trim on the client side, or use `grep`/`Select-String`.
- **No concurrency control.** Two simultaneous `/exec` calls are serialised by
  `execute_sync`, but nothing prevents interleaving. Keep heavy sweeps sequential.
- **`/callees` sees direct calls only.** Indirect calls (`call [rax+3F8h]`) carry no code
  xref and tail calls (`jmp other_func`) are not call xrefs, so neither appears. Use
  `/search` on the call encoding for virtual dispatch (§6.2).
- **`/search` scans every mapped byte.** It walks the whole segment table in 1 MiB chunks,
  so cost scales with database size, not with `limit`. On a 180 MB image expect a few
  seconds per pattern. Matches inside a segment chunk that `idc.get_bytes()` cannot read
  are skipped.
- **`/log` is a ring buffer.** Only the last `LOG_KEEP` (500) lines survive, and it is
  process-local: reloading the script starts it empty.
- **Timeouts.** Long requests block until done; the client (`idac.py`) waits up to 600 s.
  A pattern sweep over a whole large image can exceed that — narrow the pattern or split
  the work across `/exec` calls.
- **`/status` counts** come from IDA's inventory; they are not comparable across IDA
  versions or different analysis settings.
- **Debugger endpoints need both `ida_dbg` (IDA 7.4+) and a live session.** Without either
  they answer `{"ok": false, "error": …}` instead of failing. Nothing polls the target in
  the background: it only moves when a request asks it to.
- **No breakpoint conditions, no expression evaluation.** `/dbg/bpts` shows `condition`
  read-only and `request_add_bpt()` takes address/size/type only; this build's `idc` has no
  `eval_expr`, so use registers/memory or `/exec` (see §7).
- **`/dbg/regs` naming follows the processor module** through `idaapi.get_reg_name(index, width)`;
  indices it cannot name show up as `reg_<index>`.
- **Launching works for the loaded target, not for foreign processes.** `POST /dbg/start`
  on the database's own exe ran to completion (see §7), but starting a *different* exe made
  the target run without stopping and left the debugger state unrecoverable through the
  API. `/dbg/start` also insists on an explicit `path`; it will not launch the file that is
  currently loaded on its own.

---

## 9. Security

- Binds to **`127.0.0.1` only**. Nothing leaves the machine.
- **No authentication.** Any local process that can reach the bridge port (13337 upwards)
  gets full IDAPython execution via `/exec`. Treat the bridge as equivalent to handing out
  a shell inside IDA. Do not run it on a shared host you do not control.
- `/exec` can read and write files, launch processes, and modify the database. Prefer the
  named endpoints for read-only work; reserve `/exec` for cases the named endpoints cannot
  express.
- The debugger endpoints reach further than the database: `/dbg/start` and `/dbg/attach`
  spawn or seize processes, `/dbg/write` and `/dbg/reg/set` modify a live one, and
  `/dbg/exit` kills it. Set `ALLOW_DBG_LAUNCH = False` if the bridge should not touch
  processes at all.
- Shut it down (`/shutdown`) when finished.

---

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `no IDA bridge is listening on 127.0.0.1:13337..13400` | Nothing answered `/whoami` in the scanned range. Load the script in IDA, or the instance runs above 13400 — raise `PORT_SCAN` (server) / `PORT_SCAN` (client) to match. |
| `several IDA bridges are listening` | More than one IDA is bridged. The list shows each port, pid and loaded executable: pick with `--exe <substring>` or `--port <n>`. |
| `transport error: [WinError 10061]` | The port you forced with `--port` is not listening. Drop the flag to let the client discover the bridge. |
| `transport error` after it worked earlier | IDA was restarted, or the script was reloaded onto a different port. Re-run `idac.py` (it rediscovers) instead of reusing a stale port. |
| `500` with `"error": "Traceback …"` | The handler raised. The response contains the full traceback — read it; it is not truncated. |
| `{"ok": false, "error": "no function at 0x…"}` | Address is not inside a defined function. Disassemble/define it first, or pass an address you know is a function start. |
| `{"ok": false, "error": "Hex-Rays decompiler not available"}` | `ida_hexrays.init_hexrays_plugin()` returned false — decompiler not present/licensed. |
| `{"ok": false, "error": "bad hex: …"}` from `/search` | Odd number of digits or a non-hex character. Spaces are optional, `FF90F8030000` and `FF 90 F8 03 00 00` are the same pattern. |
| Requests hang | IDA is busy (modal dialog, long analysis). The request waits for the main thread. Close the dialog. |
| `NameError` inside `/exec` | See §4 — list comprehensions cannot see `exec` locals; use explicit loops. |
| `[ida_bridge] … client went away` / `client closed the socket` | Normal, not an error: the caller timed out, was interrupted, or dropped a keep-alive connection. The bridge keeps serving. |
| `[ida_bridge] cannot bind any port in 13337..13400` | Nothing was free in the scanned range (64 ports by default). Close stale instances, raise `PORT`/`PORT_SCAN`, and keep `BASE_PORT`/`PORT_SCAN` in `idac.py` in step. |
| `[ida_bridge] WARNING: port N is still busy after /shutdown` | The previous instance did not release its socket in time (older build, or a client still holding a connection). The new run simply takes the next free port; `/whoami` tells you which one it is. |
| `SyntaxError: Non-ASCII character '\xe2'` from `idac.py` | You are on Python 2. Run it as `py -3.8 idac.py …` or `python3 idac.py …` (§5). |
| `no debugger session` from any `/dbg` endpoint | No process is being debugged. Start one in the GUI (Debugger → Start process / Attach to process) or `POST /dbg/start?path=…`. |
| `/dbg/start` → `missing ?path=` | Deliberate: the bridge never falls back to the loaded executable, which might do real work when run (§7 Safety). |
| `/dbg/wait` returns but the target did not stop | It hit `timeout_ms` (ceiling `DBG_WAIT_MAX` = 60 s). Check `GET /dbg` — `state_name` is still `run`. |
| `/dbg/regs` shows `reg_0`, `reg_1`, … | `idc.get_reg_name(index)` returned nothing for those registers on this processor module. |
| `/dbg/mem` → `… is not mapped in the debugged process` | `is_debugger_memory()` refused the address: wrong address, or no session. |
| `no debugger plugin could be loaded through load_debugger()` in the Output window | This IDA install will not take a debugger from Python. Create the session in the GUI instead; reads and stepping then work. |
| `state_name` stays `run` and every register read returns `false` | The target is executing, not stopped. A GUI session stops at its breakpoint; a script-side attach on this build does not — see §7 "Verified on a live session". |
| IDA stuck "debugging" a process that no longer exists, `exit_process()` → `False`, and the target cannot be killed | Known outcome of a script-side attach on this build. Restart IDA. |

---

## 11. Extending it

The file is deliberately one layer, one class:

- **Add an endpoint**: write `op_*()` returning a JSON-able value and register it in the
  `ROUTES` dict. Wrap it in `on_main(...)` if it touches IDA's analysis state — `/log`
  does not, so it is called straight from the handler thread.
- **Add a POST endpoint**: extend `do_POST` alongside the `/exec` branch.
- **Change the port range**: edit `PORT` / `PORT_SCAN` at the top, and `BASE_PORT` /
  `PORT_SCAN` in `idac.py` so the client scans the same window. Ports occupied by other
  programs are skipped automatically, so nothing else needs to know.
- **Log something**: call `log("…")` from anywhere in the file. The line lands in IDA's
  Output window and in the ring buffer behind `/log`. `LOG_REQUESTS` controls the echo,
  `LOG_KEEP` the buffer depth.
- **Wrap as MCP**: everything an MCP tool needs is already a pure function — the
  `op_*` functions are stateless and return dicts, so a JSON-RPC shim only has to map
  method names to them.
