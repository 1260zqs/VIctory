# VIctory

Runs Grand Theft Auto VI (Xbox Series X|S) natively on Windows, from files
the user supplies.

The title's x86-64 code runs unchanged inside our process; VIctory supplies
the platform underneath it and converts the title's data, ahead of time where
it can (shaders and pipelines too, see Getting started) and on first use
otherwise. See [docs/architecture.md](docs/architecture.md).

## Status (2026-11-24)

**Not playable yet.** The title boots, runs its menus at its own 30 fps,
loads the world and shows it: slowly, and with rendering defects.

| Stage | State |
|-------|-------|
| Boot, first-boot screens (accessibility, language, settings, legal) | works, 30 fps |
| Intro video with sound | works |
| Start screen, profile and saves | works |
| Loading into the world (about 50 s) | works |
| The world (first mission's intro) | drawn and shown: streets, buildings, vehicles, characters, the title card and credits; 1-2 s per frame. Surfaces are unlit, a band of distant geometry is missing, characters come out broken in some shots |

Tested on one machine: Windows 11, AMD RX 6700 XT.

> **Warning.** Entering the world on a real GPU has hung it in earlier
> builds, and Windows then resets the display driver (every monitor goes
> black for a moment). The latest runs did not, but it is not ruled out; a
> run can also end on a GPU fault (`crashes.log`). A diagnostics build with
> `VICTORY_D3D12_WARP=1` renders on the software adapter instead (too slow
> to reach the world in minutes).

What each part does today and what it still needs:

| Subsystem | Today | Needs |
|-----------|-------|-------|
| Loader | Runs the title's executable and its DLLs in our process; crash reports name the faulting code and are kept in `crashes.log` | – |
| Runtime services | One signed-in offline user, licences, packages, saves that survive a kill at any step, text entry dialog | Speech is silent; the dialog and relaunch are untested live |
| Network | Offline by design: the title cannot reach the network | – |
| Files and streaming | Archives and streamed data read, zlib and BCPack decoded in parallel | Loading is limited by writes into title memory |
| Input | XInput pads, keyboard, keyboard stand-in pad | Trigger rumble |
| Audio | Menu, video and loading sound; XMA voices and Opus streams decode | Reverb is silent; Opus results unverified against the title |
| GPU: menus | Draws, compute and presentation on host D3D12; only changed title memory is copied | Frame pacing drifts on one screen in release builds |
| GPU: world | The scene is drawn and presented: mesh pipelines, indirect execution, views the shaders pick from the heap themselves, title memory read by address (ray-tracing structures), depth written from compute, pipelines pre-built or made by worker threads and kept on disk | Lighting (surfaces are unlit) and some missing geometry; frames take 1-2 s; draws of untranslated shaders are dropped; real queries, depth bounds, HDR and scaling are missing |
| Shaders | Console GPU code recompiled to DXIL, ahead of time (`translate --cache`) or at first use, cached on disk. Menus: all. World: mesh 8,765 of 8,765, vertex/pixel 12,550 of 12,592, compute 2,579 of 2,637 | Merged geometry stages (195 programs) and about 100 others; fused multiply-adds follow the host GPU; some compute programs need a GPU with 64-lane waves |
| Textures | Console tiled layouts and detiling for the modes the title uses | Render-target metadata planes |
| Series S mode | Runs through the menus to the loading screen | The world, as above |

## Getting started

Requirements: Windows 10/11 x64, a CPU with AVX2, a Direct3D 12 GPU with
shader model 6.6 (and mesh shaders for the world), Rust (pinned in
`rust-toolchain.toml`).

To install Rust, use rustup (`winget install --id Rustlang.Rustup -e`, or
the installer from https://rustup.rs). The first `cargo` command in this
repository then fetches the pinned toolchain. Building needs the MSVC C++
build tools: Visual Studio or its Build Tools with the "Desktop development
with C++" workload.

The title also needs several GiB of available Windows commit at startup.
Check **Committed** under **Task Manager → Performance → Memory**. If
`crashes.log` reports Windows error 1455, close other applications or increase
the Windows paging file size, then retry.

```powershell
cargo xtask install-hooks                # asset-policy check on every commit
copy victory.example.toml victory.toml   # then set your paths (outside the repo)
cargo test --workspace                   # needs no game data
cargo run -p victory -- config           # check your paths
```

Run the title:

```powershell
cargo build --release -p victory
target\release\victory.exe translate --cache --pipelines <game dir>\shaders.rpf <game dir>\<the title's exe> <game dir>\XboxBvhBuilder.dll <game dir>\amd_fidelityfx_upscaler_xbox.dll
target\release\victory.exe run <game dir>\<the title's exe> --execute
```

The `translate --cache` step (minutes; again after a change of the shader
translator) translates every shader the title can ask for into the cache
(about 1.3 GB), so a run does not translate them while it plays; without it
they are translated at first use, and their draws wait. With `--pipelines`
it then makes every pipeline in the title's shader pack (inside
`shaders.rpf`) into the host pipeline library (about 27,000 pipelines, 4 MB;
some 20 minutes on 16 threads, most of it the 2,700 compute ones), so a run
compiles none of those either; the library belongs to the GPU and driver it
was made on. Run again, it skips what is there in seconds; stopped
early, it keeps what it made.

Upscaling (Series S mode): the title upscales with AMD FidelityFX. To run
it with the PC build on your GPU instead of the console build, get the
[FidelityFX SDK](https://github.com/GPUOpen-LibrariesAndSDKs/FidelityFX-SDK)
and point `VICTORY_FIDELITYFX_DIR` (or `[paths].fidelityfx_dir`) at its
`Kits/FidelityFX/signedbin` folder, which holds
`amd_fidelityfx_upscaler_dx12.dll`. Without it, or if that DLL offers no
upscaler for your GPU (the log says so), the title's own DLLs run.

The window caption shows the framerate. Saves, settings and `crashes.log`
are kept under the data folder (default `%LOCALAPPDATA%\victory\data`), derived
data under the cache folder.

Set `VICTORY_WINDOW_MAX=1920x1080` before launching to limit the title's
top-level window to that bounding box. Smaller windows keep their size,
larger windows keep their proportions, and the monitor's work area still
limits them. This scales the displayed image; it does not change the
console render resolution or the swap-chain buffers. With the variable
unset, window sizing is unchanged.

Input: XInput pads. With none connected the keyboard is a pad while the
title's window has focus:

| Keys | Pad |
|------|-----|
| W A S D / I J K L | left / right stick |
| arrows | D-pad |
| Enter, Backspace, X, Y | A, B, X, Y |
| Q / E, Z / C | shoulders, triggers |
| F / H | stick clicks |
| Esc, Tab | Menu, View |

## Commands

```
victory inspect <exe|dll> [--imports] [--exports]
victory census [paths...] [--missing] [--strict]
victory lib-exports <import.lib> [--list]
victory shader-info [paths...] [--verbose] [--disasm] [--effects]
victory translate [paths...] [--validate] [--pipelines] [--list] [--jobs N]
victory translate [paths...] --cache [--pipelines] [--jobs N]
victory run <exe> [--execute] [--debugger[=PORT]]
            [--unimplemented trap|zero] [--strict]
            [--console series-x|series-s] [-- <title arguments>]
victory config
```

Logging: `VICTORY_LOG=victory_loader=trace,info` (a release build logs
info and above).

### Windows shader-test validator

The shader tests use `dxil.dll` to validate Shader Model 6.6 containers.
An older Windows SDK validator can load successfully but reject them with
`Unknown shader model 'ps_6_6'`. If this happens, use a current x64 validator
from [Microsoft's DirectX Shader Compiler releases](https://github.com/microsoft/DirectXShaderCompiler/releases)
or a current Windows SDK. Set its path for the test session:

```powershell
$env:VICTORY_DXIL = 'C:\tools\dxc\bin\x64\dxil.dll'
cargo test -p victory-shader --lib --locked -- --test-threads=1
```

Without this override, the validator loader selects the newest installed
Windows SDK's `bin/<version>/x64/dxil.dll`, then falls back to the DLL search
path when no SDK copy is found. This is a test/offline-validation dependency;
the translated shaders do not require it at runtime.

## Debugging

VIctory includes an in-process x64 debugger in regular release builds. Start the
title with the debugger enabled:

```powershell
target\release\victory.exe run <game dir>\<the title's exe> --execute --debugger
```

Then open **http://127.0.0.1:17890**. Override the port with
`--debugger=PORT`. The HTTP listener binds to loopback only.

### First stop and execution control

The debugger installs a software breakpoint at the title entry point before
execution starts. The process should stop there automatically. Use **Resume**
to continue, **Pause** to interrupt execution, and **Step** to execute one
instruction from a supported instruction breakpoint. A breakpoint hit restores
the original instruction byte, executes that instruction, then rearms the
breakpoint.

Use the Breakpoints panel to add or remove software breakpoints. Use **Run to**
to resume until a specified address. Run-to is asynchronous: the request
returns after execution resumes, and the debugger UI waits for the next stop.

### Addresses, registers and call stack

Addresses inside the title image use IDA virtual-address space. The default
preferred image base for this title is `0x140000000`; the dashboard also shows
the actual runtime image base and the signed rebase delta
(`IDA base - runtime base`). You can paste an IDA EA into breakpoint,
disassembly or memory controls. Addresses outside the title image, such as
host DLLs and thread stacks, remain native process virtual addresses.

When execution stops, the dashboard selects the stopped thread and refreshes
its registers and call stack. Select a stack frame to inspect its address in
the Disassembly panel. The stack includes module-relative locations where
available; symbol names are not guaranteed.

### Disassembly and memory

The Disassembly panel follows the current stop by default. Enter an IDA or
native address and press **Go** to inspect another location. Select a stack
frame to jump to that frame. Scroll down to fetch subsequent instruction
pages; scroll up to fetch preceding instructions. The UI preserves the visible
position when it prepends earlier instructions. Backward x64 decoding is
best-effort because x64 instructions are variable length and arbitrary byte
sequences can admit more than one valid decoding.

The Memory inspector reads process memory at an entered address or a selected
region. Reads are limited to 4 KiB per request. Memory writes are available
through the HTTP API while paused and are limited to one committed region; a
write cannot overlap an active software breakpoint.

### File-I/O breakpoints

Enable **Read** and/or **Write** in the File I/O Breakpoints panel. Optionally
enter a path substring such as `common.rpf` to filter case-insensitively, then
apply the configuration. A matching operation pauses the thread that requested
the I/O. The automatically refreshed call stack is intended to show the game
function that initiated the operation.

The hooks cover VIctory's title HLE boundaries for Win32
`ReadFile`/`WriteFile`, CRT `fread`/`fwrite` and `_read`/`_write`,
plus DirectStorage request enqueue. For DirectStorage, the stack belongs to the
game thread submitting the request, not the worker that later performs the
queued read.

The event history records requested operations, not proof that the underlying
I/O completed successfully. File offsets come from the `OVERLAPPED` structure
for overlapped Win32 I/O, the current file pointer for synchronous
`ReadFile`/`WriteFile`, the CRT stream/descriptor cursor for CRT operations,
and the explicit request offset for DirectStorage. Offsets are best-effort for
non-seekable handles; concurrent synchronous operations sharing one file
pointer can move it between the position query and the operation.

These are API-boundary breakpoints, **not** x64 hardware data breakpoints
(DR0–DR3). They do not catch arbitrary I/O performed by unhooked host-library
code or direct native syscalls that bypass the HLE entry points.

### HTTP API reference

The loopback HTTP API is useful for scripts and external tools:

| Method and path | Purpose |
|---|---|
| `GET /api/status` | Process state, stop reason and target address mapping |
| `GET /api/threads` | Enumerate inspectable threads |
| `GET /api/registers?thread=ID` | Read a thread's registers |
| `GET /api/stack?thread=ID` | Unwind a thread while paused |
| `GET /api/disassemble?address=0x...&count=128` | Decode forward from an address |
| `GET /api/disassemble/before?address=0x...&count=128` | Decode preceding instructions, best-effort |
| `GET /api/memory?address=0x...&length=256` | Read process memory |
| `GET /api/regions?cursor=0x...` | Enumerate virtual memory regions |
| `GET /api/breakpoints` | List software breakpoints |
| `POST /api/breakpoints/add?address=0x...` | Add a software breakpoint |
| `POST /api/breakpoints/remove?address=0x...` | Remove a software breakpoint |
| `POST /api/pause` / `POST /api/resume` | Pause or resume execution |
| `POST /api/step` | Execute one instruction from a supported stop |
| `POST /api/runto?address=0x...` | Resume until an address; pair with `GET /api/wait` |
| `GET /api/wait?timeout_ms=30000` | Wait for the next stop instead of polling |
| `POST /api/memory/write?address=0x...&hex=...` | Write up to 4 KiB while paused |
| `POST /api/registers/set?thread=ID&name=RAX&value=0x...` | Edit a register at an exception stop |
| `GET /api/io/breakpoints` | Read file-I/O breakpoint settings |
| `POST /api/io/breakpoints?read=true&write=true&path=common.rpf` | Configure file-I/O breakpoints |
| `GET /api/io/events` | Read the last 100 file-I/O requests |

For an I/O breakpoint, `GET /api/stack?thread=ID` can inspect the initiating
thread while it is paused. The DirectStorage event offset is the request's
explicit file offset.

An unowned process `INT3` (including title or CRT `__debugbreak()`) is
reported as `reason:"exception"` in `/api/status`. Resume skips the one-byte
INT3 instruction; it does not repair the assertion or guarantee the title can
continue. Step skips that INT3 and stops after the next native instruction.
First-chance access violations (`0xC0000005`) and illegal-instruction
exceptions can also be inspected with their call stack and access details.
Resume without editing the saved context passes those exceptions to later
Windows exception handlers; editing a register or RIP and resuming applies
the modified context instead.

This is an in-process debugger, not a CPU emulator or a remote debugger.
Pausing all threads can catch a thread while it owns a process-wide lock; keep
debugger requests read-focused while paused and continue promptly if other
runtime work is blocked.

Build diagnostics separately when you also need scheduled stack dumps,
memory-on-crash capture and the other switches below:

```powershell
cargo build --profile diag -p victory --features diagnostics   # target\diag\victory.exe
```

The on/off switches below (`...=1`) are off when unset or set to `0`.

| Variable | Effect |
|----------|--------|
| `VICTORY_LOG=<target>=debug,...` | debug and trace output |
| `VICTORY_STACKS=20,60` | every thread's stack at those seconds |
| `VICTORY_WATCH=<rva>,...` | logs a title u32 when it changes |
| `VICTORY_POKE=<rva>:<byte>,...` | writes a title byte twice a second (a hang watchdog's tick, say) |
| `VICTORY_KEYS=30:Enter,35:X` | presses keys at those seconds, focus or not |
| `VICTORY_CRASH_BREAKPOINTS=1` | appends first-chance breakpoints to `crashes.log`, including ones a handler may recover from |
| `VICTORY_CRASH_SAVE=<rva>:<len>,...` | saves title memory to the cache folder on a crash |
| `VICTORY_CAPTURE=<dir>` | saves presented frames (powers of two, or `VICTORY_CAPTURE_FRAMES=<list>`) |
| `VICTORY_DUMP_TARGETS=1` | with the two above, saves every render target of those frames |
| `VICTORY_CAPTURE_WORLD=<list>` | with `VICTORY_CAPTURE`, also saves (and with `VICTORY_DUMP_TARGETS` dumps) the frames at these offsets from the first frame that ran 500 draws (the world's first; its number depends on how fast the title loaded) |
| `VICTORY_DUMP_WRITERS=<hash>,...` | with the two above, also the textures a pipeline containing a listed shader hash writes, the first frame it runs, and for its buffers a log line (dwords changed, dwords not zero) |
| `VICTORY_PEEK=<hex address>[:<bytes>],...` | in listed frames, those bytes of title memory logged after each submission. Listed frames also log targets of 16 texels or fewer as values, each table view's view words and whether its host slot is null, the host copy of every buffer of 64 bytes or fewer a draw reads (at submission and after its list), and each 1D or 3D texture a dispatch writes, read back right after it |
| `VICTORY_D3D12_DEBUG=1` | host debug layer |
| `VICTORY_D3D12_GBV=1` | with the above, GPU-based validation (bad descriptor use reported, not faulted; slow) |
| `VICTORY_D3D12_DRED=1` | on a GPU failure, the allocation hit and the commands in flight |
| `VICTORY_SKIP_PIPELINES=<hash>,...` | omit draws and dispatches, including indirect ones, whose pipeline contains a listed 16-digit shader hash |
| `VICTORY_GPU_TIMING=1` | with the above, each list of a submission run and timed on its own; slow lists logged with their slowest commands; a device removal names the list it happened in and lists all its commands |
| `VICTORY_TRACE_SHADERS=<hash>,...` | with `VICTORY_D3D12_DRED`, every draw and dispatch of a listed shader logged with what it binds (user data, heap slots, root views and their first dwords; the first 500) |
| `VICTORY_D3D12_WARP=1` | host device on the software adapter (slow; cannot reset the driver) |
| `VICTORY_PIPELINE_LOG=<file>` | a line per title pipeline created (key, shaders, state), first used, and made or loaded (library name); `translate --cache --pipelines` writes the last kind too |
| `VICTORY_PREBUILD_KEYS=<file>` | `translate --cache --pipelines` makes nothing and lists each pack record's key, shaders and state (or why it is skipped) |
| `VICTORY_SHADER_LOOP_LIMIT=<n>` | translated shader loops stop after `n` iterations per lane instead of 2^20 (own shader cache entries); if a lower `n` makes world frames much faster, loops hitting the limit are what makes them slow |
| `VICTORY_AUDIO_CAPTURE=<file.wav>` | records what the title plays (our process only) |
| `VICTORY_XMA_DUMP=<dir>` | saves the first 32 XMA voices' context and input |

Every build appends unhandled exceptions, panics, and host GPU failures to
`crashes.log` in the title's data folder.

For a startup breakpoint (`0x80000003`), run the diagnostics build with
`VICTORY_CRASH_BREAKPOINTS=1`. Keep the console output along with the new
`crashes.log` entries. A host DLL refusal includes the caller stack in the
console output. The refusal is expected for DLLs outside the host policy,
including `rpcrt4.dll`.

On Series 1.0.2.1, a missing `appdata0.rpf` reproduced the breakpoint at
`+0x2237178` before the first window. Restore the archive from the same
package beside the title executable. `run --execute` checks that it can
read the RPF9 header before starting this build.

To compare hardware and software rendering, repeat with
`VICTORY_D3D12_WARP=1` and check the console for
`host device on the software adapter (WARP)` to confirm the WARP device was
created. Compare the exception's module and offset, stack frames, and
preceding messages across the two runs.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
