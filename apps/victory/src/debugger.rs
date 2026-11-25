//! Local web debugger for inspecting the native Xbox title process.
//!
//! The HTTP listener is loopback-only. It intentionally lives in the same
//! process as the title so register and memory inspection does not depend on
//! an external debugger attaching to the synthetic PE module.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::ffi::c_void;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::{Value, json};
use windows_sys::Win32::Foundation::{
    CloseHandle, EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP, HANDLE, INVALID_HANDLE_VALUE,
    LocalFree,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, CONTEXT, CONTEXT_FULL_AMD64, EXCEPTION_POINTERS,
    FlushInstructionCache, GetThreadContext, ReadProcessMemory, RtlCaptureContext,
    WriteProcessMemory,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::Memory::{
    MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, VirtualProtect, VirtualQuery,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, GetThreadDescription, OpenThread,
    ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
    THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
};

const TRAP_FLAG: u32 = 0x100;
const DEFAULT_WINMAIN_IDA_ADDRESS: u64 = 0x145A91BD0;
const MAX_HTTP_HEADER: usize = 16 * 1024;
const MAX_MEMORY_READ: usize = 0x1000;

#[derive(Clone)]
pub struct DebugTarget {
    pub title: String,
    pub build_hash: String,
    pub image_base: usize,
    pub ida_base: u64,
    pub image_size: usize,
    pub entry_rva: u32,
}

impl DebugTarget {
    fn to_ida_address(&self, address: usize) -> u64 {
        let Some(offset) = address.checked_sub(self.image_base) else {
            return address as u64;
        };
        if offset < self.image_size {
            self.ida_base.saturating_add(offset as u64)
        } else {
            address as u64
        }
    }

    fn to_ida_boundary(&self, address: usize) -> u64 {
        let Some(offset) = address.checked_sub(self.image_base) else {
            return address as u64;
        };
        if offset <= self.image_size {
            self.ida_base.saturating_add(offset as u64)
        } else {
            address as u64
        }
    }

    fn to_process_address(&self, address: u64) -> Result<usize, String> {
        if let Some(offset) = address.checked_sub(self.ida_base) {
            if offset <= self.image_size as u64 {
                let offset = usize::try_from(offset)
                    .map_err(|_| format!("IDA address {address:#x} is out of range"))?;
                return self
                    .image_base
                    .checked_add(offset)
                    .ok_or_else(|| format!("IDA address {address:#x} overflows the process address space"));
            }
        }

        usize::try_from(address)
            .map_err(|_| format!("address {address:#x} is out of range"))
    }

    fn rebase_delta(&self) -> i128 {
        self.ida_base as i128 - self.image_base as i128
    }
}

fn default_winmain_address(target: &DebugTarget) -> Option<usize> {
    let address = target
        .to_process_address(DEFAULT_WINMAIN_IDA_ADDRESS)
        .ok()?;
    let offset = address.checked_sub(target.image_base)?;
    (offset < target.image_size).then_some(address)
}

struct Runtime {
    target: DebugTarget,
    started: Instant,
    server_thread: AtomicU32,
    http_threads: Mutex<HashSet<u32>>,
    breakpoints: Mutex<BTreeMap<usize, u8>>,
    temporary_breakpoints: Mutex<HashSet<usize>>,
    io_breakpoints: Mutex<IoBreakpointConfig>,
    io_events: Mutex<VecDeque<victory_hle::modules::files::FileIoEvent>>,
    control: Mutex<Control>,
    changed: Condvar,
    suspended: Mutex<Vec<usize>>,
}

#[derive(Clone, Default)]
struct IoBreakpointConfig {
    reads: bool,
    writes: bool,
    path_filter: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Wait,
    Continue,
    Step,
}

struct Control {
    paused: bool,
    reason: &'static str,
    hit_address: Option<usize>,
    hit_thread: Option<u32>,
    hit_registers: Option<Registers>,
    hit_context: Option<CONTEXT>,
    pending_context: Option<CONTEXT>,
    exception_code: Option<u32>,
    io_event: Option<victory_hle::modules::files::FileIoEvent>,
    action: Action,
    step_thread: Option<u32>,
    step_breakpoint: Option<usize>,
    stop_after_instruction: bool,
}

#[derive(Clone, Copy)]
struct Registers {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    rsp: u64,
    rip: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rflags: u32,
}

#[repr(C, align(16))]
struct AlignedContext(CONTEXT);

static RUNTIME: OnceLock<Arc<Runtime>> = OnceLock::new();

pub fn start(port: u16, target: DebugTarget) -> Result<String> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .with_context(|| format!("binding debugger to 127.0.0.1:{port}"))?;
    let address = listener.local_addr()?;
    let entry_address = target
        .image_base
        .checked_add(target.entry_rva as usize)
        .context("title entry-point address overflow")?;

    let runtime = Arc::new(Runtime {
        target,
        started: Instant::now(),
        server_thread: AtomicU32::new(0),
        http_threads: Mutex::new(HashSet::new()),
        breakpoints: Mutex::new(BTreeMap::new()),
        temporary_breakpoints: Mutex::new(HashSet::new()),
        io_breakpoints: Mutex::new(IoBreakpointConfig::default()),
        io_events: Mutex::new(VecDeque::with_capacity(100)),
        control: Mutex::new(Control {
            paused: false,
            reason: "running",
            hit_address: None,
            hit_thread: None,
            hit_registers: None,
            hit_context: None,
            pending_context: None,
            exception_code: None,
            io_event: None,
            action: Action::Wait,
            step_thread: None,
            step_breakpoint: None,
            stop_after_instruction: false,
        }),
        changed: Condvar::new(),
        suspended: Mutex::new(Vec::new()),
    });

    RUNTIME
        .set(runtime.clone())
        .map_err(|_| anyhow::anyhow!("the runtime debugger was already started"))?;

    // SAFETY: the callback only handles breakpoint/single-step exceptions
    // installed by this debugger and passes every other exception onward.
    let handler = unsafe { AddVectoredExceptionHandler(1, Some(exception_handler)) };
    anyhow::ensure!(!handler.is_null(), "AddVectoredExceptionHandler failed");

    let io_runtime = Arc::downgrade(&runtime);
    victory_hle::modules::files::set_file_io_observer(Some(Arc::new(move |event| {
        if let Some(runtime) = io_runtime.upgrade() {
            handle_file_io(&runtime, event);
        }
    })));

    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let server_runtime = runtime.clone();
    thread::Builder::new()
        .name("victory-debug-http".into())
        .spawn(move || {
            server_runtime
                .server_thread
                // SAFETY: a plain query of the calling server thread.
                .store(unsafe { GetCurrentThreadId() }, Ordering::Release);
            let _ = ready_tx.send(());
            tracing::info!(%address, "runtime debugger listening");
            for connection in listener.incoming() {
                match connection {
                    Ok(stream) => {
                        let connection_runtime = server_runtime.clone();
                        let port = address.port();
                        if let Err(error) = thread::Builder::new()
                            .name("victory-debug-http-client".into())
                            .spawn(move || {
                                let id = unsafe { GetCurrentThreadId() };
                                connection_runtime.http_threads
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .insert(id);
                                serve(stream, &connection_runtime, port);
                                connection_runtime.http_threads
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .remove(&id);
                            })
                        {
                            tracing::warn!(%error, "debugger HTTP client thread failed");
                        }
                    }
                    Err(error) => tracing::warn!(%error, "debugger HTTP accept failed"),
                }
            }
        })?;
    ready_rx
        .recv()
        .context("waiting for the debugger HTTP thread to start")?;

    // The title has not been launched yet, so this breakpoint is guaranteed
    // to be in place before the entry thread can execute its first instruction.
    let ida_entry_address = runtime.target.to_ida_address(entry_address);
    add_breakpoint(&runtime, entry_address)
        .map_err(anyhow::Error::msg)
        .with_context(|| {
            format!(
                "installing entry-point breakpoint at IDA {ida_entry_address:#x} (runtime {entry_address:#x})"
            )
        })?;
    tracing::info!(
        entry = %format!("{ida_entry_address:#x}"),
        runtime = %format!("{entry_address:#x}"),
        "automatic entry-point breakpoint installed"
    );

    if let Some(winmain_address) = default_winmain_address(&runtime.target) {
        let ida_winmain_address = runtime.target.to_ida_address(winmain_address);
        match add_breakpoint(&runtime, winmain_address) {
            Ok(()) => tracing::info!(
                ida = %format!("{ida_winmain_address:#x}"),
                runtime = %format!("{winmain_address:#x}"),
                "automatic WinMain breakpoint installed"
            ),
            Err(error) => tracing::warn!(
                ida = %format!("{ida_winmain_address:#x}"),
                runtime = %format!("{winmain_address:#x}"),
                %error,
                "could not install automatic WinMain breakpoint"
            ),
        }
    } else {
        tracing::warn!(
            ida = %format!("{DEFAULT_WINMAIN_IDA_ADDRESS:#x}"),
            ida_base = %format!("{:#x}", runtime.target.ida_base),
            image_size = %format!("{:#x}", runtime.target.image_size),
            "WinMain breakpoint is outside the title image; skipping"
        );
    }

    Ok(format!("http://127.0.0.1:{}", address.port()))
}

fn exception_runtime() -> Option<&'static Arc<Runtime>> {
    RUNTIME.get()
}

// Windows has already adjusted CONTEXT.Rip to the address of the INT3
// instruction before dispatching EXCEPTION_BREAKPOINT to user mode.
#[inline]
fn breakpoint_address(context: &CONTEXT) -> usize {
    context.Rip as usize
}

unsafe extern "system" fn exception_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    if info.is_null() {
        return 0;
    }
    // SAFETY: Windows supplies a valid EXCEPTION_POINTERS for this callback.
    let (record, context) = unsafe {
        let pointers = &mut *info;
        (&*pointers.ExceptionRecord, &mut *pointers.ContextRecord)
    };
    let Some(runtime) = exception_runtime() else {
        return 0;
    };

    if record.ExceptionCode == EXCEPTION_BREAKPOINT {
        let address = breakpoint_address(context);
        let original = {
            let breakpoints = runtime.breakpoints.lock().unwrap_or_else(|e| e.into_inner());
            breakpoints.get(&address).copied()
        };
        let Some(original) = original else {
            // Unowned INT3s are still useful debugger stops, including traps
            // raised inside VCRUNTIME/CRT rather than the title image itself.
            let exception_address = record.ExceptionAddress as usize;
            return handle_title_breakpoint(runtime, context, exception_address);
        };

        // Restore the original byte. RIP already points at the INT3 address,
        // so leave it there and execute the original instruction with TF set.
        // SAFETY: the breakpoint was installed by this debugger at this address.
        if unsafe { write_code_byte(address, original) }.is_err() {
            return 0;
        }
        let temporary = runtime
            .temporary_breakpoints
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&address);
        if temporary {
            runtime
                .breakpoints
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&address);
        }
        context.EFlags |= TRAP_FLAG;
        // SAFETY: a plain query of the title thread that raised the breakpoint.
        let thread_id = unsafe { GetCurrentThreadId() };
        suspend_peers(runtime, &[thread_id]);

        let mut control = runtime.control.lock().unwrap_or_else(|e| e.into_inner());
        control.paused = true;
        control.reason = "breakpoint";
        control.hit_address = Some(address);
        control.hit_thread = Some(thread_id);
        control.hit_registers = Some(Registers::from(context));
        control.hit_context = Some(*context);
        control.exception_code = None;
        control.step_thread = Some(thread_id);
        control.step_breakpoint = Some(address);
        control.pending_context = None;
        control.action = Action::Wait;
        runtime.changed.notify_all();

        while control.action == Action::Wait {
            control = runtime.changed.wait(control).unwrap_or_else(|e| e.into_inner());
        }
        if let Some(pending) = control.pending_context.take() {
            *context = pending;
        }
        control.stop_after_instruction = control.action == Action::Step;
        context.EFlags |= TRAP_FLAG;
        control.paused = false;
        runtime.changed.notify_all();
        return -1; // EXCEPTION_CONTINUE_EXECUTION
    }

    if record.ExceptionCode == EXCEPTION_SINGLE_STEP {
        // SAFETY: a plain query of the title thread that raised the exception.
        let thread_id = unsafe { GetCurrentThreadId() };
        let (is_step_thread, breakpoint) = {
            let control = runtime.control.lock().unwrap_or_else(|e| e.into_inner());
            (control.step_thread == Some(thread_id), control.step_breakpoint)
        };
        if !is_step_thread {
            return 0;
        }
        if let Some(address) = breakpoint {
            let enabled = runtime
                .breakpoints
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&address);
            if enabled {
                // SAFETY: this is the address whose original byte was saved when
                // the user installed the software breakpoint.
                let _ = unsafe { write_code_byte(address, 0xCC) };
            }
        }
        context.EFlags &= !TRAP_FLAG;

        let mut control = runtime.control.lock().unwrap_or_else(|e| e.into_inner());
        if !control.stop_after_instruction {
            control.paused = false;
            control.reason = "running";
            control.hit_address = None;
            control.hit_thread = None;
            control.hit_registers = None;
            control.hit_context = None;
            control.exception_code = None;
            control.step_thread = None;
            control.step_breakpoint = None;
            runtime.changed.notify_all();
            drop(control);
            resume_peers(runtime);
            return -1;
        }

        control.paused = true;
        control.reason = "step";
        control.hit_address = Some(context.Rip as usize);
        control.hit_thread = Some(thread_id);
        control.hit_registers = Some(Registers::from(context));
        control.hit_context = Some(*context);
        control.pending_context = None;
        control.exception_code = None;
        control.action = Action::Wait;
        runtime.changed.notify_all();

        while control.action == Action::Wait {
            control = runtime.changed.wait(control).unwrap_or_else(|e| e.into_inner());
        }

        match control.action {
            Action::Step => {
                if let Some(pending) = control.pending_context.take() {
                    *context = pending;
                }
                control.paused = false;
                control.stop_after_instruction = true;
                context.EFlags |= TRAP_FLAG;
                runtime.changed.notify_all();
                return -1;
            }
            Action::Continue => {
                if let Some(pending) = control.pending_context.take() {
                    *context = pending;
                }
                control.paused = false;
                control.stop_after_instruction = false;
                context.EFlags &= !TRAP_FLAG;
                control.reason = "running";
                control.hit_address = None;
                control.hit_thread = None;
                control.hit_registers = None;
                control.hit_context = None;
                control.exception_code = None;
                control.step_thread = None;
                control.step_breakpoint = None;
                runtime.changed.notify_all();
                drop(control);
                resume_peers(runtime);
                return -1;
            }
            Action::Wait => return 0,
        }
    }

    0 // EXCEPTION_CONTINUE_SEARCH
}

fn handle_title_breakpoint(runtime: &Runtime, context: &mut CONTEXT, address: usize) -> i32 {
    // A title-generated INT3 (for example __debugbreak()) is an inspectable
    // stop, not an unhandled exception. All other process breakpoints pass on.
    // SAFETY: a plain query of the title thread raising the exception.
    let thread_id = unsafe { GetCurrentThreadId() };
    suspend_peers(runtime, &[thread_id]);

    let mut control = runtime.control.lock().unwrap_or_else(|e| e.into_inner());
    control.paused = true;
    control.reason = "exception";
    control.hit_address = Some(address);
    control.hit_thread = Some(thread_id);
    let mut stopped_context = *context;
    stopped_context.Rip = address as u64;
    control.hit_registers = Some(Registers::from(&stopped_context));
    control.hit_context = Some(stopped_context);
    control.pending_context = None;
    control.exception_code = Some(EXCEPTION_BREAKPOINT as u32);
    control.step_thread = Some(thread_id);
    control.step_breakpoint = None;
    control.stop_after_instruction = false;
    control.action = Action::Wait;
    runtime.changed.notify_all();

    while control.action == Action::Wait {
        control = runtime.changed.wait(control).unwrap_or_else(|e| e.into_inner());
    }

    let action = control.action;
    if let Some(pending) = control.pending_context.take() {
        *context = pending;
    }
    control.paused = false;
    control.reason = "running";
    control.hit_address = None;
    control.hit_thread = None;
    control.hit_registers = None;
    control.hit_context = None;
    control.exception_code = None;
    control.step_breakpoint = None;
    control.stop_after_instruction = action == Action::Step;
    if action == Action::Step {
        control.step_thread = Some(thread_id);
    } else {
        control.step_thread = None;
    }
    runtime.changed.notify_all();
    drop(control);

    // __debugbreak emits a one-byte INT3. Continue skips it; Step skips it
    // and traps after exactly the following native instruction.
    if context.Rip == address as u64 {
        context.Rip = (address as u64).saturating_add(1);
    }
    context.EFlags &= !TRAP_FLAG;
    if action == Action::Step {
        context.EFlags |= TRAP_FLAG;
    } else {
        resume_peers(runtime);
    }
    -1 // EXCEPTION_CONTINUE_EXECUTION
}

impl Registers {
    fn from(context: &CONTEXT) -> Self {
        Self {
            rax: context.Rax,
            rbx: context.Rbx,
            rcx: context.Rcx,
            rdx: context.Rdx,
            rsi: context.Rsi,
            rdi: context.Rdi,
            rbp: context.Rbp,
            rsp: context.Rsp,
            rip: context.Rip,
            r8: context.R8,
            r9: context.R9,
            r10: context.R10,
            r11: context.R11,
            r12: context.R12,
            r13: context.R13,
            r14: context.R14,
            r15: context.R15,
            rflags: context.EFlags,
        }
    }

    fn json(self, target: &DebugTarget) -> Value {
        let address = |value: u64| {
            format!("{:#018x}", target.to_ida_address(value as usize))
        };
        json!({
            "rax": address(self.rax),
            "rbx": address(self.rbx),
            "rcx": address(self.rcx),
            "rdx": address(self.rdx),
            "rsi": address(self.rsi),
            "rdi": address(self.rdi),
            "rbp": address(self.rbp),
            "rsp": address(self.rsp),
            "rip": address(self.rip),
            "r8": address(self.r8),
            "r9": address(self.r9),
            "r10": address(self.r10),
            "r11": address(self.r11),
            "r12": address(self.r12),
            "r13": address(self.r13),
            "r14": address(self.r14),
            "r15": address(self.r15),
            "rflags": format!("{:#010x}", self.rflags),
        })
    }
}

fn suspend_peers(runtime: &Runtime, extra_excluded: &[u32]) {
    let mut suspended = runtime.suspended.lock().unwrap_or_else(|e| e.into_inner());
    let mut known = HashSet::new();
    for _ in 0..3 {
        // SAFETY: a plain query of the calling thread ID.
        let current = unsafe { GetCurrentThreadId() };
        let server = runtime.server_thread.load(Ordering::Acquire);
        let http_threads = runtime.http_threads.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let ids = process_thread_ids();
        let mut added = false;
        for id in ids {
            if id == current || id == server || http_threads.contains(&id)
                || extra_excluded.contains(&id) || !known.insert(id) {
                continue;
            }
            // SAFETY: opens another thread in this process for suspension.
            let handle = unsafe {
                OpenThread(
                    THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                    0,
                    id,
                )
            };
            if handle.is_null() {
                continue;
            }
            // SAFETY: handle names a thread in this process.
            if unsafe { SuspendThread(handle) } == u32::MAX {
                // SAFETY: handle was opened successfully immediately above.
                unsafe { CloseHandle(handle) };
                continue;
            }
            suspended.push(handle as usize);
            added = true;
        }
        if !added {
            break;
        }
    }
}

fn resume_peers(runtime: &Runtime) {
    let handles = {
        let mut suspended = runtime.suspended.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *suspended)
    };
    for handle in handles {
        // SAFETY: each handle was opened and suspended once by suspend_peers.
        unsafe {
            ResumeThread(handle as HANDLE);
            CloseHandle(handle as HANDLE);
        }
    }
}

fn process_thread_ids() -> Vec<u32> {
    // SAFETY: snapshot of all process threads.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Vec::new();
    }
    // SAFETY: a plain query of the current process ID.
    let process = unsafe { GetCurrentProcessId() };
    let mut ids = Vec::new();
    // SAFETY: zeroed is valid and dwSize is initialised before use.
    let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = size_of::<THREADENTRY32>() as u32;
    // SAFETY: snapshot is open and entry has its required size.
    let mut more = unsafe { Thread32First(snapshot, &mut entry) } != 0;
    while more {
        if entry.th32OwnerProcessID == process {
            ids.push(entry.th32ThreadID);
        }
        // SAFETY: snapshot is open and entry remains correctly sized.
        more = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
    }
    // SAFETY: snapshot was opened by CreateToolhelp32Snapshot above.
    unsafe { CloseHandle(snapshot) };
    ids
}

fn read_thread_context(thread_id: u32) -> Option<AlignedContext> {
    // SAFETY: opens the requested thread for a brief context read.
    let handle = unsafe {
        OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
            0,
            thread_id,
        )
    };
    if handle.is_null() {
        return None;
    }
    // SAFETY: zeroed is a valid initial CONTEXT; ContextFlags is set below.
    let mut context = AlignedContext(unsafe { std::mem::zeroed() });
    context.0.ContextFlags = CONTEXT_FULL_AMD64;
    // SAFETY: handle is an opened thread with suspend/context permissions.
    let result = unsafe {
        let suspended = SuspendThread(handle);
        if suspended == u32::MAX {
            false
        } else {
            let read = GetThreadContext(handle, &mut context.0) != 0;
            ResumeThread(handle);
            read
        }
    };
    // SAFETY: handle was opened successfully above.
    unsafe { CloseHandle(handle) };
    result.then_some(context)
}

fn read_context(thread_id: u32) -> Option<Registers> {
    read_thread_context(thread_id).map(|context| Registers::from(&context.0))
}

fn thread_name(thread_id: u32) -> String {
    // SAFETY: opens the requested thread for its description.
    let handle = unsafe {
        OpenThread(
            THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
            0,
            thread_id,
        )
    };
    if handle.is_null() {
        return String::new();
    }
    let mut name: *mut u16 = null_mut();
    // SAFETY: handle has query access and name receives the allocated description.
    let result = unsafe { GetThreadDescription(handle, &mut name) };
    let value = if result < 0 || name.is_null() {
        String::new()
    } else {
        // SAFETY: GetThreadDescription returned a NUL-terminated UTF-16 string.
        let len = unsafe { (0..).take_while(|&i| *name.add(i) != 0).count() };
        // SAFETY: the pointer addresses `len` UTF-16 code units in the returned allocation.
        let text = unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(name, len)) };
        // SAFETY: GetThreadDescription allocated this string for LocalFree.
        unsafe { LocalFree(name.cast::<c_void>()) };
        text
    };
    // SAFETY: handle was opened successfully above.
    unsafe { CloseHandle(handle) };
    value
}

fn threads_json(runtime: &Runtime) -> Value {
    let server = runtime.server_thread.load(Ordering::Acquire);
    let http_threads = runtime.http_threads.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let threads: Vec<Value> = process_thread_ids()
        .into_iter()
        .filter(|id| *id != server && !http_threads.contains(id))
        .map(|id| {
            json!({
                "id": id,
                "name": thread_name(id),
            })
        })
        .collect();
    Value::Array(threads)
}

fn registers_json(runtime: &Runtime, thread_id: u32) -> Result<Value, String> {
    let control = runtime.control.lock().unwrap_or_else(|e| e.into_inner());
    let hit_registers = if control.hit_thread == Some(thread_id) {
        control.hit_registers
    } else {
        None
    };
    drop(control);

    let registers = hit_registers
        .or_else(|| read_context(thread_id))
        .ok_or_else(|| format!("thread {thread_id} exited or its context is unavailable"))?;
    Ok(json!({
        "thread_id": thread_id,
        "registers": registers.json(&runtime.target),
    }))
}

fn set_context_register(context: &mut CONTEXT, name: &str, value: u64) -> Result<(), String> {
    match name.to_ascii_lowercase().as_str() {
        "rax" => context.Rax = value,
        "rbx" => context.Rbx = value,
        "rcx" => context.Rcx = value,
        "rdx" => context.Rdx = value,
        "rsi" => context.Rsi = value,
        "rdi" => context.Rdi = value,
        "rbp" => context.Rbp = value,
        "rsp" => context.Rsp = value,
        "rip" => context.Rip = value,
        "r8" => context.R8 = value,
        "r9" => context.R9 = value,
        "r10" => context.R10 = value,
        "r11" => context.R11 = value,
        "r12" => context.R12 = value,
        "r13" => context.R13 = value,
        "r14" => context.R14 = value,
        "r15" => context.R15 = value,
        "rflags" | "eflags" => {
            context.EFlags = u32::try_from(value)
                .map_err(|_| "RFLAGS must fit in 32 bits".to_owned())?;
        }
        _ => return Err(format!("unsupported register: {name}")),
    }
    Ok(())
}

fn set_register(runtime: &Runtime, thread_id: u32, name: &str, value: u64) -> Result<Value, String> {
    let mut control = runtime.control.lock().unwrap_or_else(|e| e.into_inner());
    if !control.paused {
        return Err("register writes require a paused process".into());
    }
    if control.hit_thread != Some(thread_id) {
        return Err("register writes currently require the thread at the active stop".into());
    }
    if control.reason == "io-breakpoint" || control.reason == "manual" {
        return Err("register writes require a native exception stop; I/O and manual stops are snapshots only".into());
    }
    let mut context = control
        .pending_context
        .or(control.hit_context)
        .ok_or_else(|| "the active stop has no saved exception context".to_owned())?;
    let process_value = runtime.target.to_process_address(value)?;
    set_context_register(&mut context, name, process_value as u64)?;
    control.hit_context = Some(context);
    control.pending_context = Some(context);
    control.hit_registers = Some(Registers::from(&context));
    Ok(json!({
        "thread_id": thread_id,
        "register": name.to_ascii_uppercase(),
        "value": format!("{:#x}", runtime.target.to_ida_address(process_value)),
        "registers": Registers::from(&context).json(&runtime.target),
    }))
}

fn stack_bounds(rsp: usize) -> Option<(usize, usize)> {
    // SAFETY: zeroed is a valid output buffer for MEMORY_BASIC_INFORMATION.
    let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: VirtualQuery writes into the correctly sized structure.
    let read = unsafe {
        VirtualQuery(
            rsp as *const c_void,
            &mut info,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if read == 0 || info.AllocationBase.is_null() {
        return None;
    }

    let allocation_base = info.AllocationBase as usize;
    let mut cursor = (info.BaseAddress as usize).checked_add(info.RegionSize)?;
    let mut high = cursor;
    for _ in 0..128 {
        // SAFETY: zeroed is a valid output buffer for MEMORY_BASIC_INFORMATION.
        let mut next: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: VirtualQuery writes into the correctly sized structure.
        let read = unsafe {
            VirtualQuery(
                cursor as *const c_void,
                &mut next,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if read == 0 || next.AllocationBase as usize != allocation_base {
            break;
        }
        let end = (next.BaseAddress as usize).checked_add(next.RegionSize)?;
        if end <= cursor {
            break;
        }
        cursor = end;
        high = end;
    }

    (rsp >= allocation_base && rsp < high).then_some((allocation_base, high))
}

fn stack_json(runtime: &Runtime, thread_id: u32) -> Result<Value, String> {
    let saved = {
        let control = runtime.control.lock().unwrap_or_else(|e| e.into_inner());
        if !control.paused {
            return Err("stack inspection requires a paused process".into());
        }
        if control.hit_thread == Some(thread_id) {
            control.hit_context
        } else {
            None
        }
    };
    let context = saved
        .map(AlignedContext)
        .or_else(|| read_thread_context(thread_id))
        .ok_or_else(|| format!("thread {thread_id} exited or its context is unavailable"))?;
    let rsp = context.0.Rsp as usize;
    let (low, high) = stack_bounds(rsp)
        .ok_or_else(|| format!("could not determine stack bounds for thread {thread_id}"))?;
    let frames = victory_loader::unwind_context(context.0, low, high);
    let frames: Vec<Value> = frames
        .into_iter()
        .enumerate()
        .map(|(index, address)| {
            let runtime_address = address as usize;
            json!({
                "index": index,
                "address": format!("{:#x}", runtime.target.to_ida_address(runtime_address)),
                "runtime_address": format!("{runtime_address:#x}"),
                "location": victory_loader::locate(runtime_address),
            })
        })
        .collect();
    Ok(json!({
        "thread_id": thread_id,
        "stack_low": format!("{low:#x}"),
        "stack_high": format!("{high:#x}"),
        "frames": frames,
    }))
}

fn io_event_json(event: &victory_hle::modules::files::FileIoEvent) -> Value {
    json!({
        "operation": event.operation,
        "path": event.path,
        "api": event.api,
        "size": event.size,
        "offset": event.offset.map(|value| format!("{value:#x}")),
    })
}

fn io_breakpoints_json(runtime: &Runtime) -> Value {
    let config = runtime.io_breakpoints.lock().unwrap_or_else(|e| e.into_inner());
    json!({
        "read": config.reads,
        "write": config.writes,
        "path_filter": config.path_filter,
    })
}

fn io_events_json(runtime: &Runtime) -> Value {
    let events = runtime.io_events.lock().unwrap_or_else(|e| e.into_inner());
    Value::Array(events.iter().map(io_event_json).collect())
}

fn configure_io_breakpoints(
    runtime: &Runtime,
    reads: Option<bool>,
    writes: Option<bool>,
    path_filter: Option<String>,
) -> Value {
    let mut config = runtime.io_breakpoints.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(reads) = reads {
        config.reads = reads;
    }
    if let Some(writes) = writes {
        config.writes = writes;
    }
    if let Some(path_filter) = path_filter {
        config.path_filter = path_filter;
    }
    json!({
        "read": config.reads,
        "write": config.writes,
        "path_filter": config.path_filter,
    })
}

fn io_breakpoint_matches(runtime: &Runtime, event: &victory_hle::modules::files::FileIoEvent) -> bool {
    let config = runtime.io_breakpoints.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let enabled = match event.operation.as_str() {
        "read" => config.reads,
        "write" => config.writes,
        _ => false,
    };
    enabled && (
        config.path_filter.is_empty()
            || event.path.to_lowercase().contains(&config.path_filter.to_lowercase())
    )
}

fn handle_file_io(
    runtime: &Runtime,
    event: victory_hle::modules::files::FileIoEvent,
) {
    {
        let mut events = runtime.io_events.lock().unwrap_or_else(|e| e.into_inner());
        if events.len() == 100 {
            events.pop_front();
        }
        events.push_back(event.clone());
    }
    if !io_breakpoint_matches(runtime, &event) {
        return;
    }

    // Capture the initiating title thread here, before ReadFile/WriteFile or
    // DirectStorage enqueue returns to the caller.
    let mut context = AlignedContext(unsafe { std::mem::zeroed() });
    // SAFETY: RtlCaptureContext writes the current x64 thread context.
    unsafe { RtlCaptureContext(&mut context.0) };
    // SAFETY: a plain query of the calling title thread ID.
    let thread_id = unsafe { GetCurrentThreadId() };
    suspend_peers(runtime, &[thread_id]);

    let mut control = runtime.control.lock().unwrap_or_else(|e| e.into_inner());
    control.paused = true;
    control.reason = "io-breakpoint";
    control.hit_address = Some(context.0.Rip as usize);
    control.hit_thread = Some(thread_id);
    control.hit_registers = Some(Registers::from(&context.0));
    control.hit_context = Some(context.0);
    control.pending_context = None;
    control.exception_code = None;
    control.io_event = Some(event);
    control.step_thread = None;
    control.step_breakpoint = None;
    control.stop_after_instruction = false;
    control.action = Action::Wait;
    runtime.changed.notify_all();

    while control.action == Action::Wait {
        control = runtime.changed.wait(control).unwrap_or_else(|e| e.into_inner());
    }

    control.paused = false;
    control.reason = "running";
    control.hit_address = None;
    control.hit_thread = None;
    control.hit_registers = None;
    control.hit_context = None;
    control.pending_context = None;
    control.exception_code = None;
    control.io_event = None;
    control.action = Action::Wait;
    runtime.changed.notify_all();
    drop(control);
    resume_peers(runtime);
}

fn parse_bool_parameter(query: &str, key: &str) -> Option<bool> {
    query_value(query, key).and_then(|value| match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" => Some(true),
        "0" | "false" | "off" | "no" => Some(false),
        _ => None,
    })
}

fn wait_for_stop(runtime: &Runtime, timeout: Duration) -> Value {
    let control = runtime.control.lock().unwrap_or_else(|e| e.into_inner());
    let (control, result) = runtime
        .changed
        .wait_timeout_while(control, timeout, |control| !control.paused)
        .unwrap_or_else(|error| error.into_inner());
    let timed_out = result.timed_out() && !control.paused;
    drop(control);
    json!({
        "timed_out": timed_out,
        "status": status_json(runtime),
    })
}

fn status_json(runtime: &Runtime) -> Value {
    // SAFETY: a plain query of the current process ID.
    let pid = unsafe { GetCurrentProcessId() };
    let control = runtime.control.lock().unwrap_or_else(|e| e.into_inner());
    let breakpoints = runtime.breakpoints.lock().unwrap_or_else(|e| e.into_inner());
    json!({
        "pid": pid,
        "title": runtime.target.title,
        "build_hash": runtime.target.build_hash,
        "runtime_base": format!("{:#x}", runtime.target.image_base),
        "ida_base": format!("{:#x}", runtime.target.ida_base),
        "rebase_delta": format_signed_hex(runtime.target.rebase_delta()),
        "image_size": format!("{:#x}", runtime.target.image_size),
        "entry_rva": format!("{:#x}", runtime.target.entry_rva),
        "entry_address": format!(
            "{:#x}",
            runtime.target.to_ida_address(
                runtime.target.image_base + runtime.target.entry_rva as usize
            )
        ),
        "state": if control.paused { "paused" } else { "running" },
        "reason": control.reason,
        "hit_address": control
            .hit_address
            .map(|v| format!("{:#x}", runtime.target.to_ida_address(v))),
        "hit_thread": control.hit_thread,
        "exception": control.exception_code.map(|code| json!({
            "code": format!("{code:#010x}"),
            "address": control.hit_address.map(|address| {
                format!("{:#x}", runtime.target.to_ida_address(address))
            }),
            "thread_id": control.hit_thread,
        })),
        "io_event": control.io_event.as_ref().map(io_event_json),
        "breakpoint_count": breakpoints.len(),
        "uptime_seconds": runtime.started.elapsed().as_secs(),
    })
}

fn format_signed_hex(value: i128) -> String {
    if value < 0 {
        format!("-{:#x}", value.unsigned_abs())
    } else {
        format!("+{:#x}", value as u128)
    }
}

fn protection_name(protect: u32) -> &'static str {
    match protect & 0xff {
        0x01 => "NOACCESS",
        0x02 => "READONLY",
        0x04 => "READWRITE",
        0x08 => "WRITECOPY",
        0x10 => "EXECUTE",
        0x20 => "EXECUTE_READ",
        0x40 => "EXECUTE_READWRITE",
        0x80 => "EXECUTE_WRITECOPY",
        _ => "UNKNOWN",
    }
}

fn regions_json(runtime: &Runtime, cursor: usize, limit: usize) -> Value {
    let mut address = cursor;
    let mut rows = Vec::new();
    let mut done = false;
    for _ in 0..limit {
        // SAFETY: zeroed is a valid output buffer for MEMORY_BASIC_INFORMATION.
        let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: VirtualQuery writes to the correctly sized structure.
        let read = unsafe {
            VirtualQuery(
                address as *const c_void,
                &mut info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if read == 0 || info.RegionSize == 0 {
            done = true;
            break;
        }
        let base = info.BaseAddress as usize;
        let end = base.saturating_add(info.RegionSize);
        if info.State != 0x10000 {
            let state = match info.State {
                0x1000 => "COMMIT",
                0x2000 => "RESERVE",
                _ => "UNKNOWN",
            };
            let kind = match info.Type {
                0x1000000 => "IMAGE",
                0x40000 => "MAPPED",
                0x20000 => "PRIVATE",
                _ => "UNKNOWN",
            };
            rows.push(json!({
                "base": format!("{:#x}", runtime.target.to_ida_address(base)),
                "end": format!("{:#x}", runtime.target.to_ida_boundary(end)),
                "size": format!("{:#x}", info.RegionSize),
                "allocation_base": format!(
                    "{:#x}",
                    runtime.target.to_ida_address(info.AllocationBase as usize)
                ),
                "state": state,
                "type": kind,
                "protect": protection_name(info.Protect),
                "protect_raw": format!("{:#x}", info.Protect),
            }));
        }
        if end <= address {
            done = true;
            break;
        }
        address = end;
    }
    json!({
        "regions": rows,
        "next": format!("{:#x}", runtime.target.to_ida_boundary(address)),
        "done": done,
    })
}

fn memory_json(runtime: &Runtime, address: usize, requested: usize) -> Value {
    let length = requested.clamp(1, MAX_MEMORY_READ);
    let mut bytes = vec![0u8; length];
    let mut read = 0usize;
    // SAFETY: ReadProcessMemory validates the supplied address in the current process.
    let ok = unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            address as *const c_void,
            bytes.as_mut_ptr().cast(),
            length,
            &mut read,
        )
    } != 0;
    bytes.truncate(read);
    let ascii: String = bytes
        .iter()
        .map(|byte| {
            if (0x20..=0x7e).contains(byte) {
                *byte as char
            } else {
                '.'
            }
        })
        .collect();
    json!({
        "address": format!("{:#x}", runtime.target.to_ida_address(address)),
        "requested": length,
        "read": bytes.len(),
        "ok": ok || !bytes.is_empty(),
        "hex": bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>(),
        "ascii": ascii,
    })
}

fn write_memory(runtime: &Runtime, address: usize, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > MAX_MEMORY_READ {
        return Err(format!("write length must be between 1 and {MAX_MEMORY_READ:#x} bytes"));
    }
    if !runtime.control.lock().unwrap_or_else(|e| e.into_inner()).paused {
        return Err("memory writes require a paused process".into());
    }
    let end = address
        .checked_add(bytes.len())
        .ok_or_else(|| "memory write address overflows".to_owned())?;

    // Keep one write inside a single VirtualQuery region so restoring the
    // original protection cannot accidentally alter a neighboring region.
    // SAFETY: zeroed is a valid output buffer for MEMORY_BASIC_INFORMATION.
    let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: VirtualQuery writes into the correctly sized structure.
    let queried = unsafe {
        VirtualQuery(
            address as *const c_void,
            &mut info,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if queried == 0 || info.State != 0x1000 {
        return Err(format!("address {address:#x} is not committed memory"));
    }
    let region_start = info.BaseAddress as usize;
    let region_end = region_start.saturating_add(info.RegionSize);
    if address < region_start || end > region_end {
        return Err("memory write crosses a region boundary".into());
    }
    if info.Protect & 0x100 != 0 || info.Protect & 0xff == 0x01 {
        return Err(format!("address {address:#x} is guarded or inaccessible"));
    }

    if runtime
        .breakpoints
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .range(address..end)
        .next()
        .is_some()
    {
        return Err("remove overlapping software breakpoints before writing memory".into());
    }

    let target = address as *mut c_void;
    let mut old_protect = 0u32;
    // SAFETY: the range is committed and confined to one queried region.
    if unsafe {
        VirtualProtect(
            target,
            bytes.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }

    let mut written = 0usize;
    // SAFETY: VirtualProtect above made the complete destination range writable.
    let write_ok = unsafe {
        WriteProcessMemory(
            GetCurrentProcess(),
            target,
            bytes.as_ptr().cast(),
            bytes.len(),
            &mut written,
        )
    } != 0 && written == bytes.len();
    let write_error = (!write_ok).then(|| std::io::Error::last_os_error().to_string());

    let mut ignored = 0u32;
    // SAFETY: restores the protection returned by the successful VirtualProtect call.
    let restored = unsafe { VirtualProtect(target, bytes.len(), old_protect, &mut ignored) } != 0;
    if !restored {
        return Err(format!(
            "memory was written, but restoring page protection failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if let Some(error) = write_error {
        return Err(error);
    }

    if matches!(old_protect & 0xff, 0x10 | 0x20 | 0x40 | 0x80) {
        // SAFETY: flushes modified instructions in this process.
        unsafe { FlushInstructionCache(GetCurrentProcess(), target, bytes.len()) };
    }
    Ok(())
}

fn parse_hex_bytes(value: &str) -> Option<Vec<u8>> {
    let value = value.trim().trim_start_matches("0x").trim_start_matches("0X");
    if value.is_empty() || value.len() % 2 != 0 || value.len() / 2 > MAX_MEMORY_READ {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}

fn breakpoints_json(runtime: &Runtime) -> Value {
    let breakpoints = runtime.breakpoints.lock().unwrap_or_else(|e| e.into_inner());
    Value::Array(
        breakpoints
            .iter()
            .map(|(address, original)| {
                json!({
                    "address": format!("{:#x}", runtime.target.to_ida_address(*address)),
                    "original_byte": format!("{original:02X}"),
                    "enabled": true,
                })
            })
            .collect(),
    )
}

unsafe fn write_code_byte(address: usize, byte: u8) -> Result<(), String> {
    let target = address as *mut c_void;
    let mut old = 0u32;
    // SAFETY: the caller provides a committed executable address from the process map.
    if unsafe { VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &mut old) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: VirtualProtect above made this single byte writable.
    unsafe { (address as *mut u8).write_volatile(byte) };
    let mut ignored = 0u32;
    // SAFETY: restores the protection returned by the successful VirtualProtect call.
    unsafe { VirtualProtect(target, 1, old, &mut ignored) };
    // SAFETY: flushes the instruction byte just modified in this process.
    unsafe { FlushInstructionCache(GetCurrentProcess(), address as *const c_void, 1) };
    Ok(())
}

fn is_executable(address: usize) -> bool {
    // SAFETY: zeroed is a valid output buffer for MEMORY_BASIC_INFORMATION.
    let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: VirtualQuery writes to the correctly sized structure.
    let read = unsafe {
        VirtualQuery(
            address as *const c_void,
            &mut info,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    read != 0 && info.State == 0x1000 && matches!(info.Protect & 0xff, 0x10 | 0x20 | 0x40 | 0x80)
}

fn byte_at(address: usize) -> Result<u8, String> {
    let mut byte = 0u8;
    let mut read = 0usize;
    // SAFETY: ReadProcessMemory validates the supplied address in the current process.
    let ok = unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            address as *const c_void,
            (&mut byte as *mut u8).cast(),
            1,
            &mut read,
        )
    };
    if ok == 0 || read != 1 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(byte)
}

fn add_breakpoint(runtime: &Runtime, address: usize) -> Result<(), String> {
    if runtime
        .breakpoints
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&address)
    {
        return Ok(());
    }
    if !is_executable(address) {
        return Err(format!(
            "IDA/native address {:#x} (runtime {address:#x}) is not committed executable memory",
            runtime.target.to_ida_address(address)
        ));
    }

    let was_paused = runtime.control.lock().unwrap_or_else(|e| e.into_inner()).paused;
    if !was_paused {
        suspend_peers(runtime, &[]);
    }
    let result = (|| {
        let original = byte_at(address)?;
        if original == 0xCC {
            return Err(format!(
                "IDA/native address {:#x} (runtime {address:#x}) already contains an INT3 instruction",
                runtime.target.to_ida_address(address)
            ));
        }
        // SAFETY: address was checked as executable and all other process threads were suspended.
        unsafe { write_code_byte(address, 0xCC) }?;
        runtime
            .breakpoints
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(address, original);
        Ok(())
    })();
    if !was_paused {
        resume_peers(runtime);
    }
    result
}

fn remove_breakpoint(runtime: &Runtime, address: usize) -> Result<(), String> {
    let was_paused = runtime.control.lock().unwrap_or_else(|e| e.into_inner()).paused;
    if !was_paused {
        suspend_peers(runtime, &[]);
    }
    runtime
        .temporary_breakpoints
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&address);
    let original = runtime
        .breakpoints
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&address);
    let result = if let Some(original) = original {
        // SAFETY: the saved byte is the instruction that was replaced by INT3.
        unsafe { write_code_byte(address, original) }
    } else {
        Ok(())
    };
    if !was_paused {
        resume_peers(runtime);
    }
    result
}

fn pause(runtime: &Runtime) {
    let already = runtime.control.lock().unwrap_or_else(|e| e.into_inner()).paused;
    if already {
        return;
    }
    suspend_peers(runtime, &[]);
    let mut control = runtime.control.lock().unwrap_or_else(|e| e.into_inner());
    control.paused = true;
    control.reason = "manual";
    control.hit_address = None;
    control.hit_thread = None;
    control.hit_registers = None;
    control.hit_context = None;
    control.pending_context = None;
    control.exception_code = None;
    runtime.changed.notify_all();
}

fn continue_or_step(runtime: &Runtime, step: bool) -> Result<(), String> {
    let mut control = runtime.control.lock().unwrap_or_else(|e| e.into_inner());
    if !control.paused {
        return Err("the process is not paused".into());
    }
    if control.reason == "manual" {
        if step {
            return Err("single-step is available after a software breakpoint".into());
        }
        control.paused = false;
        control.reason = "running";
        control.hit_address = None;
        control.hit_thread = None;
        control.hit_registers = None;
        control.hit_context = None;
        control.exception_code = None;
        runtime.changed.notify_all();
        drop(control);
        resume_peers(runtime);
        return Ok(());
    }
    if control.reason == "io-breakpoint" {
        if step {
            return Err("single-step is not available at an I/O API breakpoint".into());
        }
        control.paused = false;
        control.reason = "running";
        control.hit_address = None;
        control.hit_thread = None;
        control.hit_registers = None;
        control.hit_context = None;
        control.pending_context = None;
        control.io_event = None;
        runtime.changed.notify_all();
        return Ok(());
    }
    if control.reason != "breakpoint" && control.reason != "step" && control.reason != "exception" {
        return Err("the current stop cannot be stepped".into());
    }
    control.action = if step { Action::Step } else { Action::Continue };
    control.paused = false;
    control.reason = "running";
    control.hit_address = None;
    control.hit_thread = None;
    control.hit_registers = None;
    control.hit_context = None;
    control.exception_code = None;
    runtime.changed.notify_all();
    Ok(())
}

fn run_to(runtime: &Runtime, address: usize) -> Result<(), String> {
    if !runtime.control.lock().unwrap_or_else(|e| e.into_inner()).paused {
        return Err("run-to requires a paused process".into());
    }
    let already_set = runtime
        .breakpoints
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&address);
    add_breakpoint(runtime, address)?;
    if !already_set {
        runtime
            .temporary_breakpoints
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(address);
    }
    if let Err(error) = continue_or_step(runtime, false) {
        if !already_set {
            remove_breakpoint(runtime, address)?;
        }
        return Err(error);
    }
    Ok(())
}

fn query_value(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (url_decode(name) == key).then(|| url_decode(value))
    })
}

fn url_decode(value: &str) -> String {
    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                if let Ok(hex) = u8::from_str_radix(&value[index + 1..index + 3], 16) {
                    out.push(hex);
                    index += 3;
                } else {
                    out.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_address(value: Option<String>, default: Option<usize>) -> Option<usize> {
    let Some(value) = value else {
        return default;
    };
    let value = value.trim().trim_start_matches("0x").trim_start_matches("0X");
    if value.is_empty() {
        return None;
    }
    usize::from_str_radix(value, 16).ok()
}

fn serve(mut stream: TcpStream, runtime: &Arc<Runtime>, port: u16) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
    let mut request = Vec::with_capacity(4096);
    let mut chunk = [0u8; 2048];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(read) => {
                request.extend_from_slice(&chunk[..read]);
                if request.len() > MAX_HTTP_HEADER {
                    respond(&mut stream, 413, "text/plain", "request too large");
                    return;
                }
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => return,
        }
    }

    let text = String::from_utf8_lossy(&request);
    let mut lines = text.split("\r\n");
    let Some(first) = lines.next() else { return };
    let mut first_parts = first.split_whitespace();
    let method = first_parts.next().unwrap_or("");
    let target = first_parts.next().unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut host = "";
    let mut origin = "";
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            match name.trim().to_ascii_lowercase().as_str() {
                "host" => host = value.trim(),
                "origin" => origin = value.trim(),
                _ => {}
            }
        }
    }

    let expected_a = format!("127.0.0.1:{port}");
    let expected_b = format!("localhost:{port}");
    if (!host.is_empty() && host != expected_a && host != expected_b)
        || (!origin.is_empty()
            && origin != format!("http://{expected_a}")
            && origin != format!("http://{expected_b}"))
    {
        respond(&mut stream, 403, "application/json", r#"{"error":"invalid host or origin"}"#);
        return;
    }

    let response = match (method, path) {
        ("GET", "/" | "/index.html") => {
            respond(&mut stream, 200, "text/html; charset=utf-8", include_str!("debugger.html"));
            return;
        }
        ("GET", "/api/status") => (200, status_json(runtime)),
        ("GET", "/api/threads") => (200, threads_json(runtime)),
        ("GET", "/api/io/breakpoints") => (200, io_breakpoints_json(runtime)),
        ("GET", "/api/io/events") => (200, io_events_json(runtime)),
        ("POST", "/api/io/breakpoints") => {
            let reads = parse_bool_parameter(query, "read");
            let writes = parse_bool_parameter(query, "write");
            if (query_value(query, "read").is_some() && reads.is_none())
                || (query_value(query, "write").is_some() && writes.is_none())
            {
                respond(&mut stream, 400, "application/json", r#"{"error":"read/write must be true or false"}"#);
                return;
            }
            let path_filter = query_value(query, "path");
            (200, configure_io_breakpoints(runtime, reads, writes, path_filter))
        }
        ("GET", "/api/wait") => {
            let timeout_ms = match query_value(query, "timeout_ms") {
                Some(value) => match value.parse::<u64>() {
                    Ok(value) => value.clamp(1, 60_000),
                    Err(_) => {
                        respond(&mut stream, 400, "application/json", r#"{"error":"invalid timeout_ms"}"#);
                        return;
                    }
                },
                None => 30_000,
            };
            (200, wait_for_stop(runtime, Duration::from_millis(timeout_ms)))
        }
        ("POST", "/api/registers/set") => {
            let Some(thread_id) = query_value(query, "thread")
                .and_then(|value| value.parse::<u32>().ok())
            else {
                respond(&mut stream, 400, "application/json", r#"{"error":"invalid thread ID"}"#);
                return;
            };
            let Some(name) = query_value(query, "name") else {
                respond(&mut stream, 400, "application/json", r#"{"error":"missing register name"}"#);
                return;
            };
            let Some(value) = parse_address(query_value(query, "value"), None) else {
                respond(&mut stream, 400, "application/json", r#"{"error":"missing or invalid register value"}"#);
                return;
            };
            match set_register(runtime, thread_id, &name, value as u64) {
                Ok(value) => (200, value),
                Err(error) => (409, json!({"error": error})),
            }
        }
        ("GET", "/api/stack") => {
            let Some(thread_id) = query_value(query, "thread")
                .and_then(|value| value.parse::<u32>().ok())
            else {
                respond(&mut stream, 400, "application/json", r#"{"error":"invalid thread ID"}"#);
                return;
            };
            match stack_json(runtime, thread_id) {
                Ok(value) => (200, value),
                Err(error) if error == "stack inspection requires a paused process" => {
                    (409, json!({"error": error}))
                }
                Err(error) => (404, json!({"error": error})),
            }
        }
        ("GET", "/api/registers") => {
            let Some(thread_id) = query_value(query, "thread")
                .and_then(|value| value.parse::<u32>().ok())
            else {
                respond(&mut stream, 400, "application/json", r#"{"error":"invalid thread ID"}"#);
                return;
            };
            match registers_json(runtime, thread_id) {
                Ok(value) => (200, value),
                Err(error) => (404, json!({"error": error})),
            }
        }
        ("GET", "/api/regions") => {
            let Some(cursor) = parse_address(query_value(query, "cursor"), Some(0)) else {
                respond(&mut stream, 400, "application/json", r#"{"error":"invalid cursor"}"#);
                return;
            };
            let cursor = match runtime.target.to_process_address(cursor as u64) {
                Ok(address) => address,
                Err(error) => {
                    respond(&mut stream, 400, "application/json", &json!({"error": error}).to_string());
                    return;
                }
            };
            let limit = query_value(query, "limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(250)
                .clamp(1, 500);
            (200, regions_json(runtime, cursor, limit))
        }
        ("GET", "/api/memory") => {
            let Some(address) = parse_address(query_value(query, "address"), None) else {
                respond(&mut stream, 400, "application/json", r#"{"error":"invalid address"}"#);
                return;
            };
            let address = match runtime.target.to_process_address(address as u64) {
                Ok(address) => address,
                Err(error) => {
                    respond(&mut stream, 400, "application/json", &json!({"error": error}).to_string());
                    return;
                }
            };
            let length = query_value(query, "length")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0x100);
            (200, memory_json(runtime, address, length))
        }
        ("POST", "/api/memory/write") => {
            let Some(address) = parse_address(query_value(query, "address"), None) else {
                respond(&mut stream, 400, "application/json", r#"{"error":"missing or invalid address"}"#);
                return;
            };
            let Some(bytes) = query_value(query, "hex").and_then(|value| parse_hex_bytes(&value)) else {
                respond(&mut stream, 400, "application/json", r#"{"error":"missing or invalid hex payload (expected 1-4096 bytes)"}"#);
                return;
            };
            let address = match runtime.target.to_process_address(address as u64) {
                Ok(address) => address,
                Err(error) => {
                    respond(&mut stream, 400, "application/json", &json!({"error": error}).to_string());
                    return;
                }
            };
            match write_memory(runtime, address, &bytes) {
                Ok(()) => (200, json!({
                    "address": format!("{:#x}", runtime.target.to_ida_address(address)),
                    "written": bytes.len(),
                    "hex": bytes.iter().map(|byte| format!("{byte:02X}")).collect::<String>(),
                })),
                Err(error) => (409, json!({"error": error})),
            }
        }
        ("GET", "/api/breakpoints") => (200, breakpoints_json(runtime)),
        ("POST", "/api/pause") => {
            pause(runtime);
            (200, status_json(runtime))
        }
        ("POST", "/api/resume") => match continue_or_step(runtime, false) {
            Ok(()) => (200, status_json(runtime)),
            Err(error) => (409, json!({"error": error})),
        },
        ("POST", "/api/step") => match continue_or_step(runtime, true) {
            Ok(()) => (200, status_json(runtime)),
            Err(error) => (409, json!({"error": error})),
        },
        ("POST", "/api/runto") => {
            let Some(address) = parse_address(query_value(query, "address"), None) else {
                respond(&mut stream, 400, "application/json", r#"{"error":"missing or invalid address"}"#);
                return;
            };
            let address = match runtime.target.to_process_address(address as u64) {
                Ok(address) => address,
                Err(error) => {
                    respond(&mut stream, 400, "application/json", &json!({"error": error}).to_string());
                    return;
                }
            };
            match run_to(runtime, address) {
                Ok(()) => (200, status_json(runtime)),
                Err(error) => (409, json!({"error": error})),
            }
        }
        ("POST", "/api/breakpoints/add") => {
            let Some(address) = parse_address(query_value(query, "address"), None) else {
                respond(&mut stream, 400, "application/json", r#"{"error":"invalid address"}"#);
                return;
            };
            let address = match runtime.target.to_process_address(address as u64) {
                Ok(address) => address,
                Err(error) => {
                    respond(&mut stream, 400, "application/json", &json!({"error": error}).to_string());
                    return;
                }
            };
            match add_breakpoint(runtime, address) {
                Ok(()) => (200, breakpoints_json(runtime)),
                Err(error) => (400, json!({"error": error})),
            }
        }
        ("POST", "/api/breakpoints/remove") => {
            let Some(address) = parse_address(query_value(query, "address"), None) else {
                respond(&mut stream, 400, "application/json", r#"{"error":"invalid address"}"#);
                return;
            };
            let address = match runtime.target.to_process_address(address as u64) {
                Ok(address) => address,
                Err(error) => {
                    respond(&mut stream, 400, "application/json", &json!({"error": error}).to_string());
                    return;
                }
            };
            match remove_breakpoint(runtime, address) {
                Ok(()) => (200, breakpoints_json(runtime)),
                Err(error) => (400, json!({"error": error})),
            }
        }
        _ => {
            respond(&mut stream, 404, "application/json", r#"{"error":"not found"}"#);
            return;
        }
    };

    let body = serde_json::to_string(&response.1).unwrap_or_else(|_| "{}".into());
    respond(&mut stream, response.0, "application/json; charset=utf-8", &body);
}

fn respond(stream: &mut TcpStream, status: u16, content_type: &str, body: &str) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        _ => "Internal Server Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breakpoint_context_rip_is_the_int3_address() {
        let mut context = AlignedContext(unsafe { std::mem::zeroed() });
        context.0.Rip = 0x00007ff908101ec8;

        assert_eq!(breakpoint_address(&context.0), 0x00007ff908101ec8);
    }

    #[test]
    fn register_writer_updates_general_purpose_registers() {
        let mut context = AlignedContext(unsafe { std::mem::zeroed() });
        set_context_register(&mut context.0, "RAX", 0x1234).unwrap();
        set_context_register(&mut context.0, "rip", 0x140001000).unwrap();
        set_context_register(&mut context.0, "rflags", 0x202).unwrap();

        assert_eq!(context.0.Rax, 0x1234);
        assert_eq!(context.0.Rip, 0x140001000);
        assert_eq!(context.0.EFlags, 0x202);
        assert!(set_context_register(&mut context.0, "xmm0", 0).is_err());
        assert!(set_context_register(&mut context.0, "rflags", u64::MAX).is_err());
    }

    #[test]
    fn memory_write_hex_parser_is_bounded_and_strict() {
        assert_eq!(parse_hex_bytes("4883EC28"), Some(vec![0x48, 0x83, 0xEC, 0x28]));
        assert_eq!(parse_hex_bytes("0xCC"), Some(vec![0xCC]));
        assert_eq!(parse_hex_bytes("0"), None);
        assert_eq!(parse_hex_bytes("GG"), None);
        assert_eq!(parse_hex_bytes(""), None);
        assert_eq!(parse_hex_bytes(&"AA".repeat(MAX_MEMORY_READ + 1)), None);
    }

    #[test]
    fn address_parser_accepts_hex_addresses() {
        assert_eq!(parse_address(Some("0x7ff900001000".into()), None), Some(0x7ff900001000));
        assert_eq!(parse_address(Some("7FF900001000".into()), None), Some(0x7ff900001000));
        assert_eq!(parse_address(Some("invalid".into()), None), None);
        assert_eq!(parse_address(None, None), None);
        assert_eq!(parse_address(None, Some(0)), Some(0));
    }

    #[test]
    fn title_addresses_translate_to_and_from_ida_space() {
        let target = DebugTarget {
            title: "test".into(),
            build_hash: "test".into(),
            image_base: 0x00007ff600000000,
            ida_base: 0x140000000,
            image_size: 0x300000,
            entry_rva: 0x1000,
        };

        let process_address = target.image_base + 0x1234;
        let ida_address = 0x140001234;

        assert_eq!(target.to_ida_address(process_address), ida_address);
        assert_eq!(target.to_process_address(ida_address), Ok(process_address));
        let image_end = target.image_base + target.image_size;
        let ida_image_end = target.ida_base + target.image_size as u64;
        assert_eq!(target.to_ida_boundary(image_end), ida_image_end);
        assert_eq!(target.to_process_address(ida_image_end), Ok(image_end));

        let external_address = 0x00007ff700001000usize;
        assert_eq!(target.to_ida_address(external_address), external_address as u64);
        assert_eq!(
            target.to_process_address(external_address as u64),
            Ok(external_address)
        );
    }

    #[test]
    fn default_winmain_breakpoint_is_rebased_from_ida_space() {
        let target = DebugTarget {
            title: "test".into(),
            build_hash: "test".into(),
            image_base: 0x00007ff600000000,
            ida_base: 0x140000000,
            image_size: 0x06000000,
            entry_rva: 0x1000,
        };
        let expected = target.image_base + 0x05a91bd0;

        assert_eq!(default_winmain_address(&target), Some(expected));
        assert_eq!(target.to_ida_address(expected), DEFAULT_WINMAIN_IDA_ADDRESS);
    }

    #[test]
    fn default_winmain_breakpoint_is_skipped_outside_title_image() {
        let target = DebugTarget {
            title: "test".into(),
            build_hash: "test".into(),
            image_base: 0x00007ff600000000,
            ida_base: 0x140000000,
            image_size: 0x300000,
            entry_rva: 0x1000,
        };

        assert_eq!(default_winmain_address(&target), None);
    }

    #[test]
    fn url_decoder_handles_query_values() {
        assert_eq!(url_decode("hello+world"), "hello world");
        assert_eq!(url_decode("%2Fapi%2Fstatus"), "/api/status");
    }
}
