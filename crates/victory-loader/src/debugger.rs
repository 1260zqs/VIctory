//! Native debugger handoff before the Xbox title's entry point runs.

use std::time::Duration;

/// Waits until a native debugger attaches, then breaks before guest execution.
///
/// At this point the title image is already mapped and its imports are bound,
/// so the debugger can inspect the module and install RVA breakpoints before
/// the original entry point starts.
pub fn wait_for_debugger() {
    use windows_sys::Win32::System::Diagnostics::Debug::{DebugBreak, IsDebuggerPresent};

    tracing::info!("waiting for a native debugger to attach before title execution");
    while unsafe { IsDebuggerPresent() } == 0 {
        std::thread::sleep(Duration::from_millis(100));
    }

    tracing::info!("native debugger attached; breaking before the title entry point");
    // SAFETY: intentionally raises a breakpoint exception for the attached debugger.
    unsafe { DebugBreak() };
}
