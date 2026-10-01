//! Graceful Ctrl+C for interactive scans. With the status line on, scan
//! results print only at the end, so the default Ctrl+C (kill at once)
//! would throw away everything found so far. Instead the first press
//! asks the scan to stop: worker pools stop taking new work, probes in
//! flight finish (each is bounded by its timeout), and the partial
//! results print. A second press quits immediately, as usual.
//!
//! Each OS gets its native mechanism:
//! - POSIX: a SIGINT handler installed with SA_RESETHAND, so the kernel
//!   restores the default action after the first signal and a second
//!   Ctrl+C terminates without our involvement. The handler only stores
//!   an atomic flag, which is async-signal-safe.
//! - Windows: SetConsoleCtrlHandler. The handler runs on a thread the
//!   system creates, not in signal context; returning FALSE on the
//!   second press passes the event to the default handler, which ends
//!   the process.
//!
//! Only interactive scans install this. Piped and `--json` scans stream
//! their results as they go, so the default Ctrl+C loses nothing there.

const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;

var stop_requested: std.atomic.Value(bool) = .init(false);

/// True once the user has pressed Ctrl+C. Worker pools check this
/// before taking the next unit of work.
pub fn requested() bool {
    return stop_requested.load(.monotonic);
}

/// Take over the first Ctrl+C for the rest of the process.
pub fn install() void {
    if (comptime builtin.os.tag == .windows) {
        _ = SetConsoleCtrlHandler(handleConsoleCtrl, .TRUE);
    } else {
        // An ignored SIGINT (nohup, background jobs of a script) means
        // whoever started us does not want Ctrl+C to reach us: leave it
        // ignored, as POSIX shells and well-behaved tools do.
        var current: std.posix.Sigaction = undefined;
        std.posix.sigaction(.INT, null, &current);
        if (current.handler.handler == std.posix.SIG.IGN) return;

        const act: std.posix.Sigaction = .{
            .handler = .{ .handler = handleSigint },
            .mask = std.posix.sigemptyset(),
            // RESETHAND: one-shot, so the second Ctrl+C gets the default
            // action. RESTART: resume interrupted syscalls where the OS
            // allows instead of failing them with EINTR.
            .flags = std.posix.SA.RESETHAND | std.posix.SA.RESTART,
        };
        std.posix.sigaction(.INT, &act, null);
    }
}

/// End the process the way an unhandled Ctrl+C would have, after the
/// partial results are out. Shells and scripts then see an interrupt,
/// not a success: on POSIX the process dies by SIGINT (status 130 in
/// shells, and `while` loops around `ns` stop as they should); on
/// Windows it exits with STATUS_CONTROL_C_EXIT, the code the default
/// console handler uses.
pub fn exitInterrupted() noreturn {
    if (comptime builtin.os.tag == .windows) {
        ExitProcess(@intFromEnum(windows.NTSTATUS.CONTROL_C_EXIT));
    } else {
        // SA_RESETHAND already restored the default action, but set it
        // explicitly so this holds however the flag was raised.
        const default: std.posix.Sigaction = .{
            .handler = .{ .handler = std.posix.SIG.DFL },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(.INT, &default, null);
        std.posix.raise(.INT) catch {};
        // Only reached if the signal is blocked: still report it.
        std.process.exit(128 + @as(u8, @intCast(@intFromEnum(std.posix.SIG.INT))));
    }
}

fn handleSigint(_: std.posix.SIG) callconv(.c) void {
    stop_requested.store(true, .monotonic);
}

const CTRL_C_EVENT: windows.DWORD = 0;
const CTRL_BREAK_EVENT: windows.DWORD = 1;

fn handleConsoleCtrl(ctrl_type: windows.DWORD) callconv(.winapi) windows.BOOL {
    // Close, logoff and shutdown events keep their default handling.
    if (ctrl_type != CTRL_C_EVENT and ctrl_type != CTRL_BREAK_EVENT) return .FALSE;
    // Second press: not handled, so the default handler ends the process.
    if (stop_requested.swap(true, .monotonic)) return .FALSE;
    return .TRUE;
}

const HandlerRoutine = *const fn (windows.DWORD) callconv(.winapi) windows.BOOL;
extern "kernel32" fn SetConsoleCtrlHandler(handler: ?HandlerRoutine, add: windows.BOOL) callconv(.winapi) windows.BOOL;
extern "kernel32" fn ExitProcess(exit_code: windows.UINT) callconv(.winapi) noreturn;
