//! Graceful Ctrl+C for interactive scans. With the status line on, scan
//! results print only at the end, so the default Ctrl+C (kill at once)
//! would throw away everything found so far. Instead the first press
//! asks the scan to stop: worker pools stop taking new work, probes in
//! flight finish (each is bounded by its timeout), and the partial
//! results print. A second press quits immediately, as usual.
//!
//! Each OS gets its native mechanism:
//! - POSIX: a SIGINT handler. The first press only stores an atomic
//!   flag. The second erases the status line, then re-raises SIGINT
//!   with the default action, so the process dies exactly as an
//!   unhandled Ctrl+C would. Both paths are async-signal-safe.
//! - Windows: SetConsoleCtrlHandler. The handler runs on a thread the
//!   system creates, not in signal context. On the second press it
//!   erases the status line and returns FALSE, which passes the event
//!   to the default handler, and that ends the process.
//!
//! Only interactive scans install this. Piped and `--json` scans stream
//! their results as they go, so the default Ctrl+C loses nothing there.

const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;

var stop_requested: std.atomic.Value(bool) = .init(false);

/// Set while the status line (live.zig) is drawn with escape codes. A
/// second Ctrl+C ends the process without the clean shutdown that
/// normally clears the line, so it erases the line itself; otherwise
/// the last frame stays on screen and the terminal's tab or taskbar
/// progress keeps spinning.
var erase_on_quit: std.atomic.Value(bool) = .init(false);

/// What std.Progress writes to take its line down when it ends
/// cleanly (clearWrittenWithEscapeCodes). It keeps the cursor at the
/// start of its line, so this erases from there to the end of the
/// screen, then clears the tab or taskbar progress (OSC 9;4;0). The
/// leading \r also covers a frame the signal cut short.
const erase_status_line = "\r\x1b[J\x1b]9;4;0\x1b\\";

/// True once the user has pressed Ctrl+C.
pub fn requested() bool {
    return stop_requested.load(.monotonic);
}

/// The flag itself, for the scan engine's `cancel` option: its worker
/// pools check it before taking the next unit of work. The engine takes
/// a pointer rather than reading this module, so it has no global state
/// and tests can stop a scan with a flag of their own.
pub fn flag() *const std.atomic.Value(bool) {
    return &stop_requested;
}

/// Whether a second Ctrl+C should erase the status line before the
/// process dies. live.zig turns this on while it draws with escape
/// codes, and off before it clears the line itself. Under the legacy
/// Windows console API there is nothing a raw write could erase, so
/// it stays off there.
pub fn eraseStatusLineOnQuit(erase: bool) void {
    erase_on_quit.store(erase, .monotonic);
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
            // RESTART: resume interrupted syscalls where the OS allows
            // instead of failing them with EINTR.
            .flags = std.posix.SA.RESTART,
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
        restoreDefaultSigint();
        std.posix.raise(.INT) catch {};
        // Only reached if the signal is blocked: still report it.
        std.process.exit(128 + @as(u8, @intCast(@intFromEnum(std.posix.SIG.INT))));
    }
}

fn restoreDefaultSigint() void {
    const default: std.posix.Sigaction = .{
        .handler = .{ .handler = std.posix.SIG.DFL },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.INT, &default, null);
}

/// Take the status line down with one raw write. Safe in a signal
/// handler (write is async-signal-safe) and on the Windows handler
/// thread, which the scan's own I/O knows nothing about.
fn eraseStatusLine() void {
    if (!erase_on_quit.load(.monotonic)) return;
    const stderr = std.Io.File.stderr().handle;
    if (comptime builtin.os.tag == .windows) {
        var written: windows.DWORD = 0;
        _ = WriteFile(stderr, erase_status_line, erase_status_line.len, &written, null);
    } else {
        _ = std.c.write(stderr, erase_status_line, erase_status_line.len);
    }
}

fn handleSigint(_: std.posix.SIG) callconv(.c) void {
    // First press: ask the scan to stop.
    if (!stop_requested.swap(true, .monotonic)) return;
    // Second press: quit now. SIGINT stays blocked while this handler
    // runs, so the raised signal arrives, with the default action, the
    // moment it returns. write, sigaction and raise are all
    // async-signal-safe.
    eraseStatusLine();
    restoreDefaultSigint();
    std.posix.raise(.INT) catch {};
}

const CTRL_C_EVENT: windows.DWORD = 0;
const CTRL_BREAK_EVENT: windows.DWORD = 1;

fn handleConsoleCtrl(ctrl_type: windows.DWORD) callconv(.winapi) windows.BOOL {
    // Close, logoff and shutdown events keep their default handling.
    if (ctrl_type != CTRL_C_EVENT and ctrl_type != CTRL_BREAK_EVENT) return .FALSE;
    // First press: ask the scan to stop.
    if (!stop_requested.swap(true, .monotonic)) return .TRUE;
    // Second press: not handled, so the default handler ends the process.
    eraseStatusLine();
    return .FALSE;
}

const HandlerRoutine = *const fn (windows.DWORD) callconv(.winapi) windows.BOOL;
extern "kernel32" fn SetConsoleCtrlHandler(handler: ?HandlerRoutine, add: windows.BOOL) callconv(.winapi) windows.BOOL;
extern "kernel32" fn ExitProcess(exit_code: windows.UINT) callconv(.winapi) noreturn;
extern "kernel32" fn WriteFile(
    file: windows.HANDLE,
    buffer: [*]const u8,
    bytes_to_write: windows.DWORD,
    bytes_written: ?*windows.DWORD,
    overlapped: ?*anyopaque,
) callconv(.winapi) windows.BOOL;
