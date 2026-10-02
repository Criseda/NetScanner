//! The interactive status line: one self-updating line on stderr while
//! a text scan runs in a terminal, e.g.
//!
//!     ⠹ Scanning 192.168.1.0/24… 42% · 7 hosts found
//!     ⠼ Identifying devices… 3 of 9
//!
//! The results themselves print once, as the summary at the end, so a
//! terminal no longer shows every host twice (streamed, then summary).
//! main.zig turns this on only when stdout and stderr are both a
//! terminal and output is text; pipes, files and `--json` keep
//! streaming results line by line.
//!
//! Drawing goes through std.Progress, the standard library's terminal
//! progress renderer, rather than hand-written escape codes. It handles
//! each platform properly: ANSI escape codes where the terminal speaks
//! them (enabling virtual terminal processing on Windows 10+ consoles),
//! the Windows console API on older consoles, line width from
//! TIOCGWINSZ / GetConsoleScreenBufferInfo, redraws on SIGWINCH, and
//! clearing the line before anything else writes to stderr.
//!
//! The braille spinner, ellipsis and middle dot need a UTF-8 terminal,
//! so glyphs() asks each platform properly and falls back to ASCII
//! (`| Scanning 192.168.1.0/24... 42% - 7 hosts found`) otherwise.
//!
//! This file only decides what the line says. A ticker thread rebuilds
//! the text a few times a second from counters the scan bumps (found
//! results, the phase's ProgressMeter), so workers never format or lock
//! anything for it.

const std = @import("std");
const builtin = @import("builtin");
const interrupt = @import("interrupt.zig");
const ProgressMeter = @import("progress.zig").ProgressMeter;

/// How often the text (and the spinner frame) is rebuilt; matches
/// std.Progress's default 80ms redraw, so every frame gets drawn.
const TICK_MS = 80;

/// The characters the line is drawn with.
pub const Glyphs = struct {
    spinner: []const []const u8,
    ellipsis: []const u8,
    separator: []const u8,

    pub const unicode: Glyphs = .{
        .spinner = &.{ "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏" },
        .ellipsis = "…",
        .separator = "·",
    };
    pub const ascii: Glyphs = .{
        .spinner = &.{ "|", "/", "-", "\\" },
        .ellipsis = "...",
        .separator = "-",
    };
};

/// Unicode glyphs when the terminal decodes UTF-8, ASCII otherwise.
///
/// POSIX: the locale says how the terminal decodes bytes, resolved the
/// standard way (see localeIsUtf8).
/// Windows: the console's output code page decides, as it does for
/// std.Progress's own tree symbols. 65001 is UTF-8; anything else (the
/// OEM default, 437 or 850) would garble braille. ns never changes the
/// code page itself: the console is shared with the user's shell, so
/// the change would outlive the scan.
pub fn glyphs(io: std.Io, env: *const std.process.Environ.Map) Glyphs {
    if (comptime builtin.os.tag == .windows) {
        var get_cp = std.os.windows.CONSOLE.USER_IO.GET_CP(.Output);
        const status = get_cp.operate(io, .stderr()) catch return .ascii;
        const utf8 = status == .SUCCESS and get_cp.Data.CodePage == 65001;
        return if (utf8) .unicode else .ascii;
    }
    return if (localeIsUtf8(env.get("LC_ALL"), env.get("LC_CTYPE"), env.get("LANG"))) .unicode else .ascii;
}

/// POSIX locale resolution for character encoding: the first of LC_ALL,
/// LC_CTYPE, LANG that is set and non-empty wins, and its codeset
/// (after the dot, e.g. `en_GB.UTF-8`) names the encoding. Unset, or
/// `C` / `POSIX`, means plain ASCII.
pub fn localeIsUtf8(lc_all: ?[]const u8, lc_ctype: ?[]const u8, lang: ?[]const u8) bool {
    const locale = for ([_]?[]const u8{ lc_all, lc_ctype, lang }) |v| {
        if (v) |s| if (s.len > 0) break s;
    } else return false;
    const dot = std.mem.indexOfScalar(u8, locale, '.') orelse return false;
    // Drop a trailing @modifier, as in `de_DE.UTF-8@euro`.
    const codeset_end = std.mem.indexOfScalarPos(u8, locale, dot, '@') orelse locale.len;
    const codeset = locale[dot + 1 .. codeset_end];
    return std.ascii.eqlIgnoreCase(codeset, "UTF-8") or std.ascii.eqlIgnoreCase(codeset, "utf8");
}

/// The longest prefix of `line` within `max_bytes` that does not split a
/// UTF-8 character. std.Progress cuts lines to the terminal width in
/// bytes, which could leave half a braille or `…` sequence (drawn as
/// garbage) on a narrow terminal; cutting here first avoids that.
pub fn truncateUtf8(line: []const u8, max_bytes: usize) []const u8 {
    if (line.len <= max_bytes) return line;
    var end = max_bytes;
    // A continuation byte (10xxxxxx) at the cut means a character
    // straddles it: back up to that character's first byte.
    while (end > 0 and line[end] & 0xC0 == 0x80) end -= 1;
    return line[0..end];
}

/// Terminal width in columns, asked the same way std.Progress does:
/// TIOCGWINSZ on POSIX, the console screen buffer info on Windows.
/// Queried on every tick, so resizes are picked up. Null if unknown.
fn terminalColumns(io: std.Io) ?usize {
    if (comptime builtin.os.tag == .windows) {
        var info = std.os.windows.CONSOLE.USER_IO.GET_SCREEN_BUFFER_INFO;
        const status = info.operate(io, .stderr()) catch return null;
        if (status != .SUCCESS or info.Data.dwWindowSize.X <= 0) return null;
        return @intCast(info.Data.dwWindowSize.X);
    }
    var winsize: std.posix.winsize = .{ .row = 0, .col = 0, .xpixel = 0, .ypixel = 0 };
    const result = io.operate(.{ .device_io_control = .{
        .file = .stderr(),
        .code = std.posix.T.IOCGWINSZ,
        .arg = &winsize,
    } }) catch return null;
    if (result.device_io_control < 0 or winsize.col == 0) return null;
    return winsize.col;
}

pub const Live = struct {
    io: std.Io,
    root: std.Progress.Node = .none,
    /// What the results are called, e.g. "host found" / "hosts found".
    noun: Noun,
    found: std.atomic.Value(usize) = .init(0),
    /// Guards `phase`: the scan switches phases while the ticker reads.
    phase_mutex: std.Io.Mutex = .init,
    phase: Phase,
    ticker: ?std.Thread = null,
    stop: std.Io.Event = .unset,
    /// Set from glyphs() by whoever turns the line on.
    glyphs: Glyphs = .ascii,

    pub const Noun = struct { one: []const u8, many: []const u8 };

    pub const Phase = struct {
        /// e.g. "Scanning 192.168.1.0/24" or "Identifying devices".
        label: []const u8,
        /// Progress through this phase; null for phases too quick or
        /// too open-ended to measure (reading the ARP table). Read by
        /// the ticker thread: see setMeter for who keeps it alive.
        meter: ?*const ProgressMeter = null,
        /// `percent` shows the found count plus a percentage; `count`
        /// shows "N of M", for small phases counted in hosts.
        style: enum { percent, count } = .percent,
    };

    pub fn init(io: std.Io, noun: Noun, phase: Phase) Live {
        return .{ .io = io, .noun = noun, .phase = phase };
    }

    /// Start drawing. Call once nothing else will write to stdout until
    /// finish(): stdout and the status line share the terminal, and
    /// only stderr writes are coordinated with it. If std.Progress has
    /// nowhere to draw (no threads, say) this does nothing; the summary
    /// still prints, so no result is lost. Call at most once per process.
    pub fn begin(self: *Live) void {
        self.root = std.Progress.start(self.io, .{});
        if (self.root.index == .none) return;
        self.ticker = std.Thread.spawn(.{}, tick, .{self}) catch {
            self.root.end();
            self.root = .none;
            return;
        };
        // Repeat the test std.Progress used to pick escape codes over
        // the legacy Windows console API (it is idempotent): only an
        // escape-code line can be erased by the second Ctrl+C.
        const escape_codes = if (std.Io.File.stderr().enableAnsiEscapeCodes(self.io)) |_| true else |_| false;
        interrupt.eraseStatusLineOnQuit(escape_codes);
    }

    /// Stop the ticker and clear the line, so the summary prints on a
    /// clean terminal. Idempotent.
    pub fn finish(self: *Live) void {
        const ticker = self.ticker orelse return;
        // std.Progress clears the line below. Turned off first, so a
        // second Ctrl+C can never erase part of the summary instead.
        interrupt.eraseStatusLineOnQuit(false);
        self.stop.set(self.io);
        ticker.join();
        self.ticker = null;
        self.root.end();
        self.root = .none;
    }

    pub fn setPhase(self: *Live, phase: Phase) void {
        self.phase_mutex.lockUncancelable(self.io);
        defer self.phase_mutex.unlock(self.io);
        self.phase = phase;
    }

    /// Attach the meter of the current phase, keeping its label. For
    /// scans whose caller names the phase but whose engine owns the
    /// meter (port scans). The ticker reads the meter from its own
    /// thread, so its owner detaches it (null) before the meter goes
    /// out of scope, usually with a `defer` right after attaching.
    pub fn setMeter(self: *Live, meter: ?*const ProgressMeter) void {
        self.phase_mutex.lockUncancelable(self.io);
        defer self.phase_mutex.unlock(self.io);
        self.phase.meter = meter;
    }

    /// Count one result (a host up, an open port).
    pub fn addFound(self: *Live) void {
        _ = self.found.fetchAdd(1, .monotonic);
    }

    fn tick(self: *Live) void {
        var frame: usize = 0;
        while (true) : (frame +%= 1) {
            self.render(frame);
            const timeout: std.Io.Timeout = .{ .duration = .{
                .clock = .awake,
                .raw = .fromMilliseconds(TICK_MS),
            } };
            // Returns at once when finish() sets the event.
            if (self.stop.waitTimeout(self.io, timeout)) |_| return else |err| switch (err) {
                error.Timeout => {},
                error.Canceled => return,
            }
        }
    }

    fn render(self: *Live, frame: usize) void {
        var buf: [std.Progress.Node.max_name_len]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        {
            // Held while formatting, which reads the phase's meter: once
            // setMeter(null) returns, no frame can still be reading a
            // meter whose owner is about to return. Workers never take
            // this lock, so it costs the scan nothing.
            self.phase_mutex.lockUncancelable(self.io);
            defer self.phase_mutex.unlock(self.io);
            // A full buffer only shortens the line, so overflow is
            // ignored; truncateUtf8 below also repairs a character cut
            // by the buffer.
            writeStatus(&w, self.glyphs, frame, self.phase, self.found.load(.monotonic), self.noun) catch {};
        }
        const width = terminalColumns(self.io) orelse buf.len;
        self.root.setName(truncateUtf8(w.buffered(), width));
    }
};

/// Compose one status line. Separate from the ticker so the wording is
/// testable without a terminal.
pub fn writeStatus(
    w: *std.Io.Writer,
    g: Glyphs,
    frame: usize,
    phase: Live.Phase,
    found: usize,
    noun: Live.Noun,
) std.Io.Writer.Error!void {
    const spinner = g.spinner[frame % g.spinner.len];
    if (interrupt.requested()) {
        try w.print("{s} Stopping{s} finishing probes in flight (Ctrl+C again to quit now)", .{ spinner, g.ellipsis });
        return;
    }
    try w.print("{s} {s}{s}", .{ spinner, phase.label, g.ellipsis });
    switch (phase.style) {
        .percent => {
            if (phase.meter) |m| try w.print(" {d}% {s}", .{ m.percent(), g.separator });
            try w.print(" {d} {s}", .{ found, if (found == 1) noun.one else noun.many });
        },
        .count => if (phase.meter) |m| {
            try w.print(" {d} of {d}", .{ m.completed(), m.total });
        },
    }
}
