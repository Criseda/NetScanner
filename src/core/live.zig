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
//! the text a few times a second from the scan's progress.Tracker, which
//! the caller owns, so workers never format or lock anything for it and
//! nothing the ticker reads can go out of scope under it. The scan
//! engine knows the line only as a progress.Display: two hooks, to
//! appear after its header and to get out of the way before results.

const std = @import("std");
const builtin = @import("builtin");
const interrupt = @import("interrupt.zig");
const progress = @import("progress.zig");

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

/// True when TERM says the terminal cannot move the cursor or erase a
/// line (`dumb`: Emacs shell mode, some CI ptys). Such a terminal is
/// still a tty, and std.Progress never checks TERM, so main.zig asks
/// here and keeps streaming results instead of drawing the status line.
/// Unset or empty TERM is not dumb: Windows consoles set none.
pub fn isDumbTerminal(term: ?[]const u8) bool {
    const name = term orelse return false;
    return std.mem.eql(u8, name, "dumb");
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
    /// What the line shows. The caller owns it and keeps it alive at
    /// least as long as this Live, so the ticker can always read it.
    tracker: *progress.Tracker,
    /// What the probing phase is called, e.g. "Scanning 192.168.1.0/24".
    label: []const u8,
    /// What the results are called, e.g. "host found" / "hosts found".
    noun: Noun,
    root: std.Progress.Node = .none,
    ticker: ?std.Thread = null,
    stop: std.Io.Event = .unset,
    /// Set from glyphs() by whoever turns the line on.
    glyphs: Glyphs = .ascii,
    /// Whether the line is drawn with escape codes, as opposed to the
    /// legacy Windows console API (or not at all). Set by begin().
    escape_codes: bool = false,

    pub const Noun = struct { one: []const u8, many: []const u8 };

    pub fn init(io: std.Io, tracker: *progress.Tracker, label: []const u8, noun: Noun) Live {
        return .{ .io = io, .tracker = tracker, .label = label, .noun = noun };
    }

    /// The hooks the scan engine calls: begin() once its header is out,
    /// end() before its results print (see progress.Display).
    pub fn display(self: *Live) progress.Display {
        return .{ .context = self, .beginFn = beginOpaque, .endFn = endOpaque };
    }

    fn beginOpaque(context: *anyopaque) void {
        const self: *Live = @ptrCast(@alignCast(context));
        self.begin();
    }

    fn endOpaque(context: *anyopaque) void {
        const self: *Live = @ptrCast(@alignCast(context));
        self.end();
    }

    /// Start drawing. Call once nothing else will write to stdout until
    /// end(): stdout and the status line share the terminal, and only
    /// stderr writes are coordinated with it. If std.Progress has
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
        self.escape_codes = if (std.Io.File.stderr().enableAnsiEscapeCodes(self.io)) |_| true else |_| false;
        interrupt.eraseStatusLineOnQuit(self.escape_codes);
    }

    /// Stop the ticker and clear the line, so the results print on a
    /// clean terminal. Idempotent, and a no-op if begin() never drew.
    pub fn end(self: *Live) void {
        const ticker = self.ticker orelse return;
        // std.Progress clears the line below. Turned off first, so a
        // second Ctrl+C can never erase part of the summary instead.
        interrupt.eraseStatusLineOnQuit(false);
        self.stop.set(self.io);
        ticker.join();
        self.ticker = null;
        self.root.end();
        self.root = .none;
        // The terminal echoes Ctrl+C (and anything typed) as `^C` at
        // the start of the line, moving the cursor along. std.Progress
        // clears from the cursor onwards, so when the scan ends before
        // the next frame the echo survives and the summary prints right
        // after it (`^C192.168.1.1`). Clear the whole line instead.
        if (self.escape_codes) std.Io.File.stderr().writeStreamingAll(self.io, "\r\x1b[K") catch {};
    }

    fn tick(self: *Live) void {
        var frame: usize = 0;
        while (true) : (frame +%= 1) {
            self.render(frame);
            const timeout: std.Io.Timeout = .{ .duration = .{
                .clock = .awake,
                .raw = .fromMilliseconds(TICK_MS),
            } };
            // Returns at once when end() sets the event.
            if (self.stop.waitTimeout(self.io, timeout)) |_| return else |err| switch (err) {
                error.Timeout => {},
                error.Canceled => return,
            }
        }
    }

    fn render(self: *Live, frame: usize) void {
        const status: Status = .{
            .label = self.label,
            .noun = self.noun,
            .progress = self.tracker.snapshot(self.io),
            .stopping = interrupt.requested(),
        };
        var buf: [std.Progress.Node.max_name_len]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        // A full buffer only shortens the line, so overflow is ignored;
        // truncateUtf8 below also repairs a character cut by the buffer.
        writeStatus(&w, self.glyphs, frame, status) catch {};
        const width = terminalColumns(self.io) orelse buf.len;
        self.root.setName(truncateUtf8(w.buffered(), width));
    }
};

/// What one frame of the status line is made of.
pub const Status = struct {
    /// What the probing phase is called, e.g. "Scanning 192.168.1.0/24".
    label: []const u8,
    noun: Live.Noun,
    progress: progress.Snapshot = .{},
    /// Ctrl+C was pressed: probes in flight are finishing.
    stopping: bool = false,
};

/// Compose one status line. Separate from the ticker so the wording is
/// testable without a terminal.
pub fn writeStatus(w: *std.Io.Writer, g: Glyphs, frame: usize, s: Status) std.Io.Writer.Error!void {
    const spinner = g.spinner[frame % g.spinner.len];
    if (s.stopping) {
        try w.print("{s} Stopping{s} finishing probes in flight (Ctrl+C again to quit now)", .{ spinner, g.ellipsis });
        return;
    }
    const p = s.progress;
    // Before the first phase starts, the line reads as the probing
    // phase at its very beginning.
    switch (p.phase orelse .sweep) {
        // A handful of hosts, each taking a moment: count them.
        .identify => try w.print("{s} Identifying devices{s} {d} of {d}", .{ spinner, g.ellipsis, p.done, p.total }),
        .ports, .sweep, .arp => |phase| {
            const label = if (phase == .arp) "Checking ARP table" else s.label;
            try w.print("{s} {s}{s}", .{ spinner, label, g.ellipsis });
            if (p.percent()) |percent| try w.print(" {d}% {s}", .{ percent, g.separator });
            try w.print(" {d} {s}", .{ p.found, if (p.found == 1) s.noun.one else s.noun.many });
        },
    }
}
