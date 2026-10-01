//! The interactive status line: one self-updating line on stderr while
//! a text scan runs in a terminal, e.g.
//!
//!     | Scanning 192.168.1.0/24 (7 hosts found, 42%)
//!     / Identifying devices (3 of 9)
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
//! This file only decides what the line says. A ticker thread rebuilds
//! the text a few times a second from counters the scan bumps (found
//! results, the phase's ProgressMeter), so workers never format or lock
//! anything for it.

const std = @import("std");
const interrupt = @import("interrupt.zig");
const ProgressMeter = @import("progress.zig").ProgressMeter;

/// How often the text (and the spinner frame) is rebuilt. std.Progress
/// redraws on its own schedule; this only keeps the name fresh.
const TICK_MS = 100;

/// ASCII on purpose: the line goes to Windows consoles whose code page
/// may not be UTF-8, where braille or box-drawing spinners garble.
const SPINNER = "|/-\\";

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

    pub const Noun = struct { one: []const u8, many: []const u8 };

    pub const Phase = struct {
        /// e.g. "Scanning 192.168.1.0/24" or "Identifying devices".
        label: []const u8,
        /// Progress through this phase; null for phases too quick or
        /// too open-ended to measure (reading the ARP table).
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
    }

    /// Stop the ticker and clear the line, so the summary prints on a
    /// clean terminal. Idempotent.
    pub fn finish(self: *Live) void {
        const ticker = self.ticker orelse return;
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
    /// meter (port scans).
    pub fn setMeter(self: *Live, meter: *const ProgressMeter) void {
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
            self.render(SPINNER[frame % SPINNER.len]);
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

    fn render(self: *Live, spinner: u8) void {
        self.phase_mutex.lockUncancelable(self.io);
        const phase = self.phase;
        self.phase_mutex.unlock(self.io);

        var buf: [std.Progress.Node.max_name_len]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        // A full buffer only truncates the line, so overflow is ignored.
        writeStatus(&w, spinner, phase, self.found.load(.monotonic), self.noun) catch {};
        self.root.setName(w.buffered());
    }
};

/// Compose one status line. Separate from the ticker so the wording is
/// testable without a terminal.
pub fn writeStatus(w: *std.Io.Writer, spinner: u8, phase: Live.Phase, found: usize, noun: Live.Noun) std.Io.Writer.Error!void {
    if (interrupt.requested()) {
        try w.print("{c} Stopping: finishing probes in flight (Ctrl+C again to quit now)", .{spinner});
        return;
    }
    try w.print("{c} {s} (", .{ spinner, phase.label });
    switch (phase.style) {
        .percent => {
            try w.print("{d} {s}", .{ found, if (found == 1) noun.one else noun.many });
            if (phase.meter) |m| try w.print(", {d}%", .{m.percent()});
        },
        .count => if (phase.meter) |m| {
            try w.print("{d} of {d}", .{ m.completed(), m.total });
        },
    }
    try w.writeAll(")");
}
