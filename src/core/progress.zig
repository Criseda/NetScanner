//! Counting a scan's progress. Results alone cannot yield a percentage
//! (closed ports and silent IPs print nothing), so the engine counts
//! every unit of work itself, phase by phase, on a Tracker. Two readers
//! watch it: `--json` progress events, which the engine prints, and the
//! interactive status line (live.zig), which reads it from a thread of
//! its own. Nothing here prints, so tests can exercise it without
//! touching stdout.

const std = @import("std");

/// The stages of a scan, in the order they run. The names are the
/// `phase` values of `--json` progress events (see docs/README.md).
pub const Phase = enum {
    /// `-p`: ports probed, of the range.
    ports,
    /// `-s`, TCP or `--ping`: IPs probed, of the usable hosts.
    sweep,
    /// `-s` without `--ping`: ARP-table entries checked, of the entries
    /// the sweep did not already find.
    arp,
    /// `--resolve` / `--hostname`: hosts named, of the hosts found.
    identify,
};

/// True when finishing unit `done` of `total` moves the whole
/// percentage, so at most 100 events go out per phase whatever its
/// size (and every unit when there are fewer than 100). The last unit
/// always crosses into 100%.
pub fn crossesPercent(done: usize, total: usize) bool {
    if (total == 0 or done == 0 or done > total) return false;
    // u64 keeps done * 100 from overflowing on 32-bit targets.
    const now = @as(u64, done) * 100 / total;
    const before = @as(u64, done - 1) * 100 / total;
    return now != before;
}

/// One scan's progress, shared by the engine, which advances it, and
/// whoever shows it. The caller owns it and keeps it alive for the whole
/// scan, so a display thread can read it at any moment without caring
/// which phase, or which stack frame, is current.
pub const Tracker = struct {
    /// Results so far: hosts up, or open ports.
    found: std.atomic.Value(usize) = .init(0),
    /// Units finished in the current phase. Workers bump it lock-free.
    done: std.atomic.Value(usize) = .init(0),
    /// Guards `phase` and `total`, which change between phases while a
    /// display may be reading them. Workers never take it.
    mutex: std.Io.Mutex = .init,
    /// Null until the scan starts its first phase.
    phase: ?Phase = null,
    total: usize = 0,
    /// Last count printed as a `--json` event. Guarded by the lock the
    /// caller holds around claim() (the scan's stdout mutex).
    last_claimed: usize = 0,

    /// Start a phase of `total` units. Call between phases, when no
    /// worker of the previous phase is running: workers read `total`
    /// without the lock.
    pub fn startPhase(self: *Tracker, io: std.Io, phase: Phase, total: usize) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.phase = phase;
        self.total = total;
        self.done.store(0, .monotonic);
        self.last_claimed = 0;
    }

    /// Record one finished unit. True when it moves the whole
    /// percentage, i.e. when a `--json` event is due.
    pub fn advance(self: *Tracker) bool {
        const done = self.done.fetchAdd(1, .monotonic) + 1;
        return crossesPercent(done, self.total);
    }

    /// Count one result (a host up, an open port).
    pub fn addFound(self: *Tracker) void {
        _ = self.found.fetchAdd(1, .monotonic);
    }

    /// The count to print, or null when a newer one is already out.
    /// Workers reach the output lock out of order, so each prints the
    /// newest count rather than its own: printed counts only increase,
    /// and `done == total` prints exactly once. Call with that lock held.
    pub fn claim(self: *Tracker) ?usize {
        const done = @min(self.done.load(.monotonic), self.total);
        if (done <= self.last_claimed) return null;
        self.last_claimed = done;
        return done;
    }

    /// Everything a display needs, read consistently: a phase never
    /// shows with the previous phase's total.
    pub fn snapshot(self: *Tracker, io: std.Io) Snapshot {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        return .{
            .phase = self.phase,
            .done = @min(self.done.load(.monotonic), self.total),
            .total = self.total,
            .found = self.found.load(.monotonic),
        };
    }
};

/// A Tracker at one moment.
pub const Snapshot = struct {
    phase: ?Phase = null,
    done: usize = 0,
    total: usize = 0,
    found: usize = 0,

    /// Whole percentage finished, 0-100. Null when the phase has no
    /// size yet (or nothing to do), so there is nothing to show.
    pub fn percent(self: Snapshot) ?usize {
        if (self.total == 0) return null;
        return @intCast(@as(u64, self.done) * 100 / self.total);
    }
};

/// Something that shows a Tracker while the scan runs, like the CLI's
/// status line. It shares the terminal with the scan's own output, so
/// the engine tells it when to appear (once its header is out) and when
/// to get out of the way for good (before results print). That is all
/// the engine knows about it.
pub const Display = struct {
    context: *anyopaque,
    beginFn: *const fn (context: *anyopaque) void,
    /// Must be idempotent: the engine also calls it on error paths.
    endFn: *const fn (context: *anyopaque) void,

    pub fn begin(self: Display) void {
        self.beginFn(self.context);
    }

    pub fn end(self: Display) void {
        self.endFn(self.context);
    }
};
