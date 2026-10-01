//! Counting finished work during a scan. Results alone cannot yield a
//! percentage (closed ports and silent IPs print nothing), so the
//! engine counts every probe itself. Two consumers read the count:
//! `--json` progress events, and the interactive status line
//! (live.zig). This file only counts and decides what to report; it
//! never prints, so tests can exercise it without touching stdout.

const std = @import("std");

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

/// Counts finished units of one scan phase across worker threads.
/// Workers call advance() after every probe; the one whose unit crosses
/// a percent boundary takes the stdout lock and calls claim(), which
/// reports the newest count rather than its own. That keeps printed
/// counts strictly increasing even when workers reach the lock out of
/// order, and prints `done == total` exactly once.
pub const ProgressMeter = struct {
    /// `ports`, `sweep` or `identify` (see docs/README.md).
    phase: []const u8,
    total: usize,
    /// Print `--json` progress events. Off, the meter still counts for
    /// the interactive status line.
    emit_json: bool = false,
    done: std.atomic.Value(usize) = .init(0),
    /// Last count claimed. Guarded by the lock the caller holds around
    /// claim() (the stdout mutex in the scanner).
    last_claimed: usize = 0,

    /// Record one finished unit. True when the caller should emit.
    pub fn advance(self: *ProgressMeter) bool {
        const done = self.done.fetchAdd(1, .monotonic) + 1;
        return crossesPercent(done, self.total);
    }

    /// The count to print, or null when a newer one is already out.
    /// Call with the output lock held.
    pub fn claim(self: *ProgressMeter) ?usize {
        const done = self.completed();
        if (done <= self.last_claimed) return null;
        self.last_claimed = done;
        return done;
    }

    /// Units finished so far, for readers that only display the count.
    pub fn completed(self: *const ProgressMeter) usize {
        return @min(self.done.load(.monotonic), self.total);
    }

    /// Whole percentage finished, 0-100.
    pub fn percent(self: *const ProgressMeter) usize {
        if (self.total == 0) return 100;
        return @intCast(@as(u64, self.completed()) * 100 / self.total);
    }
};
