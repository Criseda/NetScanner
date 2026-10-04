const std = @import("std");
const builtin = @import("builtin");
const progress = @import("core").progress;

// The engine counts each scan phase on a Tracker. `--json` progress
// events print to stdout, which tests must never touch, so these cover
// the throttling and ordering logic that decides what gets printed, and
// what a display reads.

const io = std.testing.io;

/// How many units of a `total`-sized phase would emit an event.
fn countCrossings(total: usize) usize {
    var n: usize = 0;
    for (1..total + 1) |done| {
        if (progress.crossesPercent(done, total)) n += 1;
    }
    return n;
}

test "crossesPercent emits at most 100 events per phase" {
    // Below 100 units every one moves the percentage; from 100 up,
    // exactly one per whole percent, however large the range.
    try std.testing.expectEqual(@as(usize, 1), countCrossings(1));
    try std.testing.expectEqual(@as(usize, 9), countCrossings(9));
    try std.testing.expectEqual(@as(usize, 100), countCrossings(100));
    try std.testing.expectEqual(@as(usize, 100), countCrossings(254));
    try std.testing.expectEqual(@as(usize, 100), countCrossings(65535));
}

test "crossesPercent always emits the final unit" {
    for ([_]usize{ 1, 2, 3, 99, 101, 254, 1023, 65535 }) |total| {
        try std.testing.expect(progress.crossesPercent(total, total));
    }
}

test "crossesPercent rejects out-of-range counts" {
    try std.testing.expect(!progress.crossesPercent(0, 10));
    try std.testing.expect(!progress.crossesPercent(11, 10));
    try std.testing.expect(!progress.crossesPercent(0, 0));
}

test "Tracker claims each count once, in order, ending at total" {
    var tracker: progress.Tracker = .{};
    tracker.startPhase(io, .ports, 254);
    var claimed: usize = 0;
    var last: usize = 0;
    for (0..254) |_| {
        if (!tracker.advance()) continue;
        const done = tracker.claim() orelse continue;
        try std.testing.expect(done > last);
        last = done;
        claimed += 1;
    }
    try std.testing.expectEqual(@as(usize, 254), last);
    try std.testing.expectEqual(@as(usize, 100), claimed);
    // Nothing newer to report: a late claim prints nothing.
    try std.testing.expectEqual(@as(?usize, null), tracker.claim());
}

test "Tracker stays ordered when workers race" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const total = 5000;

    // Mirrors the engine: advance lock-free, claim under the output
    // lock, but record the claimed counts instead of printing them.
    const Shared = struct {
        tracker: progress.Tracker = .{},
        mutex: std.Io.Mutex = .init,
        claims: [total]usize = undefined,
        claim_count: usize = 0,

        fn work(self: *@This(), units: usize) void {
            for (0..units) |_| {
                if (!self.tracker.advance()) continue;
                self.mutex.lockUncancelable(io);
                defer self.mutex.unlock(io);
                const done = self.tracker.claim() orelse continue;
                self.claims[self.claim_count] = done;
                self.claim_count += 1;
            }
        }
    };
    var shared: Shared = .{};
    shared.tracker.startPhase(io, .sweep, total);

    const workers = 8;
    var threads: [workers]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Shared.work, .{ &shared, total / workers });
    for (threads) |t| t.join();

    const claims = shared.claims[0..shared.claim_count];
    try std.testing.expect(claims.len > 0 and claims.len <= 100);
    try assertStrictlyIncreasing(claims);
    try std.testing.expectEqual(@as(usize, total), claims[claims.len - 1]);
}

test "a new phase counts from zero and keeps what was found" {
    var tracker: progress.Tracker = .{};
    tracker.startPhase(io, .sweep, 10);
    for (0..10) |_| _ = tracker.advance();
    tracker.addFound();
    tracker.addFound();
    _ = tracker.claim();

    tracker.startPhase(io, .identify, 2);
    const snapshot = tracker.snapshot(io);
    try std.testing.expectEqual(@as(?progress.Phase, .identify), snapshot.phase);
    try std.testing.expectEqual(@as(usize, 0), snapshot.done);
    try std.testing.expectEqual(@as(usize, 2), snapshot.total);
    try std.testing.expectEqual(@as(usize, 2), snapshot.found);
    // Claims start over too, so the new phase's first event prints.
    _ = tracker.advance();
    try std.testing.expectEqual(@as(?usize, 1), tracker.claim());
}

test "snapshot percent stays within 0-100 and is null without a size" {
    try std.testing.expectEqual(@as(?usize, null), (progress.Snapshot{}).percent());

    var tracker: progress.Tracker = .{};
    tracker.startPhase(io, .ports, 3);
    try std.testing.expectEqual(@as(?usize, 0), tracker.snapshot(io).percent());
    // Overshooting the total (it never should) still reads as 100%.
    for (0..5) |_| _ = tracker.advance();
    const snapshot = tracker.snapshot(io);
    try std.testing.expectEqual(@as(usize, 3), snapshot.done);
    try std.testing.expectEqual(@as(?usize, 100), snapshot.percent());
}

test "phase names are the --json phase values" {
    try std.testing.expectEqualStrings("ports", @tagName(progress.Phase.ports));
    try std.testing.expectEqualStrings("sweep", @tagName(progress.Phase.sweep));
    try std.testing.expectEqualStrings("arp", @tagName(progress.Phase.arp));
    try std.testing.expectEqualStrings("identify", @tagName(progress.Phase.identify));
}

fn assertStrictlyIncreasing(items: []const usize) !void {
    if (items.len < 2) return;
    for (items[0 .. items.len - 1], items[1..]) |a, b| {
        try std.testing.expect(a < b);
    }
}
