const std = @import("std");
const builtin = @import("builtin");
const connects = @import("core").connects;
const Window = connects.Window;

const ms = std.time.ns_per_ms;

// ---------------------------------------------------------------------------
// Window: how many connects stay in flight.
// ---------------------------------------------------------------------------

test "a fixed window stays at its maximum whatever it observes" {
    var w = Window.init(1, 1024, .fixed);
    try std.testing.expectEqual(@as(usize, 1024), w.size);
    w.observe(.refused, 1_000, 0);
    w.observe(.refused, 900_000, 1 * ms);
    w.observe(.filtered, 500_000, 2 * ms);
    try std.testing.expectEqual(@as(usize, 1024), w.size);
}

test "an adaptive window starts small, within its bounds" {
    try std.testing.expectEqual(@as(usize, Window.INITIAL), Window.init(1, 1024, .adaptive).size);
    try std.testing.expectEqual(@as(usize, 16), Window.init(1, 16, .adaptive).size);
    try std.testing.expectEqual(@as(usize, 100), Window.init(100, 1024, .adaptive).size);
}

test "prompt answers and silence both grow the window, up to its maximum" {
    var w = Window.init(1, Window.INITIAL + 3, .adaptive);
    w.observe(.refused, 1_000, 0);
    w.observe(.open, 1_200, 1 * ms);
    // Silence is no sign of overload: a host that drops closed ports
    // leaves most probes unanswered at any pace.
    w.observe(.filtered, 500_000, 2 * ms);
    try std.testing.expectEqual(@as(usize, Window.INITIAL + 3), w.size);
    w.observe(.refused, 1_000, 3 * ms);
    try std.testing.expectEqual(@as(usize, Window.INITIAL + 3), w.size);
}

test "a slow answer halves the window once per round trip" {
    var w = Window.init(1, 1024, .adaptive);
    w.observe(.refused, 1_000, 0); // fastest: 1 ms
    const before = w.size;

    // Far slower than the fastest answer: the host is queueing.
    const slow_us = 80_000;
    w.observe(.refused, slow_us, 10 * ms);
    try std.testing.expectEqual(before / 2, w.size);

    // Within that round trip, more slow answers are the same slowdown:
    // no second cut, and no growth either.
    w.observe(.refused, slow_us, 20 * ms);
    w.observe(.refused, 1_000, 30 * ms);
    try std.testing.expectEqual(before / 2, w.size);

    // Once it has passed, a prompt answer grows the window again...
    w.observe(.refused, 1_000, 10 * ms + slow_us * std.time.ns_per_us);
    try std.testing.expectEqual(before / 2 + 1, w.size);
    // ...and a slow one cuts it again.
    w.observe(.refused, slow_us, 200 * ms);
    try std.testing.expectEqual((before / 2 + 1) / 2, w.size);
}

test "jitter within the slack does not count as a slowdown" {
    var w = Window.init(1, 1024, .adaptive);
    w.observe(.refused, 2_000, 0);
    const before = w.size;
    w.observe(.refused, 2 * 2_000 + Window.SLACK_US, 1 * ms);
    try std.testing.expectEqual(before + 1, w.size);
}

test "the window never drops below its minimum" {
    var w = Window.init(8, 1024, .adaptive);
    w.observe(.refused, 1_000, 0);
    var now: i96 = 0;
    for (0..20) |_| {
        now += 1000 * ms;
        w.observe(.refused, 500_000, now);
    }
    try std.testing.expectEqual(@as(usize, 8), w.size);
}

// ---------------------------------------------------------------------------
// run: many connects, each verdict reported once.
// ---------------------------------------------------------------------------

/// Hands out `ports` on 127.0.0.1 and records each verdict.
const Recorder = struct {
    ports: []const u16,
    outcomes: []?connects.Outcome,
    index: usize = 0,
    reports: usize = 0,

    const Job = struct { target: connects.Target, slot: usize };

    pub fn next(self: *Recorder) ?Job {
        if (self.index >= self.ports.len) return null;
        defer self.index += 1;
        return .{
            .target = .{ .ip = .{ 127, 0, 0, 1 }, .port = self.ports[self.index], .timeout_ms = 2000 },
            .slot = self.index,
        };
    }

    pub fn done(self: *Recorder, job: Job, outcome: connects.Outcome, _: u64) void {
        std.debug.assert(self.outcomes[job.slot] == null);
        self.outcomes[job.slot] = outcome;
        self.reports += 1;
    }
};

test "run reports open and refused loopback ports, each exactly once" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const io = std.testing.io;

    var bound = bindLoopbackAbove(io, 48631, 20) orelse return error.SkipZigTest;
    defer bound.server.deinit(io);

    // The listener, then port 9 (discard: effectively never listening,
    // so loopback refuses it) many times over, so the run has to keep
    // more connects going than a single loop's first batch.
    var ports: [200]u16 = @splat(9);
    ports[0] = bound.port;
    var outcomes: [ports.len]?connects.Outcome = @splat(null);
    var recorder: Recorder = .{ .ports = &ports, .outcomes = &outcomes };

    for ([_]connects.Pace{ .adaptive, .fixed }) |pace| {
        recorder.index = 0;
        recorder.reports = 0;
        @memset(&outcomes, null);
        try connects.run(Recorder.Job, std.testing.allocator, io, &recorder, pace);
        try std.testing.expectEqual(ports.len, recorder.reports);
        try std.testing.expectEqual(@as(?connects.Outcome, .open), outcomes[0]);
        for (outcomes[1..]) |o| try std.testing.expectEqual(@as(?connects.Outcome, .refused), o);
    }
}

test "run with nothing to do returns at once" {
    var outcomes: [0]?connects.Outcome = .{};
    var recorder: Recorder = .{ .ports = &.{}, .outcomes = &outcomes };
    try connects.run(Recorder.Job, std.testing.allocator, std.testing.io, &recorder, .adaptive);
    try std.testing.expectEqual(@as(usize, 0), recorder.reports);
}

test "inFlightLimit allows at least one connect and at most MAX_IN_FLIGHT" {
    const limit = connects.inFlightLimit();
    try std.testing.expect(limit >= 1 and limit <= connects.MAX_IN_FLIGHT);
}

/// Bind 127.0.0.1 on the first free port at or above `from`.
/// Returns null when nothing nearby is free, so callers can skip
/// instead of failing on a crowded test machine.
fn bindLoopbackAbove(io: std.Io, from: u16, span: u16) ?struct { server: std.Io.net.Server, port: u16 } {
    var port: u32 = from;
    const end: u32 = @min(@as(u32, from) + span, 65535);
    while (port <= end) : (port += 1) {
        var addr = std.Io.net.IpAddress.parseIp4("127.0.0.1", @intCast(port)) catch continue;
        if (addr.listen(io, .{})) |server| {
            return .{ .server = server, .port = @intCast(port) };
        } else |_| {}
    }
    return null;
}
