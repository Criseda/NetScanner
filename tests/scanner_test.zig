const std = @import("std");
const builtin = @import("builtin");
const scanner = @import("core").scanner;

// This is a simple test to ensure the scanner module can be imported
test "scanner module imports correctly" {
    _ = scanner;
}

test "tcpConnect maps a closed loopback port to refused" {
    // Port 9 (discard) is effectively never listening, so loopback
    // must answer with RST. Loopback can never genuinely filter, which
    // makes the verdict deterministic within the connect timeout.
    const outcome = scanner.tcpConnect(.{ 127, 0, 0, 1 }, 9);
    try std.testing.expectEqual(scanner.ProbeOutcome.refused, outcome);
}

test "tcpConnect maps an unroutable host to filtered" {
    // TEST-NET-1 is never routed, so nothing out there can answer or
    // refuse; the connect must time out quickly instead of hanging.
    const outcome = scanner.tcpConnect(.{ 192, 0, 2, 1 }, 80);
    try std.testing.expectEqual(scanner.ProbeOutcome.filtered, outcome);
}

test "tcpConnectPort maps an unroutable host to filtered" {
    // Same TEST-NET-1 reasoning as above, through the shorter
    // port-scan timeout instead of the discovery one.
    const outcome = scanner.tcpConnectPort(.{ 192, 0, 2, 1 }, 80, 500);
    try std.testing.expectEqual(scanner.ProbeOutcome.filtered, outcome);
}

// NOTE: stream_results=true (the CLI default) has no automated test on
// purpose: under `zig build test` the runner speaks its protocol
// over stdout, so test output there hangs the run. Streaming output
// is verified manually against the built binary instead.
test "scanPorts rejects a reversed range" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const result = scanner.scanPorts(
        std.testing.allocator,
        std.testing.io,
        .{ 127, 0, 0, 1 },
        200,
        100,
        .{ .stream_results = false },
    );
    try std.testing.expectError(error.InvalidPortRange, result);
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

test "scanPorts finds a locally bound open port" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const io = std.testing.io;

    var bound = bindLoopbackAbove(io, 48231, 20) orelse return error.SkipZigTest;
    defer bound.server.deinit(io);

    var open = try scanner.scanPorts(
        std.testing.allocator,
        io,
        .{ 127, 0, 0, 1 },
        bound.port,
        bound.port,
        .{ .stream_results = false },
    );
    defer open.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), open.items.len);
    try std.testing.expectEqual(bound.port, open.items[0]);
}

test "scanPorts honors a custom timeout override" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const io = std.testing.io;

    // An open loopback port answers far inside 50ms, so the override
    // proves the plumbing without timing assertions (which flake).
    var bound = bindLoopbackAbove(io, 48431, 20) orelse return error.SkipZigTest;
    defer bound.server.deinit(io);

    var open = try scanner.scanPorts(
        std.testing.allocator,
        io,
        .{ 127, 0, 0, 1 },
        bound.port,
        bound.port,
        .{ .stream_results = false, .timeout_ms = 50 },
    );
    defer open.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), open.items.len);
    try std.testing.expectEqual(bound.port, open.items[0]);
}

test "scanPorts returns open ports sorted" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const io = std.testing.io;

    // Two listeners close together, so the scanned range stays small
    // and the test stays fast on every OS.
    var first = bindLoopbackAbove(io, 48331, 40) orelse return error.SkipZigTest;
    defer first.server.deinit(io);
    if (first.port >= 65535) return error.SkipZigTest;
    var second = bindLoopbackAbove(io, first.port + 1, 64) orelse return error.SkipZigTest;
    defer second.server.deinit(io);

    var open = try scanner.scanPorts(
        std.testing.allocator,
        io,
        .{ 127, 0, 0, 1 },
        first.port,
        second.port,
        .{ .stream_results = false },
    );
    defer open.deinit(std.testing.allocator);

    // Both bound ports must be present, in ascending order, whatever
    // else the machine has listening inside the window.
    try std.testing.expect(std.mem.indexOfScalar(u16, open.items, first.port) != null);
    try std.testing.expect(std.mem.indexOfScalar(u16, open.items, second.port) != null);
    const ia = std.mem.indexOfScalar(u16, open.items, first.port).?;
    const ib = std.mem.indexOfScalar(u16, open.items, second.port).?;
    try std.testing.expect(ia < ib);
    try assertSorted(u16, open.items);
}

test "scanPorts stays sorted over multiple worker waves" {
    if (builtin.single_threaded) return error.SkipZigTest;

    // 300 ports exceeds the worker pool on every OS, so this covers
    // the multi-wave path. Contents are machine-dependent (loopback
    // listeners vary), so only the ordering invariant is asserted.
    var open = try scanner.scanPorts(
        std.testing.allocator,
        std.testing.io,
        .{ 127, 0, 0, 1 },
        1,
        300,
        .{ .stream_results = false },
    );
    defer open.deinit(std.testing.allocator);
    try assertSorted(u16, open.items);
}

fn assertSorted(comptime T: type, items: []const T) !void {
    if (items.len < 2) return;
    for (items[0 .. items.len - 1], items[1..]) |a, b| {
        try std.testing.expect(a <= b);
    }
}

// ---------------------------------------------------------------------------
// Progress events. The printing itself goes to stdout, which tests must
// never touch, so these cover the throttling and ordering logic that
// decides what gets printed.
// ---------------------------------------------------------------------------

/// How many units of a `total`-sized phase would emit an event.
fn countCrossings(total: usize) usize {
    var n: usize = 0;
    for (1..total + 1) |done| {
        if (scanner.crossesPercent(done, total)) n += 1;
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
        try std.testing.expect(scanner.crossesPercent(total, total));
    }
}

test "crossesPercent rejects out-of-range counts" {
    try std.testing.expect(!scanner.crossesPercent(0, 10));
    try std.testing.expect(!scanner.crossesPercent(11, 10));
    try std.testing.expect(!scanner.crossesPercent(0, 0));
}

test "ProgressMeter claims each count once, in order, ending at total" {
    var meter: scanner.ProgressMeter = .{ .phase = "ports", .total = 254 };
    var claimed: usize = 0;
    var last: usize = 0;
    for (0..254) |_| {
        if (!meter.advance()) continue;
        const done = meter.claim() orelse continue;
        try std.testing.expect(done > last);
        last = done;
        claimed += 1;
    }
    try std.testing.expectEqual(@as(usize, 254), last);
    try std.testing.expectEqual(@as(usize, 100), claimed);
    // Nothing newer to report: a late claim prints nothing.
    try std.testing.expectEqual(@as(?usize, null), meter.claim());
}

test "ProgressMeter stays ordered when workers race" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const total = 5000;

    // Mirrors advanceProgress: advance lock-free, claim under a lock,
    // but records the claimed counts instead of printing them.
    const Shared = struct {
        meter: scanner.ProgressMeter = .{ .phase = "sweep", .total = total },
        mutex: std.Io.Mutex = .init,
        claims: [total]usize = undefined,
        claim_count: usize = 0,

        fn work(self: *@This(), units: usize) void {
            for (0..units) |_| {
                if (!self.meter.advance()) continue;
                self.mutex.lockUncancelable(std.testing.io);
                defer self.mutex.unlock(std.testing.io);
                const done = self.meter.claim() orelse continue;
                self.claims[self.claim_count] = done;
                self.claim_count += 1;
            }
        }
    };
    var shared: Shared = .{};

    const workers = 8;
    var threads: [workers]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Shared.work, .{ &shared, total / workers });
    for (threads) |t| t.join();

    const claims = shared.claims[0..shared.claim_count];
    try std.testing.expect(claims.len > 0 and claims.len <= 100);
    try assertStrictlyIncreasing(claims);
    try std.testing.expectEqual(@as(usize, total), claims[claims.len - 1]);
}

fn assertStrictlyIncreasing(items: []const usize) !void {
    if (items.len < 2) return;
    for (items[0 .. items.len - 1], items[1..]) |a, b| {
        try std.testing.expect(a < b);
    }
}
