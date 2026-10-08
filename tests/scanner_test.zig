const std = @import("std");
const builtin = @import("builtin");
const scanner = @import("core").scanner;
const progress = @import("core").progress;

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
    try std.testing.expect(std.mem.findScalar(u16, open.items, first.port) != null);
    try std.testing.expect(std.mem.findScalar(u16, open.items, second.port) != null);
    const ia = std.mem.findScalar(u16, open.items, first.port).?;
    const ib = std.mem.findScalar(u16, open.items, second.port).?;
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
// What the caller hands a scan: a tracker it counts on, a display it
// starts and ends, and a flag that stops it early.
// ---------------------------------------------------------------------------

test "scanPorts counts every port, and each open one, on the caller's tracker" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const io = std.testing.io;

    var bound = bindLoopbackAbove(io, 48531, 20) orelse return error.SkipZigTest;
    defer bound.server.deinit(io);
    if (bound.port > 65535 - 9) return error.SkipZigTest;

    var tracker: progress.Tracker = .{};
    var open = try scanner.scanPorts(
        std.testing.allocator,
        io,
        .{ 127, 0, 0, 1 },
        bound.port,
        bound.port + 9,
        .{ .stream_results = false, .tracker = &tracker },
    );
    defer open.deinit(std.testing.allocator);

    const snapshot = tracker.snapshot(io);
    try std.testing.expectEqual(@as(?progress.Phase, .ports), snapshot.phase);
    try std.testing.expectEqual(@as(usize, 10), snapshot.total);
    try std.testing.expectEqual(@as(usize, 10), snapshot.done);
    // Other listeners may sit in the range: found matches what came back.
    try std.testing.expectEqual(open.items.len, snapshot.found);
    try std.testing.expect(std.mem.findScalar(u16, open.items, bound.port) != null);
}

test "scanPorts probes nothing once cancelled" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const io = std.testing.io;

    // Every worker checks the flag before taking a port, so a scan
    // stopped before it starts returns at once, whatever the range.
    var cancel: std.atomic.Value(bool) = .init(true);
    var tracker: progress.Tracker = .{};
    var open = try scanner.scanPorts(
        std.testing.allocator,
        io,
        .{ 127, 0, 0, 1 },
        1,
        65535,
        .{ .stream_results = false, .tracker = &tracker, .cancel = &cancel },
    );
    defer open.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), tracker.snapshot(io).done);
    try std.testing.expectEqual(@as(usize, 0), open.items.len);
}

test "scanPorts shows its display only while it runs" {
    if (builtin.single_threaded) return error.SkipZigTest;

    // Stands in for the status line: counts the engine's calls.
    const Recorder = struct {
        begun: usize = 0,
        ended: usize = 0,

        fn begin(context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.begun += 1;
        }
        fn end(context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.ended += 1;
        }
    };
    var recorder: Recorder = .{};
    var open = try scanner.scanPorts(
        std.testing.allocator,
        std.testing.io,
        .{ 127, 0, 0, 1 },
        9,
        9,
        .{
            .stream_results = false,
            .display = .{ .context = &recorder, .beginFn = Recorder.begin, .endFn = Recorder.end },
        },
    );
    defer open.deinit(std.testing.allocator);
    // Up once, and down again before scanPorts returns, so the caller
    // can print its table on a clean terminal.
    try std.testing.expectEqual(@as(usize, 1), recorder.begun);
    try std.testing.expect(recorder.ended >= 1);
}
