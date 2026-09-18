const std = @import("std");
const builtin = @import("builtin");
const scanner = @import("core").scanner;
const utils = @import("core").utils;

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
    const outcome = scanner.tcpConnectPort(.{ 192, 0, 2, 1 }, 80);
    try std.testing.expectEqual(scanner.ProbeOutcome.filtered, outcome);
}

test "scanPorts rejects a reversed range" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const result = scanner.scanPorts(
        std.testing.allocator,
        std.testing.io,
        .{ 127, 0, 0, 1 },
        200,
        100,
        .{ .progress = false },
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
        .{ .progress = false },
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
        .{ .progress = false },
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
        .{ .progress = false },
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
