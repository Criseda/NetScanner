const std = @import("std");
const c_bindings = @import("bindings");

test "c_bindings module imports correctly" {
    _ = c_bindings;
}

test "dumpArpTable reads the kernel table on macOS, null elsewhere" {
    const table = c_bindings.dumpArpTable(std.testing.allocator);
    defer if (table) |t| std.testing.allocator.free(t);
    // The test binary is unsigned and `zig` is its parent, so macOS
    // hands back an empty table; the sysctl itself must still succeed.
    if (@import("builtin").os.tag == .macos) {
        try std.testing.expect(table != null);
    } else {
        try std.testing.expect(table == null);
    }
}

/// Records what an in-process ping sweep reports, per host.
const PingRecorder = struct {
    /// How often each host was reported, and its last verdict.
    reports: [64]u8 = @splat(0),
    answered: [64]bool = @splat(false),
    stop: bool = false,

    fn pinged(ctx: *anyopaque, index: usize, answered: c_int) callconv(.c) void {
        const self: *PingRecorder = @ptrCast(@alignCast(ctx));
        self.reports[index] += 1;
        self.answered[index] = answered != 0;
    }

    fn stopRequested(ctx: *anyopaque) callconv(.c) c_int {
        const self: *PingRecorder = @ptrCast(@alignCast(ctx));
        return @intFromBool(self.stop);
    }

    fn sweep(self: *PingRecorder, ips: []const [4]u8, max_in_flight: usize) !void {
        const observer: c_bindings.IcmpObserver = .{
            .ctx = self,
            .pinged = pinged,
            .stop_requested = stopRequested,
        };
        // Linux without net.ipv4.ping_group_range for this user: ns
        // falls back to ping(1) there, and there is nothing to test.
        if (try c_bindings.icmpPingSweep(ips, 300, max_in_flight, &observer) == .unavailable) {
            return error.SkipZigTest;
        }
    }
};

test "icmpPingSweep: loopback answers, an unrouted address does not" {
    var recorder: PingRecorder = .{};
    // 192.0.2.0/24 is TEST-NET-1: documentation only, never routed.
    try recorder.sweep(&.{ .{ 127, 0, 0, 1 }, .{ 192, 0, 2, 1 } }, 16);
    try std.testing.expectEqualSlices(u8, &.{ 1, 1 }, recorder.reports[0..2]);
    try std.testing.expectEqualSlices(bool, &.{ true, false }, recorder.answered[0..2]);
}

test "icmpPingSweep: more hosts than the window still all get their answer" {
    var recorder: PingRecorder = .{};
    // The same address many times over: only 127.0.0.1 answers on every
    // OS, and each echo is matched to its own host anyway.
    const ips: [40][4]u8 = @splat(.{ 127, 0, 0, 1 });
    try recorder.sweep(&ips, 4);
    for (recorder.reports[0..ips.len], recorder.answered[0..ips.len]) |reports, answered| {
        try std.testing.expectEqual(@as(u8, 1), reports);
        try std.testing.expect(answered);
    }
}

test "icmpPingSweep: a stop before the start pings nobody" {
    var recorder: PingRecorder = .{ .stop = true };
    try recorder.sweep(&.{ .{ 127, 0, 0, 1 }, .{ 127, 0, 0, 1 } }, 16);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0 }, recorder.reports[0..2]);
}
