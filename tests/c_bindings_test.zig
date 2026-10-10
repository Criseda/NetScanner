const std = @import("std");
const c_bindings = @import("bindings");

test "c_bindings module imports correctly" {
    _ = c_bindings;
}

test "dumpNeighbors reads the kernel table natively" {
    // netlink, GetIpNetTable2 and sysctl all need no privileges, so the
    // read itself must succeed. Its contents depend on the machine (on
    // macOS the unsigned test binary is handed an empty table).
    const table = c_bindings.dumpNeighbors(std.testing.allocator);
    try std.testing.expect(table != null);
    defer std.testing.allocator.free(table.?);
    for (table.?) |entry| {
        // Multicast and broadcast rows never come back.
        try std.testing.expect(entry.ip[0] != 0 and entry.ip[0] < 224);
        if (entry.mac) |mac| {
            const broadcast: [6]u8 = @splat(0xff);
            try std.testing.expect(!std.mem.eql(u8, &mac, &broadcast));
        }
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
