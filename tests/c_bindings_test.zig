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

/// The C compiler's view of what c_bindings.zig declares by hand, from
/// tests/c_layout.c.
const layout = struct {
    extern const layout_ns_neighbor_size: usize;
    extern const layout_ns_neighbor_align: usize;
    extern const layout_ns_neighbor_ip: usize;
    extern const layout_ns_neighbor_mac: usize;
    extern const layout_ns_neighbor_has_mac: usize;
    extern const layout_ns_neighbor_state: usize;
    extern const layout_ns_neigh_reachable: c_int;

    extern const layout_icmp_observer_size: usize;
    extern const layout_icmp_observer_align: usize;
    extern const layout_icmp_observer_ctx: usize;
    extern const layout_icmp_observer_pinged: usize;
    extern const layout_icmp_observer_stop_requested: usize;
    extern const layout_icmp_ping_done: c_int;
    extern const layout_icmp_ping_unavailable: c_int;

    extern const layout_tcp_probe_open: c_int;
    extern const layout_tcp_probe_refused: c_int;
    extern const layout_tcp_probe_filtered: c_int;
    extern const layout_tcp_probe_pending: c_int;
    extern const layout_tcp_probe_unconfirmed: c_int;
    extern const layout_tcp_probe_no_socket: c_int;
    extern const layout_tcp_probe_no_address: c_int;
    extern const layout_tcp_probe_max_sockets: c_int;

    extern const layout_udp_exchange_size: usize;
    extern const layout_udp_exchange_align: usize;
    extern const layout_udp_exchange_req: usize;
    extern const layout_udp_exchange_req_len: usize;
    extern const layout_udp_exchange_resp: usize;
    extern const layout_udp_exchange_cap: usize;
    extern const layout_udp_exchange_resp_len: usize;
    extern const layout_udp_exchange_port: usize;
    extern const layout_ns_wait_max: c_int;

    extern const layout_mc_socket_size: usize;
    extern const layout_mc_no_socket: i64;
};

test "NeighborRow matches ns_neighbor in neighbors.h" {
    const Row = c_bindings.NeighborRow;
    try std.testing.expectEqual(layout.layout_ns_neighbor_size, @sizeOf(Row));
    try std.testing.expectEqual(layout.layout_ns_neighbor_align, @alignOf(Row));
    try std.testing.expectEqual(layout.layout_ns_neighbor_ip, @offsetOf(Row, "ip"));
    try std.testing.expectEqual(layout.layout_ns_neighbor_mac, @offsetOf(Row, "mac"));
    try std.testing.expectEqual(layout.layout_ns_neighbor_has_mac, @offsetOf(Row, "has_mac"));
    try std.testing.expectEqual(layout.layout_ns_neighbor_state, @offsetOf(Row, "state"));
    try std.testing.expectEqual(layout.layout_ns_neigh_reachable, c_bindings.NS_NEIGH_REACHABLE);
}

test "IcmpObserver matches icmp_ping_observer in icmp_ping.h" {
    const Observer = c_bindings.IcmpObserver;
    try std.testing.expectEqual(layout.layout_icmp_observer_size, @sizeOf(Observer));
    try std.testing.expectEqual(layout.layout_icmp_observer_align, @alignOf(Observer));
    try std.testing.expectEqual(layout.layout_icmp_observer_ctx, @offsetOf(Observer, "ctx"));
    try std.testing.expectEqual(layout.layout_icmp_observer_pinged, @offsetOf(Observer, "pinged"));
    try std.testing.expectEqual(layout.layout_icmp_observer_stop_requested, @offsetOf(Observer, "stop_requested"));
    try std.testing.expectEqual(layout.layout_icmp_ping_done, c_bindings.ICMP_PING_DONE);
    try std.testing.expectEqual(layout.layout_icmp_ping_unavailable, c_bindings.ICMP_PING_UNAVAILABLE);
}

test "TcpProbe and TCP_PROBE_MAX_SOCKETS match tcp_probe.h" {
    const TcpProbe = c_bindings.TcpProbe;
    try std.testing.expectEqual(layout.layout_tcp_probe_open, @backingInt(TcpProbe.open));
    try std.testing.expectEqual(layout.layout_tcp_probe_refused, @backingInt(TcpProbe.refused));
    try std.testing.expectEqual(layout.layout_tcp_probe_filtered, @backingInt(TcpProbe.filtered));
    try std.testing.expectEqual(layout.layout_tcp_probe_pending, @backingInt(TcpProbe.pending));
    try std.testing.expectEqual(layout.layout_tcp_probe_unconfirmed, @backingInt(TcpProbe.unconfirmed));
    try std.testing.expectEqual(layout.layout_tcp_probe_no_socket, @backingInt(TcpProbe.no_socket));
    try std.testing.expectEqual(layout.layout_tcp_probe_no_address, @backingInt(TcpProbe.no_address));
    try std.testing.expectEqual(layout.layout_tcp_probe_max_sockets, c_bindings.TCP_PROBE_MAX_SOCKETS);
}

test "UdpExchange and UDP_EXCHANGE_MAX match resolver.h and ns_socket.h" {
    const Exchange = c_bindings.UdpExchange;
    try std.testing.expectEqual(layout.layout_udp_exchange_size, @sizeOf(Exchange));
    try std.testing.expectEqual(layout.layout_udp_exchange_align, @alignOf(Exchange));
    try std.testing.expectEqual(layout.layout_udp_exchange_req, @offsetOf(Exchange, "req"));
    try std.testing.expectEqual(layout.layout_udp_exchange_req_len, @offsetOf(Exchange, "req_len"));
    try std.testing.expectEqual(layout.layout_udp_exchange_resp, @offsetOf(Exchange, "resp"));
    try std.testing.expectEqual(layout.layout_udp_exchange_cap, @offsetOf(Exchange, "cap"));
    try std.testing.expectEqual(layout.layout_udp_exchange_resp_len, @offsetOf(Exchange, "resp_len"));
    try std.testing.expectEqual(layout.layout_udp_exchange_port, @offsetOf(Exchange, "port"));
    try std.testing.expectEqual(layout.layout_ns_wait_max, c_bindings.UDP_EXCHANGE_MAX);
}

test "MulticastSocket's handle matches mc_socket in multicast.h" {
    try std.testing.expectEqual(layout.layout_mc_socket_size, @sizeOf(@FieldType(c_bindings.MulticastSocket, "handle")));
    try std.testing.expectEqual(layout.layout_mc_no_socket, c_bindings.MC_NO_SOCKET);
}
