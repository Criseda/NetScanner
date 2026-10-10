// Direct extern declaration without using @cImport
pub const c = struct {
    pub extern "c" fn tcp_probe_start(ip: *const [4]u8, port: u16, timeout_ms: c_int, out_sock: *usize) c_int;
    pub extern "c" fn tcp_probe_wait(socks: [*]const usize, count: c_int, wait_ms: c_int, settled: [*]u8) c_int;
    pub extern "c" fn tcp_probe_finish(sock: usize, settled: c_int) c_int;
    pub extern "c" fn resolve_ptr(ip_address: [*:0]const u8, out_buf: [*]u8, out_len: usize) c_int;
    pub extern "c" fn query_netbios(ip_address: [*:0]const u8, out_buf: [*]u8, out_len: usize, timeout_ms: c_int) c_int;
    pub extern "c" fn query_mdns(ip_address: [*:0]const u8, out_buf: [*]u8, out_len: usize, timeout_ms: c_int) c_int;
    pub extern "c" fn read_file_content(path: [*:0]const u8, out_len: *usize) ?[*]u8;
    pub extern "c" fn free_file_content(ptr: [*]u8) void;
    pub extern "c" fn get_mac_sendarp(ip_address: [*:0]const u8, out_mac: [*]u8) c_int;
    pub extern "c" fn dump_neighbors(out: *?[*]NeighborRow, out_count: *usize) c_int;
    pub extern "c" fn free_neighbors(ptr: ?[*]NeighborRow) void;
    pub extern "c" fn mc_local_address(first: *const [4]u8, last: *const [4]u8, out_local: *[4]u8) c_int;
    pub extern "c" fn mc_open(local: *const [4]u8) i64;
    pub extern "c" fn mc_send(sock: i64, ip: *const [4]u8, port: c_ushort, buf: [*]const u8, len: usize) c_int;
    pub extern "c" fn mc_recv(sock: i64, timeout_ms: c_int, buf: [*]u8, cap: usize, out_from: *[4]u8) c_int;
    pub extern "c" fn mc_wake(sock: i64) void;
    pub extern "c" fn mc_close(sock: i64) void;
    pub extern "c" fn icmp_ping_sweep(ips: [*]const [4]u8, count: usize, timeout_ms: c_int, max_in_flight: usize, observer: *const IcmpObserver) c_int;
};

const std = @import("std");

pub fn getMacSendArp(ip_null_terminated: [*:0]const u8) ?[6]u8 {
    var mac: [6]u8 = undefined;
    if (c.get_mac_sendarp(ip_null_terminated, &mac) == 0) {
        return mac;
    }
    return null;
}

/// `ns_neighbor` from neighbors.h.
pub const NeighborRow = extern struct {
    ip: [4]u8,
    mac: [6]u8,
    has_mac: u8,
    state: u8,
};

/// How sure the kernel is that a neighbor is there right now.
pub const NeighborState = enum {
    /// Confirmed within the last few seconds: proof enough on its own.
    reachable,
    /// Resolved at some point, maybe long ago: still needs a ping.
    stale,
};

pub const Neighbor = struct {
    ip: [4]u8,
    mac: ?[6]u8,
    state: NeighborState,
};

/// Read the kernel's IPv4 neighbor (ARP) table natively, owned by
/// `allocator`: netlink on Linux, GetIpNetTable2 on Windows, sysctl on
/// macOS (see neighbors.h). Dead entries are already left out. Null on
/// failure. An empty table on macOS 27 usually means the binary is not
/// codesigned with a real identifier.
pub fn dumpNeighbors(allocator: std.mem.Allocator) ?[]Neighbor {
    var rows: ?[*]NeighborRow = null;
    var count: usize = 0;
    if (c.dump_neighbors(&rows, &count) != 0) return null;
    defer c.free_neighbors(rows);
    const neighbors = allocator.alloc(Neighbor, count) catch return null;
    for (neighbors, 0..) |*neighbor, i| {
        const row = rows.?[i];
        neighbor.* = .{
            .ip = row.ip,
            .mac = if (row.has_mac != 0) row.mac else null,
            // NS_NEIGH_REACHABLE; anything else is NS_NEIGH_STALE.
            .state = if (row.state == 1) .reachable else .stale,
        };
    }
    return neighbors;
}

pub fn readFileContent(path_null_terminated: [*:0]const u8) ?[]const u8 {
    var len: usize = 0;
    const ptr = c.read_file_content(path_null_terminated, &len) orelse return null;
    return ptr[0..len];
}

pub fn freeFileContent(slice: []const u8) void {
    c.free_file_content(@constCast(slice.ptr));
}

pub fn resolvePtr(ip_null_terminated: [*:0]const u8, buf: []u8) ?[]const u8 {
    if (c.resolve_ptr(ip_null_terminated, buf.ptr, buf.len) == 0) {
        return std.mem.sliceTo(buf, 0);
    }
    return null;
}

pub fn queryNetbios(ip_null_terminated: [*:0]const u8, buf: []u8, timeout_ms: c_int) ?[]const u8 {
    if (c.query_netbios(ip_null_terminated, buf.ptr, buf.len, timeout_ms) == 0) {
        return std.mem.sliceTo(buf, 0);
    }
    return null;
}

pub fn queryMdns(ip_null_terminated: [*:0]const u8, buf: []u8, timeout_ms: c_int) ?[]const u8 {
    if (c.query_mdns(ip_null_terminated, buf.ptr, buf.len, timeout_ms) == 0) {
        return std.mem.sliceTo(buf, 0);
    }
    return null;
}

/// Most sockets one tcpProbeWait call watches (TCP_PROBE_MAX_SOCKETS
/// in src/c/tcp_probe.h).
pub const TCP_PROBE_MAX_SOCKETS = 4096;

pub const TcpProbe = enum(c_int) {
    open = 0,
    refused = 1,
    filtered = 2,
    pending = 3,
};

fn toTcpProbe(raw: c_int) TcpProbe {
    return switch (raw) {
        @backingInt(TcpProbe.open) => .open,
        @backingInt(TcpProbe.refused) => .refused,
        @backingInt(TcpProbe.pending) => .pending,
        else => .filtered,
    };
}

/// Windows: begin a non-blocking connect to ip:port. `.pending` leaves
/// the socket in `out_sock` for tcpProbeWait and tcpProbeFinish; any
/// other result is final and the socket is already closed.
pub fn tcpProbeStart(ip: [4]u8, port: u16, timeout_ms: c_int, out_sock: *usize) TcpProbe {
    return toTcpProbe(c.tcp_probe_start(&ip, port, timeout_ms, out_sock));
}

/// Windows: wait up to wait_ms for any of `socks` to settle, marking
/// settled[i] for each that did. False on failure.
pub fn tcpProbeWait(socks: []const usize, wait_ms: c_int, settled: []u8) bool {
    std.debug.assert(socks.len <= TCP_PROBE_MAX_SOCKETS and settled.len >= socks.len);
    return c.tcp_probe_wait(socks.ptr, @intCast(socks.len), wait_ms, settled.ptr) >= 0;
}

/// Windows: a pending socket's verdict, closing it. `settled` false
/// means its deadline passed first.
pub fn tcpProbeFinish(sock: usize, settled: bool) TcpProbe {
    return switch (toTcpProbe(c.tcp_probe_finish(sock, @intFromBool(settled)))) {
        .pending => .filtered,
        else => |verdict| verdict,
    };
}

/// A UDP socket for multicast discovery (see src/c/multicast.h).
pub const MulticastSocket = struct {
    handle: i64,

    /// This machine's address on an attached subnet overlapping
    /// first..last, or null when the range is off-link.
    pub fn localAddress(first: [4]u8, last: [4]u8) ?[4]u8 {
        var local: [4]u8 = undefined;
        if (c.mc_local_address(&first, &last, &local) != 0) return null;
        return local;
    }

    /// Null when the socket cannot be set up.
    pub fn open(local: [4]u8) ?MulticastSocket {
        const handle = c.mc_open(&local);
        if (handle == -1) return null;
        return .{ .handle = handle };
    }

    pub fn send(self: MulticastSocket, ip: [4]u8, port: u16, payload: []const u8) bool {
        return c.mc_send(self.handle, &ip, port, payload.ptr, payload.len) == 0;
    }

    pub const Datagram = struct { from: [4]u8, data: []u8 };
    pub const RecvError = error{SocketFailed};

    /// One datagram within timeout_ms, or null when none came.
    pub fn recv(self: MulticastSocket, timeout_ms: c_int, buf: []u8) RecvError!?Datagram {
        var from: [4]u8 = undefined;
        const n = c.mc_recv(self.handle, timeout_ms, buf.ptr, buf.len, &from);
        if (n < 0) return error.SocketFailed;
        if (n == 0) return null;
        return .{ .from = from, .data = buf[0..@intCast(n)] };
    }

    /// Make a recv waiting on another thread return now.
    pub fn wake(self: MulticastSocket) void {
        c.mc_wake(self.handle);
    }

    pub fn close(self: MulticastSocket) void {
        c.mc_close(self.handle);
    }
};
/// Mirrors icmp_ping_observer in icmp_ping.h: how an in-process ping
/// sweep reports back, on the sweeping thread.
pub const IcmpObserver = extern struct {
    ctx: *anyopaque,
    pinged: *const fn (ctx: *anyopaque, index: usize, answered: c_int) callconv(.c) void,
    stop_requested: *const fn (ctx: *anyopaque) callconv(.c) c_int,
};

pub const IcmpSweep = enum { done, unavailable };

/// Ping every IP from one ICMP socket inside the process (see
/// icmp_ping.h). `.unavailable` means nothing was sent: this system
/// does not allow unprivileged ICMP sockets, so ping(1) has to do it.
pub fn icmpPingSweep(ips: []const [4]u8, timeout_ms: c_int, max_in_flight: usize, observer: *const IcmpObserver) error{OutOfMemory}!IcmpSweep {
    return switch (c.icmp_ping_sweep(ips.ptr, ips.len, timeout_ms, max_in_flight, observer)) {
        0 => .done,
        1 => .unavailable,
        else => error.OutOfMemory,
    };
}
