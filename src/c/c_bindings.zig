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
