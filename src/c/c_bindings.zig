// Direct extern declaration without using @cImport
pub const c = struct {
    pub extern "c" fn tcp_probe(ip_address: [*:0]const u8, port: u16, timeout_ms: c_int) c_int;
    pub extern "c" fn resolve_ptr(ip_address: [*:0]const u8, out_buf: [*]u8, out_len: usize) c_int;
    pub extern "c" fn query_netbios(ip_address: [*:0]const u8, out_buf: [*]u8, out_len: usize, timeout_ms: c_int) c_int;
    pub extern "c" fn query_mdns(ip_address: [*:0]const u8, out_buf: [*]u8, out_len: usize, timeout_ms: c_int) c_int;
    pub extern "c" fn read_file_content(path: [*:0]const u8, out_len: *usize) ?[*]u8;
    pub extern "c" fn free_file_content(ptr: [*]u8) void;
    pub extern "c" fn get_mac_sendarp(ip_address: [*:0]const u8, out_mac: [*]u8) c_int;
    pub extern "c" fn dump_arp_table(out_len: *usize) ?[*]u8;
    pub extern "c" fn free_arp_table(ptr: [*]u8) void;
    pub extern "c" fn mc_local_address(first: *const [4]u8, last: *const [4]u8, out_local: *[4]u8) c_int;
    pub extern "c" fn mc_open(local: *const [4]u8) i64;
    pub extern "c" fn mc_send(sock: i64, ip: *const [4]u8, port: c_ushort, buf: [*]const u8, len: usize) c_int;
    pub extern "c" fn mc_recv(sock: i64, timeout_ms: c_int, buf: [*]u8, cap: usize, out_from: *[4]u8) c_int;
    pub extern "c" fn mc_wake(sock: i64) void;
    pub extern "c" fn mc_close(sock: i64) void;
};

const std = @import("std");

pub fn getMacSendArp(ip_null_terminated: [*:0]const u8) ?[6]u8 {
    var mac: [6]u8 = undefined;
    if (c.get_mac_sendarp(ip_null_terminated, &mac) == 0) {
        return mac;
    }
    return null;
}

/// Read the macOS neighbour table straight from the kernel, as `arp -a`
/// formatted text owned by `allocator`. Null on failure or off macOS.
/// An empty (but non-null) result on macOS 27 usually means the binary
/// is not codesigned with a real identifier; see resolver.h.
pub fn dumpArpTable(allocator: std.mem.Allocator) ?[]u8 {
    var len: usize = 0;
    const ptr = c.dump_arp_table(&len) orelse return null;
    defer c.free_arp_table(ptr);
    return allocator.dupe(u8, ptr[0..len]) catch null;
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

pub const TcpProbe = enum(c_int) {
    open = 0,
    refused = 1,
    filtered = 2,
};

/// One TCP connect attempt with a timeout, via the Windows Winsock
/// helper. Anything unclassifiable counts as filtered.
pub fn tcpProbe(ip: [*:0]const u8, port: u16, timeout_ms: c_int) TcpProbe {
    return switch (c.tcp_probe(ip, port, timeout_ms)) {
        @backingInt(TcpProbe.open) => .open,
        @backingInt(TcpProbe.refused) => .refused,
        else => .filtered,
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
