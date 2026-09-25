const builtin = @import("builtin");

// Direct extern declaration without using @cImport
pub const c = struct {
    pub extern "c" fn ping_host(ip_address: [*:0]const u8) bool;
    pub extern "c" fn tcp_probe(ip_address: [*:0]const u8, port: u16, timeout_ms: c_int) c_int;
    pub extern "c" fn ping_last_error() u32;
    pub extern "c" fn resolve_ptr(ip_address: [*:0]const u8, out_buf: [*]u8, out_len: usize) c_int;
    pub extern "c" fn query_netbios(ip_address: [*:0]const u8, out_buf: [*]u8, out_len: usize, timeout_ms: c_int) c_int;
    pub extern "c" fn query_mdns(ip_address: [*:0]const u8, out_buf: [*]u8, out_len: usize, timeout_ms: c_int) c_int;
    pub extern "c" fn read_file_content(path: [*:0]const u8, out_len: *usize) ?[*]u8;
    pub extern "c" fn free_file_content(ptr: [*]u8) void;
    pub extern "c" fn get_mac_sendarp(ip_address: [*:0]const u8, out_mac: [*]u8) c_int;
    pub extern "c" fn dump_arp_table(out_len: *usize) ?[*]u8;
    pub extern "c" fn free_arp_table(ptr: [*]u8) void;
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

pub fn pingHost(ip: ?[*:0]const u8) bool {
    if (ip == null) {
        return false;
    }
    return c.ping_host(ip.?);
}

/// Winsock error of the most recent failed pingHost call (Windows
/// only). Zero means no failure has been recorded yet.
pub fn pingLastError() u32 {
    if (comptime builtin.os.tag != .windows) return 0;
    return c.ping_last_error();
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
        @intFromEnum(TcpProbe.open) => .open,
        @intFromEnum(TcpProbe.refused) => .refused,
        else => .filtered,
    };
}
