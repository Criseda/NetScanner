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
