const builtin = @import("builtin");

// Direct extern declaration without using @cImport
pub const c = struct {
    pub extern "c" fn ping_host(ip_address: [*:0]const u8) bool;
    pub extern "c" fn tcp_probe(ip_address: [*:0]const u8, port: u16, timeout_ms: c_int) c_int;
    pub extern "c" fn ping_last_error() u32;
};

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
