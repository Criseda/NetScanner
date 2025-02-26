const std = @import("std");

// Direct extern declaration without using @cImport
pub const c = struct {
    pub extern "c" fn ping_host(ip_address: [*:0]const u8) bool;
};

pub fn pingHost(ip: ?[*:0]const u8) bool {
    if (ip == null) {
        return false;
    }
    return c.ping_host(ip.?);
}
