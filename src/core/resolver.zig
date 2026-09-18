//! NetScanner hostname resolution (Reverse DNS + NetBIOS NBNS + RFC 6762 mDNS).

const std = @import("std");
const c_bindings = @import("bindings");
const utils = @import("utils.zig");

/// Resolve a single host's name using NetBIOS, mDNS, and Reverse DNS PTR.
/// Returns an allocated string for the caller to free, or null if unknown.
pub fn resolveHostName(allocator: std.mem.Allocator, ip: [4]u8) ?[]const u8 {
    var ip_buf: [16]u8 = undefined;
    const ip_str = std.fmt.bufPrintZ(&ip_buf, "{d}.{d}.{d}.{d}", .{
        ip[0], ip[1], ip[2], ip[3],
    }) catch return null;

    var name_buf: [256]u8 = undefined;

    // 1. Try NetBIOS (fast UDP to port 137 with 200ms timeout - Windows, Samba, NAS)
    if (c_bindings.queryNetbios(ip_str.ptr, &name_buf, 200)) |nb_name| {
        const trimmed = std.mem.trim(u8, nb_name, " \t\r\n");
        if (trimmed.len > 0) {
            return allocator.dupe(u8, trimmed) catch null;
        }
    }

    // 2. Try mDNS (fast unicast UDP to port 5353 with 200ms timeout - PS5, Hue, Apple, Smart TVs)
    if (c_bindings.queryMdns(ip_str.ptr, &name_buf, 200)) |mdns_name| {
        const clean_name = cleanDomainName(mdns_name);
        if (clean_name.len > 0) {
            return allocator.dupe(u8, clean_name) catch null;
        }
    }

    // 3. Try reverse DNS (getnameinfo)
    if (c_bindings.resolvePtr(ip_str.ptr, &name_buf)) |ptr_name| {
        // If reverse DNS returned the IP itself or an in-addr.arpa record, ignore it.
        if (!std.mem.eql(u8, ptr_name, ip_str) and
            !std.mem.endsWith(u8, ptr_name, ".in-addr.arpa") and
            !std.mem.endsWith(u8, ptr_name, ".ip6.arpa") and
            utils.ipStringToBytes(ptr_name) == error.InvalidIpAddress)
        {
            const clean_name = cleanDomainName(ptr_name);
            if (clean_name.len > 0 and utils.ipStringToBytes(clean_name) == error.InvalidIpAddress) {
                return allocator.dupe(u8, clean_name) catch null;
            }
        }
    }

    return null;
}

/// Strip trailing domain components from reverse DNS results (e.g. "myhost.localdomain" -> "myhost").
pub fn cleanDomainName(raw: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return trimmed;
    const dot = std.mem.indexOfScalar(u8, trimmed, '.');
    const clean_name = if (dot) |d| trimmed[0..d] else trimmed;
    return if (clean_name.len > 0) clean_name else trimmed;
}
