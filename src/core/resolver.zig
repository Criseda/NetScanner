//! NetScanner hostname resolution (Reverse DNS + NetBIOS NBNS + RFC 6762 mDNS).

const std = @import("std");
const c_bindings = @import("bindings");
const utils = @import("utils.zig");
const multicast = @import("multicast.zig");

/// How long a host gets to answer its NetBIOS and mDNS name queries,
/// in milliseconds. Both go out at once and share it.
const NAME_QUERY_TIMEOUT_MS = 200;

/// Resolve a single host's name using NetBIOS, mDNS, and Reverse DNS PTR.
/// `mdns_name` is the host's mDNS name when a multicast reply already
/// gave it: it takes the mDNS query's place and nothing else's, so a
/// host that also answers NetBIOS keeps its NetBIOS name, as before.
/// Returns an allocated string for the caller to free, or null if unknown.
///
/// The NetBIOS and mDNS queries go out together and share one wait,
/// which ends as soon as each has its answer or was refused: a host
/// with neither service refuses both in a round trip. Asked one after
/// the other, each with its own wait, they took up to twice as long.
pub fn resolveHostName(allocator: std.mem.Allocator, ip: [4]u8, mdns_name: ?[]const u8) ?[]const u8 {
    var name_buf: [256]u8 = undefined;
    var netbios_reply: [1024]u8 = undefined;
    var mdns_reply: [1024]u8 = undefined;
    var mdns_query: [64]u8 = undefined;
    var exchanges = [2]c_bindings.UdpExchange{
        .init(NETBIOS_PORT, &netbios_request, &netbios_reply),
        .init(multicast.MDNS_PORT, multicast.reverseQuery(&mdns_query, ip), &mdns_reply),
    };
    // A name heard already needs no mDNS query.
    c_bindings.udpExchangeAll(ip, exchanges[0..if (mdns_name == null) 2 else 1], NAME_QUERY_TIMEOUT_MS);

    // 1. NetBIOS (Windows, Samba, NAS)
    if (exchanges[0].reply()) |reply| {
        if (netbiosName(reply)) |nb_name| {
            const trimmed = std.mem.trim(u8, nb_name, " \t\r\n");
            if (trimmed.len > 0) {
                return allocator.dupe(u8, trimmed) catch null;
            }
        }
    }

    // 2. mDNS (PS5, Hue, Apple, Smart TVs)
    const heard = mdns_name orelse if (exchanges[1].reply()) |reply| multicast.hostName(reply, ip, &name_buf) else null;
    if (heard) |name| {
        const clean_name = cleanDomainName(name);
        if (clean_name.len > 0) {
            return allocator.dupe(u8, clean_name) catch null;
        }
    }

    // 3. Try reverse DNS (getnameinfo; DNS only on Windows, see resolver.c)
    var ip_buf: [16]u8 = undefined;
    const ip_str = utils.ipToCString(&ip_buf, ip);
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

/// Ask `ip` for its own name by unicast mDNS ("d.c.b.a.in-addr.arpa
/// PTR", RFC 6762 section 6.7) and read the reply with the same parser
/// the multicast listener uses, so a PTR answer counts only when it is
/// about `ip`. `port` is MDNS_PORT outside tests.
pub fn queryMdns(ip: [4]u8, port: u16, timeout_ms: c_int, out: *[256]u8) ?[]const u8 {
    var query_buf: [64]u8 = undefined;
    var reply_buf: [1024]u8 = undefined;
    var exchange = [1]c_bindings.UdpExchange{.init(port, multicast.reverseQuery(&query_buf, ip), &reply_buf)};
    c_bindings.udpExchangeAll(ip, &exchange, timeout_ms);
    return multicast.hostName(exchange[0].reply() orelse return null, ip, out);
}

pub const NETBIOS_PORT: u16 = 137;

/// NetBIOS Node Status Request (RFC 1002 section 4.2.17) for the
/// wildcard name "*": "which names do you have?"
pub const netbios_request: [50]u8 = [_]u8{
    0x13, 0x37, // Transaction ID
    0x00, 0x00, // Flags: query
    0x00, 0x01, // QDCOUNT: 1
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ANCOUNT, NSCOUNT, ARCOUNT
    0x20, // Name length: 32
    'C', 'K', // '*', first-level encoded: the name is '*' and 15 NULs
} ++ @as([30]u8, @splat('A')) ++ [_]u8{
    0x00, // Terminator
    0x00, 0x21, // Type: NBSTAT
    0x00, 0x01, // Class: IN
};

/// The host's own name from a Node Status Response to netbios_request:
/// its first unique workstation (0x00) or server (0x20) name, without
/// the padding. Names with anything but printable ASCII are skipped, so
/// a reply cannot slip terminal escapes into the output. Null when the
/// reply is not one, or names nothing usable.
pub fn netbiosName(reply: []const u8) ?[]const u8 {
    // The answer's name table starts after the header (12 bytes), the
    // echoed name (34), type, class, TTL and data length (10), and its
    // count (1).
    const table_start = 57;
    const entry_len = 18;
    if (reply.len < table_start or reply[0] != netbios_request[0] or reply[1] != netbios_request[1]) return null;
    var entries = reply[table_start..];
    for (0..reply[table_start - 1]) |_| {
        if (entries.len < entry_len) break;
        const entry = entries[0..entry_len];
        entries = entries[entry_len..];
        const suffix = entry[15];
        const group = entry[16] & 0x80 != 0;
        if (group or (suffix != 0x00 and suffix != 0x20)) continue;
        const name = std.mem.trimEnd(u8, entry[0..15], " ");
        if (name.len == 0) continue;
        for (name) |char| {
            if (char < 32 or char > 126) break;
        } else return name;
    }
    return null;
}

/// Strip trailing domain components from reverse DNS results (e.g. "myhost.localdomain" -> "myhost").
pub fn cleanDomainName(raw: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return trimmed;
    const dot = std.mem.findScalar(u8, trimmed, '.');
    const clean_name = if (dot) |d| trimmed[0..d] else trimmed;
    return if (clean_name.len > 0) clean_name else trimmed;
}
