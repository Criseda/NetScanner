//! The packets of multicast discovery: what `ns -s` sends to the mDNS
//! and SSDP groups, and how it reads what comes back. Many LAN devices
//! (phones, printers, TVs, speakers) drop unsolicited TCP and ICMP yet
//! answer service discovery, so one query to each group finds them
//! while the TCP sweep runs. The sockets live in src/c/multicast.c and
//! the listener in scanner.zig; nothing here touches the network, so
//! tests can exercise all of it.

const std = @import("std");

pub const MDNS_GROUP = [4]u8{ 224, 0, 0, 251 };
pub const MDNS_PORT: u16 = 5353;
pub const SSDP_GROUP = [4]u8{ 239, 255, 255, 250 };
pub const SSDP_PORT: u16 = 1900;

/// mDNS service enumeration (RFC 6763 section 9): "which service types
/// are on this link?" Every responder that offers any service answers.
/// Sent from an ephemeral port, it is a "legacy unicast" query (RFC
/// 6762 section 6.7), so the answers come straight back to that port.
pub const services_query = dnsQuery(0x4E53, &.{ "_services", "_dns-sd", "_udp", "local" }, DNS_TYPE_PTR);

/// SSDP search for everything (UPnP Device Architecture 1.1, 1.3.2).
/// MX 1 lets devices spread their answers over at most a second, which
/// a /24 sweep covers.
pub const ssdp_search =
    "M-SEARCH * HTTP/1.1\r\n" ++
    "HOST: 239.255.255.250:1900\r\n" ++
    "MAN: \"ssdp:discover\"\r\n" ++
    "MX: 1\r\n" ++
    "ST: ssdp:all\r\n" ++
    "\r\n";

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_PTR: u16 = 12;
const DNS_CLASS_IN: u16 = 1;
const DNS_HEADER_LEN = 12;

/// A one-question DNS query for `labels`, built at compile time.
fn dnsQuery(comptime id: u16, comptime labels: []const []const u8, comptime qtype: u16) []const u8 {
    comptime {
        var packet: []const u8 = &.{
            id >> 8, id & 0xFF, // ID
            0, 0, // flags: standard query
            0, 1, // QDCOUNT
            0, 0, 0, 0, 0, 0, // ANCOUNT, NSCOUNT, ARCOUNT
        };
        for (labels) |label| packet = packet ++ [_]u8{label.len} ++ label;
        packet = packet ++ [_]u8{ 0, qtype >> 8, qtype & 0xFF, DNS_CLASS_IN >> 8, DNS_CLASS_IN & 0xFF };
        const final = packet[0..packet.len].*;
        return &final;
    }
}

/// The unicast mDNS name query for `ip` ("d.c.b.a.in-addr.arpa PTR"),
/// as src/c/resolver.c's query_mdns sends it, built in `buf`. Sent to a
/// responder the moment it shows up, so its name is already known when
/// `--hostname` asks for it.
pub fn reverseQuery(buf: *[64]u8, ip: [4]u8) []const u8 {
    const header = [_]u8{ 0x4E, 0x54, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    @memcpy(buf[0..header.len], &header);
    var len: usize = header.len;
    var i: usize = 4;
    while (i > 0) {
        i -= 1;
        const digits = std.fmt.bufPrint(buf[len + 1 ..], "{d}", .{ip[i]}) catch unreachable;
        buf[len] = @intCast(digits.len);
        len += 1 + digits.len;
    }
    const tail = [_]u8{ 7, 'i', 'n', '-', 'a', 'd', 'd', 'r', 4, 'a', 'r', 'p', 'a', 0, 0, DNS_TYPE_PTR, 0, DNS_CLASS_IN };
    @memcpy(buf[len..][0..tail.len], &tail);
    return buf[0 .. len + tail.len];
}

/// Which protocol a datagram that reached the discovery socket speaks.
pub const Kind = enum { mdns, ssdp };

/// What a reply is, or null for anything that is neither an SSDP search
/// response nor a DNS response (only replies count as proof of life,
/// never a stray query).
pub fn classify(data: []const u8) ?Kind {
    const ssdp_ok = "HTTP/1.1 200";
    if (data.len >= ssdp_ok.len and std.ascii.eqlIgnoreCase(data[0..ssdp_ok.len], ssdp_ok)) return .ssdp;
    // QR set (a response) and opcode 0 (a standard query's answer).
    if (data.len >= DNS_HEADER_LEN and data[2] & 0xF8 == 0x80) return .mdns;
    return null;
}

/// The name an mDNS reply from `from` gives that host, decoded into
/// `out` (e.g. "printer.local"): the answer to a reverse query for it
/// ("d.c.b.a.in-addr.arpa PTR name") if there is one, otherwise the
/// owner of an address record pointing at it ("name A from"). Null when
/// the reply names nobody at that address, or is malformed.
pub fn hostName(packet: []const u8, from: [4]u8, out: *[256]u8) ?[]const u8 {
    if (packet.len < DNS_HEADER_LEN) return null;
    const qdcount = readU16(packet, 4);
    const records = @as(usize, readU16(packet, 6)) + readU16(packet, 8) + readU16(packet, 10);

    var reverse_buf: [32]u8 = undefined;
    const reverse = std.fmt.bufPrint(&reverse_buf, "{d}.{d}.{d}.{d}.in-addr.arpa", .{ from[3], from[2], from[1], from[0] }) catch unreachable;

    var pos: usize = DNS_HEADER_LEN;
    for (0..qdcount) |_| {
        pos = skipName(packet, pos) orelse return null;
        pos += 4; // QTYPE, QCLASS
    }

    var owner_buf: [256]u8 = undefined;
    var by_address: ?[]const u8 = null;
    for (0..records) |_| {
        if (pos > packet.len) return null;
        const owner_pos = pos;
        pos = skipName(packet, pos) orelse return null;
        if (pos + 10 > packet.len) return null;
        const rtype = readU16(packet, pos);
        const rdlen = readU16(packet, pos + 8);
        const rdata = pos + 10;
        pos = rdata + rdlen;
        if (pos > packet.len) return null;

        if (rtype == DNS_TYPE_PTR) {
            const owner = decodeName(packet, owner_pos, &owner_buf) orelse continue;
            if (!std.ascii.eqlIgnoreCase(owner, reverse)) continue;
            return decodeName(packet, rdata, out);
        }
        if (rtype == DNS_TYPE_A and rdlen == 4 and by_address == null and
            std.mem.eql(u8, packet[rdata..][0..4], &from))
        {
            by_address = decodeName(packet, owner_pos, out);
        }
    }
    return by_address;
}

fn readU16(packet: []const u8, pos: usize) u16 {
    return std.mem.readInt(u16, packet[pos..][0..2], .big);
}

/// Where the record after the name at `pos` starts, or null if the name
/// runs off the end of the packet.
fn skipName(packet: []const u8, start: usize) ?usize {
    var pos = start;
    while (pos < packet.len) {
        const len = packet[pos];
        if (len == 0) return pos + 1;
        if (len & 0xC0 == 0xC0) return if (pos + 2 <= packet.len) pos + 2 else null;
        if (len & 0xC0 != 0) return null;
        pos += 1 + len;
    }
    return null;
}

/// Most compression pointers one name may follow. A name pointing back
/// at itself would otherwise loop forever.
const MAX_JUMPS = 16;

/// The dotted name at `start`, following compression pointers. Null for
/// a malformed name, an empty one, or one with a character outside
/// printable ASCII: names end up on a terminal, so an escape sequence
/// must not get through.
fn decodeName(packet: []const u8, start: usize, out: *[256]u8) ?[]const u8 {
    var pos = start;
    var len: usize = 0;
    var jumps: usize = 0;
    while (true) {
        if (pos >= packet.len) return null;
        const label_len = packet[pos];
        if (label_len == 0) break;
        if (label_len & 0xC0 == 0xC0) {
            if (pos + 1 >= packet.len or jumps == MAX_JUMPS) return null;
            jumps += 1;
            pos = (@as(usize, label_len & 0x3F) << 8) | packet[pos + 1];
            continue;
        }
        if (label_len & 0xC0 != 0) return null;
        const label_start = pos + 1;
        const label_end = label_start + label_len;
        if (label_end > packet.len) return null;
        const dot: usize = @intFromBool(len > 0);
        if (len + dot + label_len > out.len) return null;
        if (dot == 1) out[len] = '.';
        len += dot;
        for (packet[label_start..label_end]) |char| {
            if (char < 32 or char > 126) return null;
            out[len] = char;
            len += 1;
        }
        pos = label_end;
    }
    if (len == 0) return null;
    return out[0..len];
}
