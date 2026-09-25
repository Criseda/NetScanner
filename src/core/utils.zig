const std = @import("std");

pub const Network = struct {
    address: [4]u8,
    prefix_len: u8,
};

pub const IpRange = struct {
    start: [4]u8,
    end: [4]u8,
};

fn stdoutWriter(io: std.Io, buffer: []u8) std.Io.File.Writer {
    return .initStreaming(.stdout(), io, buffer);
}

pub fn printUsage(io: std.Io) !void {
    const usage =
        \\NetScanner - Fast, zero-privilege network discovery & port scanner
        \\
        \\USAGE:
        \\  ns -s <subnet> [options]
        \\  ns -p <ip> <ports> [options]
        \\  ns [flags]
        \\
        \\COMMANDS:
        \\  -s <subnet>                 Find live hosts in a subnet (e.g. 192.168.0.1/24)
        \\                              Default: fast TCP + ARP sweep; use --ping for ICMP
        \\  -p <ip> <ports>             Scan an IP for open ports (e.g. 192.168.1.1 1-1024)
        \\
        \\SUBNET OPTIONS (-s):
        \\  --resolve                   Resolve hostnames and hardware manufacturers
        \\  --hostname                  Resolve hostnames only (mDNS, NetBIOS, Reverse DNS)
        \\  --vendor                    Lookup MAC addresses and hardware manufacturers
        \\  --oui-file <path>           Load custom Wireshark or IEEE OUI database file
        \\  --ping                      Use ICMP ping sweep instead of TCP + ARP
        \\
        \\PORT OPTIONS (-p):
        \\  --timeout <ms>              Probe connection timeout in milliseconds (default: 500)
        \\
        \\OUTPUT OPTIONS (-s, -p):
        \\  --json                      One JSON object per line, for scripts and apps
        \\
        \\FLAGS:
        \\  -h, --help                  Display this help message
        \\  -v, --version               Display version information
        \\
        \\EXAMPLES:
        \\  ns -s 192.168.0.1/24 --resolve
        \\  ns -s 10.0.0.1/24 --ping
        \\  ns -p 192.168.1.1 20-80 --timeout 250
    ;
    var buf: [2048]u8 = undefined;
    var w = stdoutWriter(io, &buf);
    try w.interface.print("{s}\n", .{usage});
    try w.interface.flush();
}

pub fn printVersion(io: std.Io) !void {
    const version = "v1.3.0";
    var buf: [64]u8 = undefined;
    var w = stdoutWriter(io, &buf);
    try w.interface.print("{s}\n", .{version});
    try w.interface.flush();
}

/// Print a line to stdout. Each call flushes, so it is safe to use from
/// multiple threads as long as callers serialize with `mutex`.
pub fn printStdout(io: std.Io, mutex: *std.Io.Mutex, comptime fmt: []const u8, args: anytype) void {
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    var buf: [1024]u8 = undefined;
    var w = stdoutWriter(io, &buf);
    w.interface.print(fmt, args) catch {};
    w.interface.flush() catch {};
}

/// Escape `s` for use inside a JSON string literal (without the quotes),
/// writing into `buf`. Hostnames and vendor names come off the network
/// or an OUI file, so quotes, backslashes and control bytes must never
/// reach `--json` output raw. Bytes >= 0x80 pass through untouched (JSON
/// is UTF-8). Output that would not fit is cut at a whole escape, never
/// mid-sequence, so the result is always valid inside quotes.
pub fn jsonEscape(buf: []u8, s: []const u8) []const u8 {
    const hex = "0123456789abcdef";
    var n: usize = 0;
    for (s) |c| {
        var tmp: [6]u8 = undefined;
        const piece: []const u8 = switch (c) {
            '"' => "\\\"",
            '\\' => "\\\\",
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            0...8, 11, 12, 14...0x1f, 0x7f => blk: {
                tmp = .{ '\\', 'u', '0', '0', hex[c >> 4], hex[c & 0xf] };
                break :blk &tmp;
            },
            else => blk: {
                tmp[0] = c;
                break :blk tmp[0..1];
            },
        };
        if (n + piece.len > buf.len) break;
        @memcpy(buf[n .. n + piece.len], piece);
        n += piece.len;
    }
    return buf[0..n];
}

/// `s` as a complete JSON value, written into `buf`: a quoted, escaped
/// string, or `null` when `s` is absent. For optional fields, which
/// `--json` prints as null rather than leaving out.
pub fn jsonStringOrNull(buf: []u8, s: ?[]const u8) []const u8 {
    const value = s orelse return "null";
    if (buf.len < 2) return "null";
    const escaped = jsonEscape(buf[1 .. buf.len - 1], value);
    buf[0] = '"';
    buf[escaped.len + 1] = '"';
    return buf[0 .. escaped.len + 2];
}

pub fn ipStringToBytes(ip_string: []const u8) !([4]u8) {
    var ip_bytes: [4]u8 = undefined;
    var byte: u8 = 0;
    var byte_index: u8 = 0;
    var has_digits = false;
    var ip_string_index: usize = 0;

    while (ip_string_index < ip_string.len) : (ip_string_index += 1) {
        const char = ip_string[ip_string_index];
        if (char == '.') {
            if (byte_index >= 4 or !has_digits) {
                return error.InvalidIpAddress;
            }
            ip_bytes[byte_index] = byte;
            byte = 0;
            byte_index += 1;
            has_digits = false;
            continue;
        }
        if (char < '0' or char > '9') {
            return error.InvalidIpAddress;
        }
        const digit = char - '0';
        // Reject octets above 255 without overflowing the u8.
        if (byte > (255 - digit) / 10) {
            return error.InvalidIpAddress;
        }
        byte = byte * 10 + digit;
        has_digits = true;
    }

    if (byte_index != 3 or !has_digits) {
        return error.InvalidIpAddress;
    }
    ip_bytes[byte_index] = byte;
    return ip_bytes;
}

pub fn ipBytesToString(allocator: std.mem.Allocator, ip: [4]u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
}

/// Split "1-1024" on the delimiter into port numbers.
/// Rejects non-digits, zeros and values above 65535.
pub fn splitStringToIntArray(allocator: std.mem.Allocator, string: []const u8, delimiter: u8) !([]u16) {
    var array: std.ArrayList(u16) = .empty;
    errdefer array.deinit(allocator);

    var number: u16 = 0;
    var has_digits = false;

    for (string) |char| {
        if (char == delimiter) {
            if (!has_digits) return error.InvalidPortRange;
            try array.append(allocator, number);
            number = 0;
            has_digits = false;
            continue;
        }
        if (char < '0' or char > '9') {
            return error.InvalidPortRange;
        }
        const digit: u16 = char - '0';
        if (number > (65535 - digit) / 10) {
            return error.InvalidPortRange;
        }
        number = number * 10 + digit;
        if (number == 0) {
            return error.InvalidPortRange;
        }
        has_digits = true;
    }

    if (!has_digits) return error.InvalidPortRange;
    try array.append(allocator, number);
    return array.toOwnedSlice(allocator);
}

pub fn parseCidr(cidr: []const u8) !Network {
    var iter = std.mem.splitScalar(u8, cidr, '/');
    const ip_str = iter.next() orelse return error.InvalidCidr;
    const prefix_str = iter.next() orelse return error.InvalidCidr;

    if (iter.next() != null) return error.InvalidCidr;

    const address: [4]u8 = try ipStringToBytes(ip_str);

    const prefix_len = try std.fmt.parseInt(u8, prefix_str, 10);
    if (prefix_len > 32) return error.InvalidPrefixLength;

    return Network{ .address = address, .prefix_len = prefix_len };
}

pub fn getIpRange(network: Network) !IpRange {
    const mask: u32 = computeMask(network.prefix_len);
    const start_ip = ipToU32(network.address) & mask;
    const end_ip = start_ip | ~mask;
    return .{ .start = u32ToIp(start_ip), .end = u32ToIp(end_ip) };
}

fn computeMask(prefix_len: u8) u32 {
    if (prefix_len == 0) return 0;
    if (prefix_len == 32) {
        return 0xFFFFFFFF;
    } else {
        return @as(u32, 0xFFFFFFFF) << @intCast(32 - prefix_len);
    }
}

pub fn incrementIP(ip: *[4]u8) void {
    var i: i32 = 3;
    while (i >= 0) : (i -= 1) {
        ip[@intCast(i)] +%= 1;
        if (ip[@intCast(i)] != 0) break;
    }
}

pub fn decrementIP(ip: *[4]u8) void {
    var i: i32 = 3;
    while (i >= 0) : (i -= 1) {
        const old = ip[@intCast(i)];
        ip[@intCast(i)] -%= 1;
        if (old != 0) break;
    }
}

/// Expand first..last into a list, inclusive on both ends.
pub fn collectIps(allocator: std.mem.Allocator, first_ip: [4]u8, last_ip: [4]u8) !std.ArrayList([4]u8) {
    var ips: std.ArrayList([4]u8) = .empty;
    errdefer ips.deinit(allocator);
    var ip = first_ip;
    while (true) {
        try ips.append(allocator, ip);
        if (std.mem.eql(u8, &ip, &last_ip)) break;
        incrementIP(&ip);
    }
    return ips;
}

/// First and last scannable host addresses of a range.
///
/// The network and broadcast addresses are not hosts, so they are left
/// out. /31 and /32 ranges have no such addresses and pass through
/// untouched.
pub fn usableHosts(network: Network, range: IpRange) IpRange {
    if (network.prefix_len >= 31) return range;
    var first = range.start;
    var last = range.end;
    incrementIP(&first);
    decrementIP(&last);
    return .{ .start = first, .end = last };
}

pub fn ipToU32(ip: [4]u8) u32 {
    return (@as(u32, ip[0]) << 24) | (@as(u32, ip[1]) << 16) | (@as(u32, ip[2]) << 8) | ip[3];
}

pub fn u32ToIp(value: u32) [4]u8 {
    return .{
        @truncate((value >> 24) & 0xFF),
        @truncate((value >> 16) & 0xFF),
        @truncate((value >> 8) & 0xFF),
        @truncate(value & 0xFF),
    };
}

pub fn ipInRange(ip: [4]u8, first: [4]u8, last: [4]u8) bool {
    const value = ipToU32(ip);
    return value >= ipToU32(first) and value <= ipToU32(last);
}

/// Represents a single host entry discovered from the operating system's
/// kernel neighbour/ARP table.
pub const ArpEntry = struct {
    ip: [4]u8,
    mac: ?[6]u8 = null,
    /// On Linux, `ip neigh` explicitly marks confirmed entries as "REACHABLE"
    /// or "DELAY" (currently undergoing reachability confirmation).
    is_reachable: bool = false,
};

/// Parse a MAC address in colon or hyphen format (e.g., "64-fa-2b-b0-93-f1" or "10:e6:6b:26:7e:53").
pub fn parseMac(s: []const u8) ?[6]u8 {
    var mac: [6]u8 = undefined;
    var byte_idx: usize = 0;
    var iter = std.mem.tokenizeAny(u8, s, ":-");
    while (iter.next()) |token| {
        if (byte_idx >= 6) return null;
        if (token.len < 1 or token.len > 2) return null;
        const val = std.fmt.parseInt(u8, token, 16) catch return null;
        mac[byte_idx] = val;
        byte_idx += 1;
    }
    if (byte_idx != 6) return null;
    return mac;
}

/// Format a MAC address into "aa:bb:cc:dd:ee:ff" lowercase string.
pub fn formatMac(buf: *[17]u8, mac: [6]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
    }) catch "00:00:00:00:00:00";
}

/// Parse one neighbour-table line into an ArpEntry (IP, optional MAC, and reachability).
///
/// Understands three formats:
///   `arp -a` (macOS/Linux): "? (192.168.1.1) at 00:11:... on en0 ..."
///   `arp -a` (Windows):     "  192.168.1.1  00-11-22-33-44-55  dynamic"
///   `ip neigh` (Linux):     "192.168.1.1 dev eth0 lladdr 00:11:... REACHABLE"
/// Returns null for dead entries (incomplete/FAILED), header lines,
/// multicast rows and anything unparseable.
pub fn parseArpEntry(line: []const u8) ?ArpEntry {
    const trimmed = std.mem.trim(u8, line, " \t\r");
    if (trimmed.len == 0) return null;
    if (std.mem.indexOf(u8, trimmed, "incomplete") != null) return null;
    if (std.mem.indexOf(u8, trimmed, "FAILED") != null) return null;

    // `arp -a` on macOS/Linux puts the address in parentheses ...
    if (std.mem.indexOfScalar(u8, trimmed, '(')) |open| {
        const close = std.mem.indexOfScalarPos(u8, trimmed, open, ')') orelse return null;
        const ip = ipStringToBytes(trimmed[open + 1 .. close]) catch return null;
        if (ip[0] >= 224) return null;

        var mac: ?[6]u8 = null;
        if (std.mem.indexOfPos(u8, trimmed, close, " at ")) |at_pos| {
            const rest = std.mem.trimStart(u8, trimmed[at_pos + 4 ..], " \t");
            const mac_end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
            mac = parseMac(rest[0..mac_end]);
        }
        return ArpEntry{ .ip = ip, .mac = mac, .is_reachable = false };
    }

    // Linux `ip neigh` has " lladdr " and reachability states (REACHABLE, DELAY, STALE, etc.)
    if (std.mem.indexOf(u8, trimmed, " lladdr ")) |lladdr_pos| {
        const end = std.mem.indexOfAny(u8, trimmed, " \t") orelse trimmed.len;
        const ip = ipStringToBytes(trimmed[0..end]) catch return null;
        if (ip[0] >= 224) return null;

        const rest = std.mem.trimStart(u8, trimmed[lladdr_pos + 8 ..], " \t");
        const mac_end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
        const mac = parseMac(rest[0..mac_end]);
        const is_reachable = std.mem.indexOf(u8, trimmed, "REACHABLE") != null or
            std.mem.indexOf(u8, trimmed, "DELAY") != null;
        return ArpEntry{ .ip = ip, .mac = mac, .is_reachable = is_reachable };
    }

    // Windows `arp -a` rows lead with IP, followed by physical address
    var tokens = std.mem.tokenizeAny(u8, trimmed, " \t");
    const ip_token = tokens.next() orelse return null;
    const ip = ipStringToBytes(ip_token) catch return null;
    if (ip[0] >= 224) return null;

    var mac: ?[6]u8 = null;
    if (tokens.next()) |mac_token| {
        mac = parseMac(mac_token);
    }
    return ArpEntry{ .ip = ip, .mac = mac };
}

/// Parse one neighbour-table line into an IP address.
pub fn parseArpLine(line: []const u8) ?[4]u8 {
    const entry = parseArpEntry(line) orelse return null;
    return entry.ip;
}
