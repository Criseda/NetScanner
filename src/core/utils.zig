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
    return .init(.stdout(), io, buffer);
}

pub fn printUsage(io: std.Io) !void {
    const usage =
        \\ns <command>
        \\
        \\Usage:
        \\
        \\ns -p <ip> <port-range>    Scan one IP for open ports (example: 192.168.1.1 1-1024)
        \\ns -s <subnet> [--ping]    Find live hosts in a subnet (example: 192.168.0.1/24)
        \\                           Default is fast TCP + ARP discovery; --ping uses ICMP instead
        \\ns --help                  Display this help message
        \\ns --version               Display the version of NetScanner
    ;
    var buf: [1024]u8 = undefined;
    var w = stdoutWriter(io, &buf);
    try w.interface.print("{s}\n", .{usage});
    try w.interface.flush();
}

pub fn printVersion(io: std.Io) !void {
    const version = "v0.3.0";
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

pub fn ipStringToBytes(ip_string: []const u8) !([4]u8) {
    var ip_bytes: [4]u8 = undefined;
    var byte: u8 = 0;
    var byte_index: u8 = 0;
    var ip_string_index: usize = 0;

    while (ip_string_index < ip_string.len) : (ip_string_index += 1) {
        const char = ip_string[ip_string_index];
        if (char == '.') {
            if (byte_index >= 4) {
                return error.InvalidIpAddress;
            }
            ip_bytes[byte_index] = byte;
            byte = 0;
            byte_index += 1;
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
    }

    if (byte_index != 3) {
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

/// Parse one neighbour-table line into an IP address.
///
/// Understands two formats:
///   `arp -a` (macOS/Linux): "? (192.168.1.1) at 10:e6:... on en0 ..."
///   `ip neigh` (Linux):     "192.168.1.1 dev eth0 lladdr 10:e6:... REACHABLE"
/// Returns null for dead entries (incomplete/FAILED), multicast lines
/// and anything unparseable (including the Windows format, for now).
pub fn parseArpLine(line: []const u8) ?[4]u8 {
    const trimmed = std.mem.trim(u8, line, " \t\r");
    if (trimmed.len == 0) return null;
    if (std.mem.indexOf(u8, trimmed, "incomplete") != null) return null;
    if (std.mem.indexOf(u8, trimmed, "FAILED") != null) return null;
    // `arp -a` puts the address in parentheses ...
    if (std.mem.indexOfScalar(u8, trimmed, '(')) |open| {
        const close = std.mem.indexOfScalarPos(u8, trimmed, open, ')') orelse return null;
        return ipStringToBytes(trimmed[open + 1 .. close]) catch null;
    }
    // ... while `ip neigh` leads with it.
    const end = std.mem.indexOfScalar(u8, trimmed, ' ') orelse trimmed.len;
    const ip = ipStringToBytes(trimmed[0..end]) catch return null;
    // Multicast and reserved ranges are never LAN hosts.
    if (ip[0] >= 224) return null;
    return ip;
}
