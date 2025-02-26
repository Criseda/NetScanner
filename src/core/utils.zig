const std = @import("std");

pub const Network = struct {
    address: [4]u8,
    prefix_len: u8,
};

pub const IpRange = struct {
    start: [4]u8,
    end: [4]u8,
};

pub fn printUsage() !void {
    const usage =
        \\ns <command>
        \\
        \\Usage:
        \\
        \\ns -p <ip> <port-range>    Scan a single IP address for open ports (example: 192.168.1.1 1-1024)
        \\ns -s <subnet>             The subnet to scan for IPs in CIDR notation (example: 192.168.0.1/24)
        \\ns --help                  Display this help message
        \\ns --version               Display the version of NetScanner
    ;
    const stdout = std.io.getStdOut().writer();
    try stdout.print("{s}\n", .{usage});
}

pub fn printVersion() !void {
    const version = "v0.3.0";
    const stdout = std.io.getStdOut().writer();
    try stdout.print("{s}\n", .{version});
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
            if (byte > 255) {
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
        // Convert the character to a digit
        const digit = char - '0';
        // Check for overflow
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

pub fn splitStringToIntArray(allocator: std.mem.Allocator, string: []const u8, delimiter: u8) !([]u16) {
    // Initial allocation with a size of 2
    var array: []u16 = try allocator.alloc(u16, 1);
    errdefer allocator.free(array);
    var array_index: usize = 0;
    var number: u16 = 0;
    var string_index: usize = 0;

    while (string_index < string.len) : (string_index += 1) {
        const char = string[string_index];
        if (char == delimiter) {
            if (array_index >= array.len) {
                // Use realloc to increase the size of the array
                const new_array = try allocator.realloc(array, array.len * 2);
                array = new_array;
            }
            array[array_index] = number;
            number = 0;
            array_index += 1;
            continue;
        }
        // Port specific checks (TODO: Refactor this into a separate function)
        if (char < '0' or char > '9') {
            return error.InvalidPortRange;
        }
        // Convert the character to a digit
        const digit: u16 = char - '0';
        // Check for overflow
        if (number > (65535 - digit) / 10) {
            return error.InvalidPortRange;
        }
        number = number * 10 + digit;

        // Throw an error if the number is zero or less
        if (number <= 0) {
            return error.InvalidPortRange;
        }
    }

    // Handle the last number after the loop
    if (array_index >= array.len) {
        const new_array = try allocator.realloc(array, array.len + 1);
        array = new_array;
    }
    array[array_index] = number;

    return array[0 .. array_index + 1];
}

pub fn parseCidr(cidr: []const u8) !Network {
    var iter = std.mem.split(u8, cidr, "/");
    const ip_str = iter.next() orelse return error.InvalidCidr;
    const prefix_str = iter.next() orelse return error.InvalidCidr;

    if (iter.next() != null) return error.InvalidCidr;

    const address: [4]u8 = try ipStringToBytes(ip_str);

    const prefix_len = try std.fmt.parseInt(u8, prefix_str, 10);
    if (prefix_len > 32) return error.InvalidPrefixLength;

    return Network{ .address = address, .prefix_len = prefix_len };
}

//TODO: FIX THIS
pub fn getIpRange(network: Network) !IpRange {
    const mask: u32 = computeMask(network.prefix_len);
    const start_ip = (@as(u32, network.address[0]) << 24) | (@as(u32, network.address[1]) << 16) | (@as(u32, network.address[2]) << 8) | network.address[3];
    const network_start = start_ip & mask;
    const network_end = network_start | ~mask;

    const start_ip_bytes = [4]u8{
        @truncate((network_start >> 24) & 0xFF),
        @truncate((network_start >> 16) & 0xFF),
        @truncate((network_start >> 8) & 0xFF),
        @truncate(network_start & 0xFF),
    };

    const end_ip_bytes = [4]u8{
        @truncate((network_end >> 24) & 0xFF),
        @truncate((network_end >> 16) & 0xFF),
        @truncate((network_end >> 8) & 0xFF),
        @truncate(network_end & 0xFF),
    };

    return IpRange{
        .start = start_ip_bytes,
        .end = end_ip_bytes,
    };
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
