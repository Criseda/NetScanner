const std = @import("std");

pub fn printUsage() !void {
    const usage =
        \\ns <command>
        \\
        \\Usage:
        \\
        \\ns -p <ip> <port-range>    Scan a single IP address for open ports (example: 192.168.1.1 1-1024)
        \\ns -s <subnet>             The subnet to scan for IPs in CIDR notation (example: 192.168.0.1/24)
        \\ns --help                  Display this help message
        // \\ns --version               Display the version of NetScanner
    ;
    const stdout = std.io.getStdOut().writer();
    try stdout.print("{s}\n", .{usage});
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
        byte = byte * 10 + (char - '0');
    }

    if (byte_index != 3) {
        return error.InvalidIpAddress;
    }
    ip_bytes[byte_index] = byte;
    return ip_bytes;
}

pub fn splitStringToIntArray(allocator: std.mem.Allocator, string: []const u8, delimiter: u8) !([]u16) {
    // Initial allocation with a size of 2
    var array: []u16 = try allocator.alloc(u16, 2);
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
        if (char < '0' or char > '9') {
            return error.InvalidPortRange;
        }
        number = number * 10 + (char - '0');
    }

    // Handle the last number after the loop
    if (array_index >= array.len) {
        const new_array = try allocator.realloc(array, array.len + 1);
        array = new_array;
    }
    array[array_index] = number;

    return array[0 .. array_index + 1];
}

test "ipStringToBytes correctly translates IP string to byte array" {
    const result = try ipStringToBytes("192.168.0.1");
    const expected: [4]u8 = [4]u8{ 192, 168, 0, 1 };
    try std.testing.expect(std.mem.eql(u8, &result, &expected));
}

test "splitStringToIntArray correctly translates port range string to array of integers" {
    const allocator = std.testing.allocator;
    const result = try splitStringToIntArray(allocator, "1-1024", '-');
    defer allocator.free(result);
    std.debug.assert(result.len == 2);
    std.debug.assert(result[0] == 1);
    std.debug.assert(result[1] == 1024);
}
