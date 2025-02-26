const std = @import("std");
const utils = @import("core").utils;

test "ipStringToBytes converts valid IP address" {
    const result = try utils.ipStringToBytes("192.168.0.1");
    const expected: [4]u8 = [4]u8{ 192, 168, 0, 1 };
    try std.testing.expectEqualSlices(u8, &result, &expected);
}

test "ipStringToBytes rejects invalid IP address formats" {
    try std.testing.expectError(error.InvalidIpAddress, utils.ipStringToBytes("192.168.0"));
    try std.testing.expectError(error.InvalidIpAddress, utils.ipStringToBytes("192.168.0.1.5"));
    try std.testing.expectError(error.InvalidIpAddress, utils.ipStringToBytes("192.168.0.256"));
    try std.testing.expectError(error.InvalidIpAddress, utils.ipStringToBytes("abc.def.ghi.jkl"));
}

test "ipBytesToString converts bytes to string correctly" {
    const ip: [4]u8 = [4]u8{ 192, 168, 0, 1 };
    const allocator = std.testing.allocator;

    const result = try utils.ipBytesToString(allocator, ip);
    defer allocator.free(result);

    try std.testing.expectEqualStrings("192.168.0.1", result);
}

test "splitStringToIntArray handles port range correctly" {
    const allocator = std.testing.allocator;
    const result = try utils.splitStringToIntArray(allocator, "1-1024", '-');
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqual(@as(u16, 1), result[0]);
    try std.testing.expectEqual(@as(u16, 1024), result[1]);
}

test "parseCidr handles valid CIDR" {
    const network = try utils.parseCidr("192.168.1.0/24");

    const expected_address: [4]u8 = [4]u8{ 192, 168, 1, 0 };
    try std.testing.expectEqualSlices(u8, &expected_address, &network.address);
    try std.testing.expectEqual(@as(u8, 24), network.prefix_len);
}

test "parseCidr rejects invalid CIDR formats" {
    try std.testing.expectError(error.InvalidCidr, utils.parseCidr("192.168.1.0"));
    try std.testing.expectError(error.InvalidCidr, utils.parseCidr("192.168.1.0/24/25"));
    try std.testing.expectError(error.InvalidPrefixLength, utils.parseCidr("192.168.1.0/33"));
}

test "getIpRange calculates correct range" {
    const network = utils.Network{
        .address = [4]u8{ 192, 168, 1, 0 },
        .prefix_len = 24,
    };

    const range = try utils.getIpRange(network);

    const expected_start: [4]u8 = [4]u8{ 192, 168, 1, 0 };
    const expected_end: [4]u8 = [4]u8{ 192, 168, 1, 255 };

    try std.testing.expectEqualSlices(u8, &expected_start, &range.start);
    try std.testing.expectEqualSlices(u8, &expected_end, &range.end);
}

test "incrementIP increments IP address correctly" {
    var ip: [4]u8 = [4]u8{ 192, 168, 0, 255 };
    utils.incrementIP(&ip);
    const expected: [4]u8 = [4]u8{ 192, 168, 1, 0 };
    try std.testing.expectEqualSlices(u8, &expected, &ip);

    // Test overflow
    ip = [4]u8{ 255, 255, 255, 255 };
    utils.incrementIP(&ip);
    const expected_overflow: [4]u8 = [4]u8{ 0, 0, 0, 0 };
    try std.testing.expectEqualSlices(u8, &expected_overflow, &ip);
}
