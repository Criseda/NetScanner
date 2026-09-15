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

test "decrementIP decrements IP address correctly" {
    var ip: [4]u8 = [4]u8{ 192, 168, 1, 0 };
    utils.decrementIP(&ip);
    const expected: [4]u8 = [4]u8{ 192, 168, 0, 255 };
    try std.testing.expectEqualSlices(u8, &expected, &ip);

    // Test underflow
    ip = [4]u8{ 0, 0, 0, 0 };
    utils.decrementIP(&ip);
    const expected_underflow: [4]u8 = [4]u8{ 255, 255, 255, 255 };
    try std.testing.expectEqualSlices(u8, &expected_underflow, &ip);
}

test "ipInRange checks bounds inclusively" {
    const first = [4]u8{ 192, 168, 1, 1 };
    const last = [4]u8{ 192, 168, 1, 254 };
    try std.testing.expect(utils.ipInRange([4]u8{ 192, 168, 1, 1 }, first, last));
    try std.testing.expect(utils.ipInRange([4]u8{ 192, 168, 1, 254 }, first, last));
    try std.testing.expect(utils.ipInRange([4]u8{ 192, 168, 1, 100 }, first, last));
    try std.testing.expect(!utils.ipInRange([4]u8{ 192, 168, 1, 0 }, first, last));
    try std.testing.expect(!utils.ipInRange([4]u8{ 192, 168, 1, 255 }, first, last));
    try std.testing.expect(!utils.ipInRange([4]u8{ 192, 168, 2, 1 }, first, last));
}

test "parseArpLine reads macOS and Linux arp -a lines" {
    const mac = utils.parseArpLine("? (192.168.1.1) at 10:e6:6b:26:7e:53 on en0 ifscope [ethernet]");
    try std.testing.expect(mac != null);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 1 }, &mac.?);

    const linux = utils.parseArpLine("? (192.168.1.20) at aa:bb:cc:dd:ee:ff [ether] on eth0");
    try std.testing.expect(linux != null);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 20 }, &linux.?);

    // Incomplete entries and garbage yield null.
    try std.testing.expect(utils.parseArpLine("? (192.168.1.22) at (incomplete) on en0 ifscope [ethernet]") == null);
    try std.testing.expect(utils.parseArpLine("not an arp line") == null);
}

test "usableHosts skips network and broadcast addresses" {
    const network = utils.Network{ .address = .{ 192, 168, 1, 0 }, .prefix_len = 24 };
    const range = utils.IpRange{ .start = .{ 192, 168, 1, 0 }, .end = .{ 192, 168, 1, 255 } };
    const hosts = utils.usableHosts(network, range);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 1 }, &hosts.start);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 254 }, &hosts.end);

    // /31 and /32 ranges pass through untouched.
    const tiny = utils.Network{ .address = .{ 10, 0, 0, 0 }, .prefix_len = 31 };
    const tiny_range = utils.IpRange{ .start = .{ 10, 0, 0, 0 }, .end = .{ 10, 0, 0, 1 } };
    const tiny_hosts = utils.usableHosts(tiny, tiny_range);
    try std.testing.expectEqualSlices(u8, &tiny_range.start, &tiny_hosts.start);
    try std.testing.expectEqualSlices(u8, &tiny_range.end, &tiny_hosts.end);
}
