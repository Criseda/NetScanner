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

test "ipStringToBytes rejects empty octets" {
    const bad = [_][]const u8{ "", ".", "...", ".168.0.1", "192..0.1", "192.168..1", "192.168.0.", "192.168.0.1." };
    for (bad) |input| {
        try std.testing.expectError(error.InvalidIpAddress, utils.ipStringToBytes(input));
    }
}

test "ipStringToBytes accepts zero octets" {
    const result = try utils.ipStringToBytes("0.0.0.0");
    try std.testing.expectEqualSlices(u8, &[4]u8{ 0, 0, 0, 0 }, &result);
}

test "formatIp fits the longest address" {
    var buf: [15]u8 = undefined;
    try std.testing.expectEqualStrings("192.168.0.1", utils.formatIp(&buf, .{ 192, 168, 0, 1 }));
    try std.testing.expectEqualStrings("255.255.255.255", utils.formatIp(&buf, .{ 255, 255, 255, 255 }));
    try std.testing.expectEqualStrings("0.0.0.0", utils.formatIp(&buf, .{ 0, 0, 0, 0 }));
}

test "ipToCString fits the longest address and terminates it" {
    var buf: [16]u8 = undefined;
    const longest = utils.ipToCString(&buf, .{ 255, 255, 255, 255 });
    try std.testing.expectEqualStrings("255.255.255.255", longest);
    try std.testing.expectEqual(@as(u8, 0), longest.ptr[longest.len]);
    try std.testing.expectEqualStrings("10.0.0.1", utils.ipToCString(&buf, .{ 10, 0, 0, 1 }));
}

test "splitStringToIntArray handles port range correctly" {
    const allocator = std.testing.allocator;
    const result = try utils.splitStringToIntArray(allocator, "1-1024", '-');
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqual(@as(u16, 1), result[0]);
    try std.testing.expectEqual(@as(u16, 1024), result[1]);
}

test "splitStringToIntArray rejects bad ranges" {
    const allocator = std.testing.allocator;
    const bad = [_][]const u8{ "", "-1024", "1024-", "1--1024", "0-1024", "1-65536", "abc", "1-x" };
    for (bad) |input| {
        const result = utils.splitStringToIntArray(allocator, input, '-');
        try std.testing.expectError(error.InvalidPortRange, result);
    }
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

test "getIpRange handles zero prefix" {
    const network = try utils.parseCidr("192.168.1.1/0");
    const range = try utils.getIpRange(network);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 0, 0, 0, 0 }, &range.start);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 255, 255, 255, 255 }, &range.end);
}

test "getIpRange handles full prefix" {
    const network = try utils.parseCidr("192.168.1.1/32");
    const range = try utils.getIpRange(network);
    try std.testing.expectEqualSlices(u8, &network.address, &range.start);
    try std.testing.expectEqualSlices(u8, &network.address, &range.end);
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

test "collectIps expands a range inclusively" {
    const allocator = std.testing.allocator;
    var ips = try utils.collectIps(allocator, .{ 192, 168, 1, 1 }, .{ 192, 168, 1, 3 });
    defer ips.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), ips.items.len);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 1 }, &ips.items[0]);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 3 }, &ips.items[2]);

    var single = try utils.collectIps(allocator, .{ 10, 0, 0, 5 }, .{ 10, 0, 0, 5 });
    defer single.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), single.items.len);
}

test "parseMac and formatMac" {
    const mac_colon = utils.parseMac("00:11:22:33:44:55");
    try std.testing.expect(mac_colon != null);
    try std.testing.expectEqualSlices(u8, &[6]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }, &mac_colon.?);

    const mac_dash = utils.parseMac("AA-BB-CC-DD-EE-FF");
    try std.testing.expect(mac_dash != null);
    try std.testing.expectEqualSlices(u8, &[6]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, &mac_dash.?);

    var buf: [17]u8 = undefined;
    const formatted = utils.formatMac(&buf, mac_dash.?);
    try std.testing.expectEqualStrings("aa:bb:cc:dd:ee:ff", formatted);

    // Invalid MAC strings
    try std.testing.expect(utils.parseMac("invalid") == null);
    try std.testing.expect(utils.parseMac("00:11:22:33:44") == null);
    try std.testing.expect(utils.parseMac("00:11:22:33:44:55:66") == null);
    try std.testing.expect(utils.parseMac("00:11:22:33:44:zz") == null);
}

test "jsonEscape escapes quotes, backslashes and control bytes" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("plain-host.local", utils.jsonEscape(&buf, "plain-host.local"));
    try std.testing.expectEqualStrings("a\\\"b\\\\c", utils.jsonEscape(&buf, "a\"b\\c"));
    try std.testing.expectEqualStrings("\\n\\r\\t", utils.jsonEscape(&buf, "\n\r\t"));
    try std.testing.expectEqualStrings("\\u001b[31m\\u007f", utils.jsonEscape(&buf, "\x1b[31m\x7f"));
}

test "jsonEscape passes UTF-8 through untouched" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Soci\u{e9}t\u{e9} G\u{e9}n\u{e9}rale", utils.jsonEscape(&buf, "Soci\u{e9}t\u{e9} G\u{e9}n\u{e9}rale"));
}

test "jsonEscape never cuts an escape sequence in half" {
    // Room for "ab" plus two bytes: the 6-byte \u001b escape must be
    // dropped whole rather than truncated into invalid JSON.
    var buf: [4]u8 = undefined;
    try std.testing.expectEqualStrings("ab", utils.jsonEscape(&buf, "ab\x1bcd"));
}

test "jsonStringOrNull quotes present values and prints null for absent ones" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("\"ms-wbt-server\"", utils.jsonStringOrNull(&buf, "ms-wbt-server"));
    try std.testing.expectEqualStrings("\"say \\\"hi\\\"\"", utils.jsonStringOrNull(&buf, "say \"hi\""));
    try std.testing.expectEqualStrings("null", utils.jsonStringOrNull(&buf, null));
    try std.testing.expectEqualStrings("\"\"", utils.jsonStringOrNull(&buf, ""));
}

test "jsonStringOrNull keeps both quotes when the value is cut" {
    var buf: [5]u8 = undefined;
    try std.testing.expectEqualStrings("\"abc\"", utils.jsonStringOrNull(&buf, "abcdef"));
}
