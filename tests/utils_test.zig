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

test "parseArpLine reads macOS and Linux arp -a lines" {
    const mac = utils.parseArpLine("? (192.168.1.1) at 10:e6:6b:26:7e:53 on en0 ifscope [ethernet]");
    try std.testing.expect(mac != null);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 1 }, &mac.?);

    const linux = utils.parseArpLine("? (192.168.1.20) at aa:bb:cc:dd:ee:ff [ether] on eth0");
    try std.testing.expect(linux != null);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 20 }, &linux.?);

    // `ip neigh show` format, including dead and multicast lines.
    const neigh = utils.parseArpLine("192.168.1.20 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE");
    try std.testing.expect(neigh != null);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 20 }, &neigh.?);
    try std.testing.expect(utils.parseArpLine("192.168.1.22 dev eth0  FAILED") == null);
    try std.testing.expect(utils.parseArpLine("224.0.0.251 dev eth0 lladdr 01:00:5e:00:00:fb REACHABLE") == null);

    // Incomplete entries and garbage yield null.
    try std.testing.expect(utils.parseArpLine("? (192.168.1.22) at (incomplete) on en0 ifscope [ethernet]") == null);
    try std.testing.expect(utils.parseArpLine("not an arp line") == null);
}

test "parseArpLine reads Windows arp -a lines" {
    // Real rows: dynamic and static entries alike.
    const dynamic = utils.parseArpLine("  192.168.0.1           64-fa-2b-b0-93-f1     dynamic");
    try std.testing.expect(dynamic != null);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 0, 1 }, &dynamic.?);

    const stat = utils.parseArpLine("  192.168.0.30          2c-cf-67-89-ea-27     dynamic");
    try std.testing.expect(stat != null);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 0, 30 }, &stat.?);

    // Headers, blank lines and the empty-table message yield null.
    try std.testing.expect(utils.parseArpLine("Interface: 192.168.0.39 --- 0x5") == null);
    try std.testing.expect(utils.parseArpLine("  Internet Address      Physical Address      Type") == null);
    try std.testing.expect(utils.parseArpLine("") == null);
    try std.testing.expect(utils.parseArpLine("No ARP Entries Found.") == null);

    // Multicast, broadcast and limited-broadcast rows yield null.
    try std.testing.expect(utils.parseArpLine("  224.0.0.251           01-00-5e-00-00-fb     static") == null);
    try std.testing.expect(utils.parseArpLine("  239.255.255.250       01-00-5e-7f-ff-fa     static") == null);
    try std.testing.expect(utils.parseArpLine("  255.255.255.255       ff-ff-ff-ff-ff-ff     static") == null);
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
    const mac_colon = utils.parseMac("64:fa:2b:b0:93:f1");
    try std.testing.expect(mac_colon != null);
    try std.testing.expectEqualSlices(u8, &[6]u8{ 0x64, 0xfa, 0x2b, 0xb0, 0x93, 0xf1 }, &mac_colon.?);

    const mac_dash = utils.parseMac("00-11-32-4F-C2-75");
    try std.testing.expect(mac_dash != null);
    try std.testing.expectEqualSlices(u8, &[6]u8{ 0x00, 0x11, 0x32, 0x4f, 0xc2, 0x75 }, &mac_dash.?);

    var buf: [17]u8 = undefined;
    const formatted = utils.formatMac(&buf, mac_dash.?);
    try std.testing.expectEqualStrings("00:11:32:4f:c2:75", formatted);

    // Invalid MAC strings
    try std.testing.expect(utils.parseMac("invalid") == null);
    try std.testing.expect(utils.parseMac("00:11:22:33:44") == null);
    try std.testing.expect(utils.parseMac("00:11:22:33:44:55:66") == null);
    try std.testing.expect(utils.parseMac("00:11:22:33:44:zz") == null);
}

test "parseArpEntry extracts both IP and MAC" {
    // macOS
    const mac_line = utils.parseArpEntry("? (192.168.1.1) at 10:e6:6b:26:7e:53 on en0 ifscope [ethernet]");
    try std.testing.expect(mac_line != null);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 1 }, &mac_line.?.ip);
    try std.testing.expect(mac_line.?.mac != null);
    try std.testing.expectEqualSlices(u8, &[6]u8{ 0x10, 0xe6, 0x6b, 0x26, 0x7e, 0x53 }, &mac_line.?.mac.?);
    try std.testing.expect(!mac_line.?.is_reachable);

    // Linux ip neigh (REACHABLE)
    const neigh_line = utils.parseArpEntry("192.168.1.20 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE");
    try std.testing.expect(neigh_line != null);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 20 }, &neigh_line.?.ip);
    try std.testing.expect(neigh_line.?.mac != null);
    try std.testing.expectEqualSlices(u8, &[6]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, &neigh_line.?.mac.?);
    try std.testing.expect(neigh_line.?.is_reachable);

    // Linux ip neigh (DELAY)
    const delay_line = utils.parseArpEntry("192.168.1.21 dev eth0 lladdr 11:22:33:44:55:66 DELAY");
    try std.testing.expect(delay_line != null);
    try std.testing.expect(delay_line.?.is_reachable);

    // Linux ip neigh (STALE)
    const stale_line = utils.parseArpEntry("192.168.1.22 dev eth0 lladdr 11:22:33:44:55:77 STALE");
    try std.testing.expect(stale_line != null);
    try std.testing.expect(!stale_line.?.is_reachable);

    // Windows
    const win_line = utils.parseArpEntry("  192.168.0.30          2c-cf-67-89-ea-27     dynamic");
    try std.testing.expect(win_line != null);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 0, 30 }, &win_line.?.ip);
    try std.testing.expect(win_line.?.mac != null);
    try std.testing.expectEqualSlices(u8, &[6]u8{ 0x2c, 0xcf, 0x67, 0x89, 0xea, 0x27 }, &win_line.?.mac.?);
    try std.testing.expect(!win_line.?.is_reachable);
}
