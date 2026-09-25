const std = @import("std");
const ports = @import("core").ports;

fn expectService(port: u16, name: []const u8, iana: ?[]const u8, category: ?[]const u8) !void {
    const s = ports.lookup(port) orelse return error.TestExpectedService;
    try std.testing.expectEqualStrings(name, s.name);
    if (iana) |want| {
        try std.testing.expectEqualStrings(want, s.iana orelse return error.TestExpectedIana);
    } else {
        try std.testing.expectEqual(@as(?[]const u8, null), s.iana);
    }
    if (category) |want| {
        try std.testing.expectEqualStrings(want, s.category orelse return error.TestExpectedCategory);
    } else {
        try std.testing.expectEqual(@as(?[]const u8, null), s.category);
    }
}

test "curated labels sit next to the official IANA name" {
    try expectService(22, "SSH", "ssh", "remote");
    try expectService(80, "HTTP", "http", "web");
    try expectService(3389, "RDP", "ms-wbt-server", "remote");
    try expectService(5900, "VNC", "rfb", "remote");
    try expectService(5000, "Web app / UPnP", "commplex-main", "web");
}

test "overlay picks the IANA name in use when IANA lists several" {
    // IANA lists urd before submissions on 465, and shilp before nfs on 2049.
    try expectService(465, "SMTPS", "submissions", "mail");
    try expectService(2049, "NFS", "nfs", "file");
}

test "common ports IANA does not assign have no iana name" {
    try expectService(8123, "Home Assistant", null, "home");
    try expectService(62078, "Apple device sync", null, null);
}

test "IANA-only ports fall back to the registry name and description" {
    const s = ports.lookup(1) orelse return error.TestExpectedService;
    try std.testing.expectEqualStrings("tcpmux", s.name);
    try std.testing.expectEqualStrings("tcpmux", s.iana.?);
    try std.testing.expectEqualStrings("TCP Port Service Multiplexer", s.description.?);
    try std.testing.expectEqual(@as(?[]const u8, null), s.category);
}

test "IANA port ranges cover every port in them" {
    try expectService(6000, "x11", "x11", null);
    try expectService(6031, "x11", "x11", null);
    try expectService(6063, "x11", "x11", null);
}

test "unknown ports return null" {
    try std.testing.expectEqual(@as(?ports.Service, null), ports.lookup(0));
    try std.testing.expectEqual(@as(?ports.Service, null), ports.lookup(65534));
}

test "table is sorted, unique, and uses only documented categories" {
    const categories = [_][]const u8{
        "web",      "remote",    "file", "mail",    "dns", "database", "directory", "media",
        "printing", "messaging", "voip", "network", "vpn", "proxy",    "home",
    };
    try std.testing.expect(ports.EMBEDDED_COUNT >= 5000);
    var previous: u16 = 0;
    for (0..ports.EMBEDDED_COUNT) |i| {
        const port = ports.portAt(i);
        try std.testing.expect(port > previous);
        previous = port;

        const s = ports.lookup(port) orelse return error.TestExpectedService;
        try std.testing.expect(s.name.len > 0 and s.name.len <= 20);
        if (s.category) |c| {
            for (categories) |known| {
                if (std.mem.eql(u8, c, known)) break;
            } else {
                std.debug.print("port {d} has undocumented category '{s}'\n", .{ port, c });
                return error.TestUnexpectedCategory;
            }
        }
    }
}
