const std = @import("std");
const oui = @import("core").oui;

test "embedded OUI lookup for known devices" {
    // Synology
    const syno = oui.lookupEmbeddedVendor([6]u8{ 0x00, 0x11, 0x32, 0x12, 0x34, 0x56 });
    try std.testing.expect(syno != null);
    try std.testing.expectEqualStrings("Synology Incorporated", syno.?);

    // Raspberry Pi
    const pi = oui.lookupEmbeddedVendor([6]u8{ 0x2c, 0xcf, 0x67, 0x89, 0xab, 0xcd });
    try std.testing.expect(pi != null);
    try std.testing.expectEqualStrings("Raspberry Pi (Trading) Ltd", pi.?);

    // Sagemcom (Virgin Media router)
    const router = oui.lookupEmbeddedVendor([6]u8{ 0x64, 0xfa, 0x2b, 0x00, 0x11, 0x22 });
    try std.testing.expect(router != null);
    try std.testing.expectEqualStrings("Sagemcom Broadband SAS", router.?);

    // Unknown MAC (locally administered / unassigned)
    const unknown = oui.lookupEmbeddedVendor([6]u8{ 0x02, 0x00, 0x00, 0x11, 0x22, 0x33 });
    try std.testing.expectEqual(@as(?[]const u8, null), unknown);
}

test "OuiDatabase lookup with fallback to embedded" {
    var db = oui.OuiDatabase.init(std.testing.allocator);
    defer db.deinit();

    const syno = db.lookup([6]u8{ 0x00, 0x11, 0x32, 0x99, 0x88, 0x77 });
    try std.testing.expect(syno != null);
    try std.testing.expectEqualStrings("Synology Incorporated", syno.?);
}

test "OuiDatabase loadFile parses colon and dash delimiters and allows reload" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const sample_content =
        \\# Sample Wireshark manuf database
        \\00:11:22   TestCorp      Test Corporation Inc.
        \\33-44-55   DashCorp      Dash Separator Ltd
        \\0:1:2      ShortHex      Short Hex Corp
    ;
    try tmp_dir.dir.writeFile(std.testing.io, .{ .sub_path = "custom_manuf.txt", .data = sample_content });

    const abs_path = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}/custom_manuf.txt", .{tmp_dir.sub_path});
    defer std.testing.allocator.free(abs_path);

    var db = oui.OuiDatabase.init(std.testing.allocator);
    defer db.deinit();

    // First load
    try db.loadFile(abs_path);

    const test_corp = db.lookup([6]u8{ 0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc });
    try std.testing.expect(test_corp != null);
    try std.testing.expectEqualStrings("Test Corporation Inc.", test_corp.?);

    const dash_corp = db.lookup([6]u8{ 0x33, 0x44, 0x55, 0x01, 0x02, 0x03 });
    try std.testing.expect(dash_corp != null);
    try std.testing.expectEqualStrings("Dash Separator Ltd", dash_corp.?);

    const short_hex = db.lookup([6]u8{ 0x00, 0x01, 0x02, 0x10, 0x20, 0x30 });
    try std.testing.expect(short_hex != null);
    try std.testing.expectEqualStrings("Short Hex Corp", short_hex.?);

    // Second load (reload must not leak memory)
    try db.loadFile(abs_path);
    const test_corp_2 = db.lookup([6]u8{ 0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc });
    try std.testing.expect(test_corp_2 != null);
    try std.testing.expectEqualStrings("Test Corporation Inc.", test_corp_2.?);
}

test "parseManufLine parses standard and variant formats" {
    // Comment line
    try std.testing.expectEqual(@as(?oui.OuiEntry, null), oui.parseManufLine("# Comment line"));
    try std.testing.expectEqual(@as(?oui.OuiEntry, null), oui.parseManufLine("   "));

    // Two-column line (short name is used as vendor)
    const two_col = oui.parseManufLine("00:11:22   TestCorp");
    try std.testing.expect(two_col != null);
    try std.testing.expectEqual([3]u8{ 0x00, 0x11, 0x22 }, two_col.?.prefix);
    try std.testing.expectEqualStrings("TestCorp", two_col.?.vendor);

    // Three-column line (full description is used as vendor)
    const three_col = oui.parseManufLine("00:11:22   TestCorp   Test Corporation Inc.");
    try std.testing.expect(three_col != null);
    try std.testing.expectEqual([3]u8{ 0x00, 0x11, 0x22 }, three_col.?.prefix);
    try std.testing.expectEqualStrings("Test Corporation Inc.", three_col.?.vendor);

    // Hyphen delimiter and single-digit hex octets
    const hyphen = oui.parseManufLine("0-1-2   ShortHex   Short Hex Ltd");
    try std.testing.expect(hyphen != null);
    try std.testing.expectEqual([3]u8{ 0x00, 0x01, 0x02 }, hyphen.?.prefix);
    try std.testing.expectEqualStrings("Short Hex Ltd", hyphen.?.vendor);

    // Invalid hex rejected
    try std.testing.expectEqual(@as(?oui.OuiEntry, null), oui.parseManufLine("ZZ:11:22 BadCorp"));
}
