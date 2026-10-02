const std = @import("std");
const core = @import("core");
const live = core.live;
const ProgressMeter = core.progress.ProgressMeter;

// The status line itself draws on a terminal through std.Progress, which
// tests cannot see. These cover what the line says and which glyphs it
// is drawn with.

const hosts: live.Live.Noun = .{ .one = "host found", .many = "hosts found" };

fn status(buf: []u8, g: live.Glyphs, frame: usize, phase: live.Live.Phase, found: usize) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try live.writeStatus(&w, g, frame, phase, found, hosts);
    return w.buffered();
}

test "status line shows percentage and found count" {
    var meter: ProgressMeter = .{ .phase = "sweep", .total = 254 };
    for (0..107) |_| _ = meter.advance();
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "⠹ Scanning 192.168.68.0/24… 42% · 7 hosts found",
        try status(&buf, .unicode, 2, .{ .label = "Scanning 192.168.68.0/24", .meter = &meter }, 7),
    );
}

test "status line falls back to ASCII glyphs" {
    var meter: ProgressMeter = .{ .phase = "sweep", .total = 254 };
    for (0..107) |_| _ = meter.advance();
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "| Scanning 192.168.68.0/24... 42% - 7 hosts found",
        try status(&buf, .ascii, 0, .{ .label = "Scanning 192.168.68.0/24", .meter = &meter }, 7),
    );
}

test "status line counts small phases as N of M" {
    var meter: ProgressMeter = .{ .phase = "identify", .total = 9 };
    for (0..3) |_| _ = meter.advance();
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "⠼ Identifying devices… 3 of 9",
        try status(&buf, .unicode, 4, .{ .label = "Identifying devices", .meter = &meter, .style = .count }, 5),
    );
}

test "status line without a meter shows only the found count, singular" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "⠋ Checking ARP table… 1 host found",
        try status(&buf, .unicode, 0, .{ .label = "Checking ARP table" }, 1),
    );
}

test "spinner frames cycle" {
    var buf: [128]u8 = undefined;
    const phase: live.Live.Phase = .{ .label = "x" };
    const frames = live.Glyphs.unicode.spinner.len;
    try std.testing.expectEqualStrings(
        try status(buf[0..64], .unicode, 1, phase, 0),
        try status(buf[64..], .unicode, 1 + frames, phase, 0),
    );
}

test "localeIsUtf8 follows LC_ALL, then LC_CTYPE, then LANG" {
    try std.testing.expect(live.localeIsUtf8(null, null, "en_GB.UTF-8"));
    try std.testing.expect(live.localeIsUtf8(null, null, "en_US.utf8"));
    try std.testing.expect(live.localeIsUtf8(null, null, "de_DE.UTF-8@euro"));
    // The first one set wins, even when it is not UTF-8.
    try std.testing.expect(!live.localeIsUtf8("C", null, "en_GB.UTF-8"));
    try std.testing.expect(!live.localeIsUtf8(null, "en_GB.ISO8859-1", "en_GB.UTF-8"));
    try std.testing.expect(live.localeIsUtf8(null, "en_GB.UTF-8", "C"));
    // Empty counts as unset.
    try std.testing.expect(live.localeIsUtf8("", "", "en_GB.UTF-8"));
    try std.testing.expect(!live.localeIsUtf8(null, null, null));
    try std.testing.expect(!live.localeIsUtf8(null, null, "POSIX"));
}

test "isDumbTerminal is true only for TERM=dumb" {
    try std.testing.expect(live.isDumbTerminal("dumb"));
    try std.testing.expect(!live.isDumbTerminal("xterm-256color"));
    try std.testing.expect(!live.isDumbTerminal("screen"));
    // Windows consoles set no TERM at all; they draw the line.
    try std.testing.expect(!live.isDumbTerminal(null));
    try std.testing.expect(!live.isDumbTerminal(""));
}

test "truncateUtf8 never splits a character" {
    const line = "⠹ ab…"; // 3 + 1 + 2 + 3 bytes
    try std.testing.expectEqualStrings(line, live.truncateUtf8(line, 100));
    try std.testing.expectEqualStrings(line, live.truncateUtf8(line, line.len));
    // Cutting inside `…` drops the whole character.
    try std.testing.expectEqualStrings("⠹ ab", live.truncateUtf8(line, line.len - 1));
    try std.testing.expectEqualStrings("⠹ ab", live.truncateUtf8(line, 7));
    // Cutting inside the spinner leaves nothing rather than a fragment.
    try std.testing.expectEqualStrings("", live.truncateUtf8(line, 2));
    try std.testing.expectEqualStrings("⠹", live.truncateUtf8(line, 3));
}

test "ProgressMeter percent stays within 0-100" {
    var meter: ProgressMeter = .{ .phase = "ports", .total = 3 };
    try std.testing.expectEqual(@as(usize, 0), meter.percent());
    for (0..5) |_| _ = meter.advance();
    try std.testing.expectEqual(@as(usize, 100), meter.percent());
    try std.testing.expectEqual(@as(usize, 3), meter.completed());
}
