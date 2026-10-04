const std = @import("std");
const core = @import("core");
const live = core.live;

// The status line itself draws on a terminal through std.Progress, which
// tests cannot see. These cover what the line says and which glyphs it
// is drawn with.

const hosts: live.Live.Noun = .{ .one = "host found", .many = "hosts found" };
const target = "Scanning 192.168.68.0/24";

fn status(buf: []u8, g: live.Glyphs, frame: usize, progress: core.progress.Snapshot) ![]const u8 {
    return statusOf(buf, g, frame, .{ .label = target, .noun = hosts, .progress = progress });
}

fn statusOf(buf: []u8, g: live.Glyphs, frame: usize, s: live.Status) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try live.writeStatus(&w, g, frame, s);
    return w.buffered();
}

test "status line shows percentage and found count" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "⠹ Scanning 192.168.68.0/24… 42% · 7 hosts found",
        try status(&buf, .unicode, 2, .{ .phase = .sweep, .done = 107, .total = 254, .found = 7 }),
    );
}

test "status line falls back to ASCII glyphs" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "| Scanning 192.168.68.0/24... 42% - 7 hosts found",
        try status(&buf, .ascii, 0, .{ .phase = .sweep, .done = 107, .total = 254, .found = 7 }),
    );
}

test "status line counts name lookups as N of M" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "⠼ Identifying devices… 3 of 9",
        try status(&buf, .unicode, 4, .{ .phase = .identify, .done = 3, .total = 9, .found = 9 }),
    );
}

test "status line names the ARP check, with a percentage once it has a size" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "⠋ Checking ARP table… 1 host found",
        try status(&buf, .unicode, 0, .{ .phase = .arp, .found = 1 }),
    );
    try std.testing.expectEqualStrings(
        "⠋ Checking ARP table… 75% · 9 hosts found",
        try status(&buf, .unicode, 0, .{ .phase = .arp, .done = 3, .total = 4, .found = 9 }),
    );
}

test "status line before the first phase reads as the scan starting" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "⠋ Scanning 192.168.68.0/24… 0 hosts found",
        try status(&buf, .unicode, 0, .{}),
    );
}

test "status line says when Ctrl+C is finishing probes" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "⠋ Stopping… finishing probes in flight (Ctrl+C again to quit now)",
        try statusOf(&buf, .unicode, 0, .{
            .label = target,
            .noun = hosts,
            .progress = .{ .phase = .sweep, .done = 10, .total = 254 },
            .stopping = true,
        }),
    );
}

test "spinner frames cycle" {
    var buf: [128]u8 = undefined;
    const frames = live.Glyphs.unicode.spinner.len;
    try std.testing.expectEqualStrings(
        try status(buf[0..64], .unicode, 1, .{}),
        try status(buf[64..], .unicode, 1 + frames, .{}),
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
