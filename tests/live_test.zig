const std = @import("std");
const core = @import("core");
const live = core.live;
const ProgressMeter = core.progress.ProgressMeter;

// The status line itself draws on a terminal through std.Progress, which
// tests cannot see. These cover what the line says.

const hosts: live.Live.Noun = .{ .one = "host found", .many = "hosts found" };

fn status(buf: []u8, phase: live.Live.Phase, found: usize) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try live.writeStatus(&w, '|', phase, found, hosts);
    return w.buffered();
}

test "status line shows found count and percentage" {
    var meter: ProgressMeter = .{ .phase = "sweep", .total = 254 };
    for (0..127) |_| _ = meter.advance();
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "| Scanning 192.168.1.0/24 (7 hosts found, 50%)",
        try status(&buf, .{ .label = "Scanning 192.168.1.0/24", .meter = &meter }, 7),
    );
}

test "status line uses the singular noun for one result" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "| Checking ARP table (1 host found)",
        try status(&buf, .{ .label = "Checking ARP table" }, 1),
    );
}

test "status line counts small phases as N of M" {
    var meter: ProgressMeter = .{ .phase = "identify", .total = 9 };
    for (0..3) |_| _ = meter.advance();
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "| Identifying devices (3 of 9)",
        try status(&buf, .{ .label = "Identifying devices", .meter = &meter, .style = .count }, 5),
    );
}

test "ProgressMeter percent stays within 0-100" {
    var meter: ProgressMeter = .{ .phase = "ports", .total = 3 };
    try std.testing.expectEqual(@as(usize, 0), meter.percent());
    for (0..5) |_| _ = meter.advance();
    try std.testing.expectEqual(@as(usize, 100), meter.percent());
    try std.testing.expectEqual(@as(usize, 3), meter.completed());
}
