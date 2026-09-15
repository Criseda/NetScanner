const std = @import("std");
const scanner = @import("core").scanner;
const utils = @import("core").utils;

// This is a simple test to ensure the scanner module can be imported
test "scanner module imports correctly" {
    _ = scanner;
}

test "tcpConnect maps a closed loopback port to refused" {
    // Port 9 (discard) is effectively never listening, so loopback
    // must answer with RST. Loopback can never genuinely filter, which
    // makes this deterministic without any timeout involved.
    const outcome = scanner.tcpConnect(std.testing.io, .{ 127, 0, 0, 1 }, 9);
    try std.testing.expectEqual(scanner.ProbeOutcome.refused, outcome);
}
