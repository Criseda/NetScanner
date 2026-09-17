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
    // makes the verdict deterministic within the connect timeout.
    const outcome = scanner.tcpConnect(.{ 127, 0, 0, 1 }, 9);
    try std.testing.expectEqual(scanner.ProbeOutcome.refused, outcome);
}

test "tcpConnect maps an unroutable host to filtered" {
    // TEST-NET-1 is never routed, so nothing out there can answer or
    // refuse; the connect must time out quickly instead of hanging.
    const outcome = scanner.tcpConnect(.{ 192, 0, 2, 1 }, 80);
    try std.testing.expectEqual(scanner.ProbeOutcome.filtered, outcome);
}
