const std = @import("std");
const RttEstimator = @import("core").rtt.RttEstimator;

// The estimator is pure arithmetic, so these feed it round trips by
// hand instead of timing real connects (which would flake).

test "RttEstimator waits the ceiling until the first answer" {
    const estimator: RttEstimator = .init(100, 500);
    try std.testing.expectEqual(@as(u32, 500), estimator.timeoutMs());
}

test "RttEstimator drops to the floor after a fast LAN answer" {
    var estimator: RttEstimator = .init(100, 500);
    // 1ms: srtt 1ms + 4 * rttvar 0.5ms = 3ms, well under the floor.
    estimator.observe(1000);
    try std.testing.expectEqual(@as(u32, 100), estimator.timeoutMs());
}

test "RttEstimator never waits longer than the ceiling" {
    var estimator: RttEstimator = .init(100, 500);
    // 200ms: srtt 200ms + 4 * rttvar 100ms = 600ms.
    estimator.observe(200_000);
    try std.testing.expectEqual(@as(u32, 500), estimator.timeoutMs());
}

test "RttEstimator follows RFC 6298 between the clamps" {
    var estimator: RttEstimator = .init(0, 10_000);
    estimator.observe(10_000);
    // Second sample, 20ms: rttvar = (3 * 5ms + |10ms - 20ms|) / 4 =
    // 6.25ms, then srtt = (7 * 10ms + 20ms) / 8 = 11.25ms. The timeout
    // is 11.25 + 4 * 6.25 = 36.25ms, rounded up.
    estimator.observe(20_000);
    try std.testing.expectEqual(@as(?u64, 11_250), estimator.srtt_us);
    try std.testing.expectEqual(@as(u64, 6_250), estimator.rttvar_us);
    try std.testing.expectEqual(@as(u32, 37), estimator.timeoutMs());
}

test "RttEstimator rounds a sub-millisecond wait up, never down to zero" {
    var estimator: RttEstimator = .init(0, 500);
    estimator.observe(1);
    try std.testing.expectEqual(@as(u32, 1), estimator.timeoutMs());
}

test "RttEstimator grows again when the host slows down" {
    var estimator: RttEstimator = .init(100, 500);
    for (0..50) |_| estimator.observe(1000);
    try std.testing.expectEqual(@as(u32, 100), estimator.timeoutMs());
    // A VPN-like 150ms round trip: the variation alone lifts the wait
    // past the floor on the first slow answer, before the average has
    // caught up.
    estimator.observe(150_000);
    try std.testing.expect(estimator.timeoutMs() > 150);
    for (0..50) |_| estimator.observe(150_000);
    try std.testing.expect(estimator.timeoutMs() >= 150);
}
