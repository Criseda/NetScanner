const std = @import("std");
const RttEstimator = @import("core").rtt.RttEstimator;

// The estimator is pure arithmetic, so these feed it round trips by
// hand instead of timing real connects (which would flake).

test "RttEstimator waits the ceiling until the first answer" {
    const estimator: RttEstimator = .init(100, 0, 500);
    try std.testing.expectEqual(@as(u32, 500), estimator.timeoutMs());
}

test "RttEstimator drops to the floor after a fast LAN answer" {
    var estimator: RttEstimator = .init(100, 0, 500);
    // 1ms: srtt 1ms + 4 * rttvar 0.5ms = 3ms, well under the floor.
    estimator.observe(1000);
    try std.testing.expectEqual(@as(u32, 100), estimator.timeoutMs());
}

test "RttEstimator never waits longer than the ceiling" {
    var estimator: RttEstimator = .init(100, 0, 500);
    // 200ms: srtt 200ms + 4 * rttvar 100ms = 600ms.
    estimator.observe(200_000);
    try std.testing.expectEqual(@as(u32, 500), estimator.timeoutMs());
}

test "RttEstimator follows RFC 6298 between the clamps" {
    var estimator: RttEstimator = .init(0, 0, 10_000);
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
    var estimator: RttEstimator = .init(0, 0, 500);
    estimator.observe(1);
    try std.testing.expectEqual(@as(u32, 1), estimator.timeoutMs());
}

test "RttEstimator grows again when the host slows down" {
    var estimator: RttEstimator = .init(100, 0, 500);
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

test "RttEstimator keeps its headroom above a steady slow link" {
    // A distant host whose refusals all take about 180ms: rttvar
    // shrinks toward zero, and without headroom the wait would settle
    // a millisecond or two above srtt, inside the spread of answers.
    var bare: RttEstimator = .init(100, 0, 500);
    var padded: RttEstimator = .init(100, 40, 500);
    for (0..200) |_| {
        bare.observe(180_000);
        padded.observe(180_000);
    }
    try std.testing.expect(bare.timeoutMs() < 185);
    try std.testing.expectEqual(@as(u32, 220), padded.timeoutMs());
}

test "RttEstimator headroom gives way to a larger variation" {
    var estimator: RttEstimator = .init(0, 1, 10_000);
    estimator.observe(10_000);
    estimator.observe(20_000);
    // As in the RFC 6298 test above: 4 * rttvar is 25ms, more than
    // the 1ms of headroom, so the wait is unchanged at 36.25ms.
    try std.testing.expectEqual(@as(u32, 37), estimator.timeoutMs());
}

test "RttEstimator headroom leaves a LAN wait at the floor" {
    var estimator: RttEstimator = .init(100, 40, 500);
    for (0..50) |_| estimator.observe(1000);
    try std.testing.expectEqual(@as(u32, 100), estimator.timeoutMs());
}
