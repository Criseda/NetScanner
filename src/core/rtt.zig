//! Connect timeouts learned from the round trips a scan actually sees.
//!
//! A fixed timeout has to fit the slowest network ns might meet, so on
//! a LAN, where answers come back in a millisecond or two, almost all
//! of it is spent idle on probes that will never be answered. Instead,
//! the estimator below watches how long answered probes took and
//! settles on a wait a little above that: TCP's own retransmission
//! timer (RFC 6298), clamped between a floor and the old fixed value.

const std = @import("std");

/// Smoothed round-trip time and its variation, in microseconds (LAN
/// round trips are well under a millisecond, so milliseconds would
/// round most of them to zero). Plain data with no locking: callers
/// that share one across threads guard it themselves.
pub const RttEstimator = struct {
    /// The timeout never drops below this. It covers what a single
    /// round trip cannot show: a Wi-Fi device waking from power save,
    /// or a host that briefly answers slower than it did a moment ago.
    floor_ms: u32,
    /// The least the timeout waits beyond srtt: the 4 * rttvar term
    /// never counts for less. On a steady link rttvar shrinks to a
    /// millisecond or two, which leaves a wait right at the bulk of the
    /// answers, so the slower few miss it, and, unanswered, never teach
    /// the estimator to wait longer. Linux bounds its retransmission
    /// timer from below the same way (tcp_rto_min). The floor already
    /// covers this while srtt is far below it; this matters only once
    /// srtt nears the floor.
    headroom_ms: u32,
    /// The timeout never rises above this, and stays here until the
    /// first answer arrives, so a scan is never slower to give up than
    /// it was with a fixed timeout.
    ceiling_ms: u32,
    /// Null until the first answer.
    srtt_us: ?u64 = null,
    rttvar_us: u64 = 0,

    pub fn init(floor_ms: u32, headroom_ms: u32, ceiling_ms: u32) RttEstimator {
        std.debug.assert(floor_ms <= ceiling_ms);
        return .{ .floor_ms = floor_ms, .headroom_ms = headroom_ms, .ceiling_ms = ceiling_ms };
    }

    /// Learn from one answered probe that took `rtt_us`. Unanswered
    /// probes teach nothing: their wait is the timeout itself.
    pub fn observe(self: *RttEstimator, rtt_us: u64) void {
        const srtt = self.srtt_us orelse {
            // RFC 6298 (2.2): the first sample seeds both values.
            self.srtt_us = rtt_us;
            self.rttvar_us = rtt_us / 2;
            return;
        };
        // RFC 6298 (2.3), with its alpha = 1/8 and beta = 1/4: the
        // variation moves first, against the old smoothed value.
        const deviation = if (srtt > rtt_us) srtt - rtt_us else rtt_us - srtt;
        self.rttvar_us = (3 * self.rttvar_us + deviation) / 4;
        self.srtt_us = (7 * srtt + rtt_us) / 8;
    }

    /// How long the next probe should wait: srtt + max(4 * rttvar,
    /// headroom_ms), rounded up to whole milliseconds and clamped to
    /// [floor_ms, ceiling_ms].
    pub fn timeoutMs(self: RttEstimator) u32 {
        const srtt = self.srtt_us orelse return self.ceiling_ms;
        const headroom_us = @max(4 * self.rttvar_us, @as(u64, self.headroom_ms) * std.time.us_per_ms);
        const wait_ms = std.math.divCeil(u64, srtt + headroom_us, std.time.us_per_ms) catch unreachable;
        return @intCast(std.math.clamp(wait_ms, self.floor_ms, self.ceiling_ms));
    }
};
