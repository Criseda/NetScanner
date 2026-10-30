const std = @import("std");
const builtin = @import("builtin");
const connects = @import("core").connects;
const Window = connects.Window;

const ms = std.time.ns_per_ms;

// ---------------------------------------------------------------------------
// Window: how many connects stay in flight.
// ---------------------------------------------------------------------------

test "a fixed window stays at its maximum whatever it observes" {
    var w = Window.init(1, 1024, .fixed);
    try std.testing.expectEqual(@as(usize, 1024), w.size);
    w.observe(.refused, 1_000, 0);
    w.observe(.refused, 900_000, 1 * ms);
    w.observe(.filtered, 500_000, 2 * ms);
    try std.testing.expectEqual(@as(usize, 1024), w.size);
}

test "a pool-paced window stays at its minimum whatever it observes" {
    var w = Window.init(128, 1024, .pool);
    try std.testing.expectEqual(@as(usize, 128), w.size);
    w.observe(.refused, 1_000, 0);
    w.observe(.filtered, 500_000, 1 * ms);
    w.observe(.refused, 900_000, 2 * ms);
    try std.testing.expectEqual(@as(usize, 128), w.size);
}

test "an adaptive window starts at its minimum" {
    try std.testing.expectEqual(@as(usize, 128), Window.init(128, 1024, .adaptive).size);
    try std.testing.expectEqual(@as(usize, 16), Window.init(16, 16, .adaptive).size);
}

test "prompt answers and silence both grow the window, up to its maximum" {
    var w = Window.init(64, 64 + 3, .adaptive);
    w.observe(.refused, 1_000, 0);
    w.observe(.open, 1_200, 1 * ms);
    // Silence is no sign of overload: a host that drops closed ports
    // leaves most probes unanswered at any pace.
    w.observe(.filtered, 500_000, 2 * ms);
    try std.testing.expectEqual(@as(usize, 64 + 3), w.size);
    w.observe(.refused, 1_000, 3 * ms);
    try std.testing.expectEqual(@as(usize, 64 + 3), w.size);
}

test "a slow answer halves the window once per round trip" {
    var w = Window.init(1, 1024, .adaptive);
    w.observe(.refused, 1_000, 0); // fastest: 1 ms
    const before = w.size;

    // Far slower than the fastest answer: the host is queueing.
    const slow_us = 80_000;
    w.observe(.refused, slow_us, 10 * ms);
    try std.testing.expectEqual(before / 2, w.size);

    // Within that round trip, more slow answers are the same slowdown:
    // no second cut, and no growth either.
    w.observe(.refused, slow_us, 20 * ms);
    w.observe(.refused, 1_000, 30 * ms);
    try std.testing.expectEqual(before / 2, w.size);

    // Once it has passed, a prompt answer grows the window again...
    w.observe(.refused, 1_000, 10 * ms + slow_us * std.time.ns_per_us);
    try std.testing.expectEqual(before / 2 + 1, w.size);
    // ...and a slow one cuts it again.
    w.observe(.refused, slow_us, 200 * ms);
    try std.testing.expectEqual((before / 2 + 1) / 2, w.size);
}

test "a host that answered most probes and then none counts as dark" {
    var w = Window.init(64, 1024, .adaptive);
    var now: i96 = 0;
    for (0..500) |_| {
        now += 1 * ms;
        w.observe(.refused, 1_000, now);
    }
    try std.testing.expect(w.size > 64);

    // Silence, but not for long yet: still growing.
    const grown = w.size;
    w.observe(.filtered, 100_000, now + 100 * ms);
    try std.testing.expectEqual(grown + 1, w.size);

    // Nothing at all for DARK_NS: back to the starting pace, and
    // silence grows it no further...
    w.observe(.filtered, 100_000, now + Window.DARK_NS);
    try std.testing.expectEqual(@as(usize, 64), w.size);
    w.observe(.filtered, 100_000, now + 2 * Window.DARK_NS);
    try std.testing.expectEqual(@as(usize, 64), w.size);

    // ...until the host answers again.
    w.observe(.refused, 1_000, now + 3 * Window.DARK_NS);
    try std.testing.expectEqual(@as(usize, 64 + 1), w.size);
    w.observe(.filtered, 100_000, now + 3 * Window.DARK_NS + 1 * ms);
    try std.testing.expectEqual(@as(usize, 64 + 2), w.size);
}

test "a host that drops most probes never counts as dark" {
    var w = Window.init(1, 1024, .adaptive);
    var now: i96 = 0;
    w.observe(.open, 1_000, now);
    // One open port, then nothing but silence for a long time: a host
    // dropping closed ports, which may be probed at full pace.
    for (0..2000) |_| {
        now += 1 * ms;
        w.observe(.filtered, 100_000, now);
    }
    try std.testing.expectEqual(@as(usize, 1024), w.size);
}

test "jitter within the slack does not count as a slowdown" {
    var w = Window.init(1, 1024, .adaptive);
    w.observe(.refused, 2_000, 0);
    const before = w.size;
    w.observe(.refused, 2 * 2_000 + Window.SLACK_US, 1 * ms);
    try std.testing.expectEqual(before + 1, w.size);
}

test "the window never drops below its minimum" {
    var w = Window.init(8, 1024, .adaptive);
    w.observe(.refused, 1_000, 0);
    var now: i96 = 0;
    for (0..20) |_| {
        now += 1000 * ms;
        w.observe(.refused, 500_000, now);
    }
    try std.testing.expectEqual(@as(usize, 8), w.size);
}

// ---------------------------------------------------------------------------
// run: many connects, each verdict reported once.
// ---------------------------------------------------------------------------

/// Hands out `ports` on 127.0.0.1 and records each verdict.
const Recorder = struct {
    ports: []const u16,
    outcomes: []?connects.Outcome,
    index: usize = 0,
    reports: usize = 0,

    const Job = struct { target: connects.Target, slot: usize };

    pub fn next(self: *Recorder) ?Job {
        if (self.index >= self.ports.len) return null;
        defer self.index += 1;
        return .{
            .target = .{ .ip = .{ 127, 0, 0, 1 }, .port = self.ports[self.index], .timeout_ms = 2000 },
            .slot = self.index,
        };
    }

    pub fn done(self: *Recorder, job: Job, outcome: connects.Outcome, _: u64) void {
        std.debug.assert(self.outcomes[job.slot] == null);
        self.outcomes[job.slot] = outcome;
        self.reports += 1;
    }
};

test "run reports open and refused loopback ports, each exactly once" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const io = std.testing.io;

    var bound = bindLoopbackAbove(io, 48631, 20) orelse return error.SkipZigTest;
    defer bound.server.deinit(io);

    // The listener, then port 9 (discard: effectively never listening,
    // so loopback refuses it) many times over, so the run has to keep
    // more connects going than a single loop's first batch.
    var ports: [200]u16 = @splat(9);
    ports[0] = bound.port;
    var outcomes: [ports.len]?connects.Outcome = @splat(null);
    var recorder: Recorder = .{ .ports = &ports, .outcomes = &outcomes };

    for ([_]connects.Pace{ .adaptive, .fixed, .pool }) |pace| {
        recorder.index = 0;
        recorder.reports = 0;
        @memset(&outcomes, null);
        try connects.run(Recorder.Job, std.testing.allocator, io, &recorder, pace);
        try std.testing.expectEqual(ports.len, recorder.reports);
        try std.testing.expectEqual(@as(?connects.Outcome, .open), outcomes[0]);
        for (outcomes[1..]) |o| try std.testing.expectEqual(@as(?connects.Outcome, .refused), o);
    }
}

test "run never reports a loopback port open that nothing listens on" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    // A free port from the ephemeral range. Connecting to it over and
    // over, a connect sooner or later gets it as its own source port,
    // and on Linux completes with itself (#90). Linux hands connects
    // even source ports and bind(0) odd ones, so the port is the even
    // one next to what bind(0) picked: an odd port never self-connects.
    var picked = bindLoopbackAbove(io, 0, 0) orelse return error.SkipZigTest;
    const port = picked.server.socket.address.getPort() & ~@as(u16, 1);
    picked.server.deinit(io);
    var free = bindLoopbackAbove(io, port, 0) orelse return error.SkipZigTest;
    free.server.deinit(io);

    // 40k tries go through the range's ~14k even ports nearly three
    // times over, with room for the ports busy at the time. Before the
    // fix this failed in every run on Linux.
    const tries = 40_000;
    const ports = try allocator.alloc(u16, tries);
    defer allocator.free(ports);
    @memset(ports, port);
    const outcomes = try allocator.alloc(?connects.Outcome, tries);
    defer allocator.free(outcomes);
    @memset(outcomes, null);
    var recorder: Recorder = .{ .ports = ports, .outcomes = outcomes };

    try connects.run(Recorder.Job, allocator, io, &recorder, .fixed);
    try std.testing.expectEqual(ports.len, recorder.reports);
    for (outcomes) |o| try std.testing.expect(o.? != .open);
}

test "a crossed pair of loopback connects is not reported open" {
    // Winsock sockets are not file descriptors; tcp_probe.c gets the
    // same treatment, but is not driven from here.
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const io = std.testing.io;

    // Sockets bound to ports A and B, each connecting to the other's
    // port at once: their SYNs cross, and the OS completes both as one
    // simultaneous open, with nothing listening on either port. A scan
    // of the machine's own address makes such pairs by chance, when
    // two of its connects get each other's target as source port. On
    // macOS they form every time; where a SYN is answered before the
    // second connect starts (Linux), both are refused, and the test
    // has nothing to show.
    var a: u16 = 47_300;
    while (a < 47_380) : (a += 2) {
        const b = a + 1;
        const x = boundNonBlocking(a) orelse continue;
        const y = boundNonBlocking(b) orelse {
            _ = std.c.close(x);
            continue;
        };
        const started_x = connectLoopback(x, b);
        const started_y = connectLoopback(y, a);
        if (started_x and started_y) {
            for ([_]std.posix.fd_t{ x, y }) |fd| {
                var pfd = [1]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.OUT, .revents = 0 }};
                _ = std.c.poll(&pfd, 1, 1000);
            }
        }
        if (!started_x or !started_y or !isConnected(x) or !isConnected(y)) {
            _ = std.c.close(x);
            _ = std.c.close(y);
            // Refused, or a port still in TIME_WAIT from an earlier
            // run's pair: try the next two.
            continue;
        }
        const to_b = connects.settledVerdict(io, x, .{ .ip = .{ 127, 0, 0, 1 }, .port = b, .timeout_ms = 1000 });
        const to_a = connects.settledVerdict(io, y, .{ .ip = .{ 127, 0, 0, 1 }, .port = a, .timeout_ms = 1000 });
        try std.testing.expect(to_b != .open);
        try std.testing.expect(to_a != .open);
        return;
    }
    return error.SkipZigTest;
}

/// A non-blocking TCP socket bound to 127.0.0.1:port, or null when the
/// port is taken.
fn boundNonBlocking(port: u16) ?std.posix.fd_t {
    const fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
    if (fd < 0) return null;
    const raw_flags = std.c.fcntl(fd, std.posix.F.GETFL, @as(c_int, 0));
    var oflags: std.posix.O = @bitCast(@as(u32, @bitCast(raw_flags)));
    oflags.NONBLOCK = true;
    var addr = loopback(port);
    if (raw_flags < 0 or std.c.fcntl(fd, std.posix.F.SETFL, @as(u32, @bitCast(oflags))) < 0 or
        std.c.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))) != 0)
    {
        _ = std.c.close(fd);
        return null;
    }
    return fd;
}

/// Start a connect to 127.0.0.1:port. False if it failed at once.
fn connectLoopback(fd: std.posix.fd_t, port: u16) bool {
    var addr = loopback(port);
    const rc = std.c.connect(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
    return rc == 0 or std.c.errno(rc) == .INPROGRESS;
}

/// Whether a connect has completed. Reading SO_ERROR would clear the
/// error the verdict is made of, so this asks for the peer instead.
fn isConnected(fd: std.posix.fd_t) bool {
    var peer: std.posix.sockaddr.in = undefined;
    var len: std.posix.socklen_t = @sizeOf(@TypeOf(peer));
    return std.c.getpeername(fd, @ptrCast(&peer), &len) == 0;
}

fn loopback(port: u16) std.posix.sockaddr.in {
    return .{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast([4]u8{ 127, 0, 0, 1 }) };
}

test "run with nothing to do returns at once" {
    var outcomes: [0]?connects.Outcome = .{};
    var recorder: Recorder = .{ .ports = &.{}, .outcomes = &outcomes };
    try connects.run(Recorder.Job, std.testing.allocator, std.testing.io, &recorder, .adaptive);
    try std.testing.expectEqual(@as(usize, 0), recorder.reports);
}

/// Hands out one silent connect that may be cut short (TEST-NET-1,
/// never routed) and a loopback one that is refused at once, and
/// offers `cap_ms` as its waitCap once something has answered.
const Cutter = struct {
    cap_ms: ?u32,
    index: usize = 0,
    answered: bool = false,
    silent_elapsed_us: ?u64 = null,

    const Job = struct { target: connects.Target };
    const silent_timeout_ms = 3000;

    pub fn next(self: *Cutter) ?Job {
        defer self.index += 1;
        return switch (self.index) {
            0 => .{ .target = .{ .ip = .{ 192, 0, 2, 1 }, .port = 80, .timeout_ms = silent_timeout_ms, .cut_floor_ms = 100 } },
            // Port 9 (discard): loopback refuses it.
            1 => .{ .target = .{ .ip = .{ 127, 0, 0, 1 }, .port = 9, .timeout_ms = silent_timeout_ms } },
            else => null,
        };
    }

    pub fn done(self: *Cutter, job: Job, outcome: connects.Outcome, elapsed_us: u64) void {
        if (job.target.cut_floor_ms != null) {
            self.silent_elapsed_us = elapsed_us;
        } else if (outcome != .filtered) {
            self.answered = true;
        }
    }

    pub fn waitCap(self: *const Cutter) ?u32 {
        return if (self.answered) self.cap_ms else null;
    }

    /// How long the silent connect waited, in milliseconds. Skips when
    /// it failed at once: some networks refuse TEST-NET-1 outright
    /// instead of leaving it silent, and there is nothing to cut.
    fn silentMs(self: *Cutter) !u64 {
        if (builtin.single_threaded) return error.SkipZigTest;
        try connects.run(Job, std.testing.allocator, std.testing.io, self, .fixed);
        const elapsed_ms = self.silent_elapsed_us.? / std.time.us_per_ms;
        if (elapsed_ms < 100) return error.SkipZigTest;
        return elapsed_ms;
    }
};

test "run cuts a silent connect short once the source has a wait for it" {
    var cutter: Cutter = .{ .cap_ms = 200 };
    // Cut at 200 ms; far from its own 3s however slow the machine.
    try std.testing.expect(try cutter.silentMs() < Cutter.silent_timeout_ms / 2);
}

test "run lets a connect that may be cut wait in full while the source has no wait" {
    var cutter: Cutter = .{ .cap_ms = null };
    try std.testing.expect(try cutter.silentMs() >= Cutter.silent_timeout_ms - 100);
}

test "run waits for sockets instead of reporting unprobed ports as unanswered" {
    if (builtin.single_threaded or builtin.os.tag == .windows) return error.SkipZigTest;
    const io = std.testing.io;

    var bound = bindLoopbackAbove(io, 48631, 20) orelse return error.SkipZigTest;
    defer bound.server.deinit(io);
    var ports: [50]u16 = @splat(9);
    ports[ports.len - 1] = bound.port;
    var outcomes: [ports.len]?connects.Outcome = @splat(null);
    var recorder: Recorder = .{ .ports = &ports, .outcomes = &outcomes };

    // Every descriptor taken: socket() fails with EMFILE until the
    // fillers close, a while into the run.
    var fillers: Fillers = try .fill();
    defer fillers.restore();
    const release_ms = 100;
    const releaser = try std.Thread.spawn(.{}, Fillers.closeAfter, .{ &fillers, io, release_ms });
    defer releaser.join();

    const started = std.Io.Clock.now(.awake, io);
    try connects.run(Recorder.Job, std.testing.allocator, io, &recorder, .adaptive);
    const elapsed = started.durationTo(std.Io.Clock.now(.awake, io));

    // It did run short, and waited instead of calling the ports silent.
    try std.testing.expect(elapsed.nanoseconds >= (release_ms - 10) * ms);
    try std.testing.expectEqual(ports.len, recorder.reports);
    for (outcomes[0 .. ports.len - 1]) |o| try std.testing.expectEqual(@as(?connects.Outcome, .refused), o);
    try std.testing.expectEqual(@as(?connects.Outcome, .open), outcomes[ports.len - 1]);
}

test "run gives up with OutOfSockets when no socket comes, reporting nothing" {
    if (builtin.single_threaded or builtin.os.tag == .windows) return error.SkipZigTest;
    var ports: [20]u16 = @splat(9);
    var outcomes: [ports.len]?connects.Outcome = @splat(null);
    var recorder: Recorder = .{ .ports = &ports, .outcomes = &outcomes };

    var fillers: Fillers = try .fill();
    defer fillers.restore();
    try std.testing.expectError(
        error.OutOfSockets,
        connects.run(Recorder.Job, std.testing.allocator, std.testing.io, &recorder, .adaptive),
    );
    try std.testing.expectEqual(@as(usize, 0), recorder.reports);
}

test "a target no connect can reach is unanswered, without waiting" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const io = std.testing.io;

    var bound = bindLoopbackAbove(io, 48631, 20) orelse return error.SkipZigTest;
    defer bound.server.deinit(io);
    // A connect to port 0 fails with EADDRNOTAVAIL on macOS and
    // Windows, as one does when the ephemeral ports are used up. The
    // ports after it start fine, so it is the target's own doing; alone,
    // there is nothing to tell, and it counts as unanswered as before.
    var many: [20]u16 = @splat(9);
    many[0] = 0;
    many[many.len - 1] = bound.port;
    for ([_][]const u16{ &many, &.{0} }) |ports| {
        var outcomes: [many.len]?connects.Outcome = @splat(null);
        var recorder: Recorder = .{ .ports = ports, .outcomes = outcomes[0..ports.len] };
        const started = std.Io.Clock.now(.awake, io);
        try connects.run(Recorder.Job, std.testing.allocator, io, &recorder, .adaptive);
        const elapsed = started.durationTo(std.Io.Clock.now(.awake, io));

        try std.testing.expect(elapsed.nanoseconds < 1000 * ms);
        try std.testing.expectEqual(ports.len, recorder.reports);
        try std.testing.expect(outcomes[0].? != .open);
        if (ports.len == 1) continue;
        for (outcomes[1 .. ports.len - 1]) |o| try std.testing.expectEqual(@as(?connects.Outcome, .refused), o);
        try std.testing.expectEqual(@as(?connects.Outcome, .open), outcomes[ports.len - 1]);
    }
}

test "inFlightLimit allows at least one connect and at most MAX_IN_FLIGHT" {
    const limit = connects.inFlightLimit();
    try std.testing.expect(limit >= 1 and limit <= connects.MAX_IN_FLIGHT);
}

/// Every free descriptor in the process, held by copies of one pipe end,
/// so socket() fails with EMFILE: running out of sockets, without root.
/// The soft open-file limit is set first to what connects.run would
/// raise it to (at most 2048 descriptors to fill), so run leaves it be.
/// POSIX only.
const Fillers = struct {
    pipe: [2]std.posix.fd_t,
    fds: [4096]std.posix.fd_t = undefined,
    len: usize = 0,
    saved: std.posix.rlimit,

    fn fill() !Fillers {
        const saved = try std.posix.getrlimit(.NOFILE);
        _ = connects.inFlightLimit();
        var limits = try std.posix.getrlimit(.NOFILE);
        if (limits.cur == std.posix.RLIM.INFINITY or limits.cur > 2048) limits.cur = 2048;
        try std.posix.setrlimit(.NOFILE, limits);

        var self: Fillers = .{ .pipe = undefined, .saved = saved };
        if (std.c.pipe(&self.pipe) != 0) return error.SkipZigTest;
        while (self.len < self.fds.len) {
            const fd = std.c.dup(self.pipe[0]);
            if (fd < 0) break;
            self.fds[self.len] = fd;
            self.len += 1;
        }
        // Make sure the table really is full.
        const probe = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
        if (probe >= 0) {
            _ = std.c.close(probe);
            self.restore();
            return error.SkipZigTest;
        }
        return self;
    }

    fn close(self: *Fillers) void {
        for (self.fds[0..self.len]) |fd| _ = std.c.close(fd);
        self.len = 0;
    }

    fn closeAfter(self: *Fillers, io: std.Io, delay_ms: i64) void {
        io.sleep(.fromMilliseconds(delay_ms), .awake) catch {};
        self.close();
    }

    fn restore(self: *Fillers) void {
        self.close();
        for (self.pipe) |fd| _ = std.c.close(fd);
        std.posix.setrlimit(.NOFILE, self.saved) catch {};
    }
};

/// Bind 127.0.0.1 on the first free port at or above `from`.
/// Returns null when nothing nearby is free, so callers can skip
/// instead of failing on a crowded test machine.
fn bindLoopbackAbove(io: std.Io, from: u16, span: u16) ?struct { server: std.Io.net.Server, port: u16 } {
    var port: u32 = from;
    const end: u32 = @min(@as(u32, from) + span, 65535);
    while (port <= end) : (port += 1) {
        var addr = std.Io.net.IpAddress.parseIp4("127.0.0.1", @intCast(port)) catch continue;
        if (addr.listen(io, .{})) |server| {
            return .{ .server = server, .port = @intCast(port) };
        } else |_| {}
    }
    return null;
}
