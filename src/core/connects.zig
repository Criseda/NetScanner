//! Many TCP connects in flight at once, without a thread per connect.
//!
//! A scan used to give every probe a thread of its own for as long as
//! it waited, so a probe that got no answer tied up a thread for its
//! whole timeout, and throughput topped out at about threads / timeout.
//! Here a thread starts non-blocking connects for many targets and
//! waits on all of them at once (poll on Linux and macOS, select on
//! Windows): a silent target costs one socket for its timeout, not one
//! thread. A few such threads share a run (see MAX_LOOPS), keeping up
//! to MAX_IN_FLIGHT connects going between them, fewer when the target
//! slows down under the load (see Window).
//!
//! Needs no privileges. On Linux and macOS each connect in flight holds
//! a file descriptor, so the process raises its own soft open-file
//! limit as far as it needs (and its hard limit allows) before a run;
//! where that fails, fewer connects go in flight and scans still work.

const std = @import("std");
const builtin = @import("builtin");
const c_bindings = @import("bindings");

/// What one TCP connect attempt found.
pub const Outcome = enum {
    open, // Connected: the port is open.
    refused, // RST: the port is closed, but a host answered.
    filtered, // Timeout or unreachable: no answer at all.
};

/// One connect to make: where to, and how long to wait for an answer.
pub const Target = struct {
    ip: [4]u8,
    port: u16,
    timeout_ms: u32,
};

/// Most connects one run keeps in flight. Enough that a scan is bound
/// by the network's answers rather than by waiting on silent targets:
/// 1024 probes waiting 500 ms each still start about 2000 per second.
/// Windows bounds it by its ephemeral ports (about 16k), and select()
/// by TCP_PROBE_MAX_SOCKETS; Linux and macOS by the open-file limit
/// (see inFlightLimit).
pub const MAX_IN_FLIGHT = 1024;
/// Descriptors left for everything else while a run is going: stdio,
/// the status line, a DNS lookup, the ping processes' pipes.
const RESERVED_FDS = 64;

comptime {
    if (builtin.os.tag == .windows) std.debug.assert(MAX_IN_FLIGHT <= c_bindings.TCP_PROBE_MAX_SOCKETS);
}

const is_windows = builtin.os.tag == .windows;
/// A connect in flight: a Winsock SOCKET, or a file descriptor.
const Socket = if (is_windows) usize else std.posix.fd_t;
/// poll()'s per-socket record; Windows waits through select() instead.
const PollFd = if (is_windows) void else std.posix.pollfd;

/// How many connects a run may keep in flight here: MAX_IN_FLIGHT, or
/// fewer when the open-file limit cannot be raised that far. Raises
/// the process's soft limit toward MAX_IN_FLIGHT plus a reserve first
/// (never above the hard limit, and never lowers it). The default soft
/// limit is 1024 on Linux and 256 on macOS, while the hard limit is
/// typically far above both, so this normally succeeds.
pub fn inFlightLimit() usize {
    if (is_windows) return MAX_IN_FLIGHT;
    const wanted: std.posix.rlim_t = MAX_IN_FLIGHT + RESERVED_FDS;
    var limits = std.posix.getrlimit(.NOFILE) catch return MAX_IN_FLIGHT / 8;
    if (limits.cur != std.posix.RLIM.INFINITY and limits.cur < wanted) {
        var raised = limits;
        raised.cur = if (limits.max == std.posix.RLIM.INFINITY) wanted else @min(wanted, limits.max);
        if (std.posix.setrlimit(.NOFILE, raised)) {
            limits = raised;
        } else |_| {}
    }
    if (limits.cur == std.posix.RLIM.INFINITY or limits.cur >= wanted) return MAX_IN_FLIGHT;
    // Short of the reserve too: still scan, a few at a time.
    if (limits.cur <= 2 * RESERVED_FDS) return @max(1, limits.cur / 2);
    return @intCast(limits.cur - RESERVED_FDS);
}

/// Make every connect `source` hands out and report each result back
/// to it. Returns once `source` has no more and every connect has
/// settled. How many are in flight at once is up to a Window: it
/// starts at the old thread pool's pace (POOL_PACE), grows while
/// answers come back promptly, and backs off when they slow down, never
/// below where it started nor past inFlightLimit().
///
/// `source` is a pointer to anything with two methods:
/// - `next() ?Job`: the next connect, or null when there are no more
///   (including when the scan was asked to stop). Job is any struct
///   with a `target: Target` field; it comes back unchanged in `done`.
/// - `done(Job, Outcome, elapsed_us: u64)`: one connect's verdict, and
///   how long its answer took (for learning timeouts).
///
/// The connects are shared out over up to MAX_LOOPS threads (see
/// there), but calls into `source` are serialized, one at a time, so
/// it needs no locks of its own. Fails only when nothing at all could
/// be set up; nothing has been probed then.
pub fn run(comptime Job: type, allocator: std.mem.Allocator, io: std.Io, source: anytype, pace: Pace) !void {
    const limit = inFlightLimit();
    const loops = @min(loopCount(), limit);
    var shared: Shared(Job, @TypeOf(source)) = .{
        .source = source,
        .io = io,
        .loops = loops,
        // Every loop holds at least one connect.
        .window = .init(@max(loops, @min(POOL_PACE, limit)), limit, pace),
    };
    // Each loop can hold an even share of the largest window.
    const capacity = std.math.divCeil(usize, limit, loops) catch unreachable;

    var threads: [MAX_LOOPS]?std.Thread = @splat(null);
    defer for (threads) |t| if (t) |thread| thread.join();
    for (threads[1..loops]) |*t| {
        // A loop that cannot start costs only its share of the window:
        // the others still drain the source.
        t.* = std.Thread.spawn(.{}, loopDetached, .{ Job, allocator, io, &shared, capacity }) catch null;
    }
    try loop(Job, allocator, io, &shared, capacity);
}

/// How many connects the old thread pool kept in flight against one
/// host (one blocking connect per thread): the pace every host already
/// took from ns before this engine. An adaptive window never drops
/// below it. Below it, a slow host that answers in tens of milliseconds
/// under load (a camera recorder refusing some 3k ports a second) kept
/// tripping the delay signal, and the window settled under the old
/// pool, making those scans 15-20% slower than before.
pub const POOL_PACE: usize = if (builtin.os.tag == .macos) 128 else 256;

/// Most threads one run spreads its connects over. On a fast answer
/// (loopback, or a LAN host refusing closed ports) the cost is in the
/// system calls of each connect -- about 150 us apiece on Windows --
/// not in waiting, so one thread would top out near 7000 connects a
/// second; a few in parallel keep the old thread pool's pace there. On
/// silent targets they change nothing: those wait on the network.
const MAX_LOOPS = 8;

fn loopCount() usize {
    const cpus = std.Thread.getCpuCount() catch 1;
    return std.math.clamp(cpus / 2, 1, MAX_LOOPS);
}

/// Most connects a loop starts before it checks on the ones in flight.
/// Starting one costs real time (see MAX_LOOPS), and an answer that
/// arrives meanwhile is only seen afterwards, which would count against
/// its round trip; small batches keep that error to a millisecond or
/// two.
const START_BATCH = 16;

/// How a run decides how many connects to keep in flight.
pub const Pace = enum {
    /// Steered by the target's answers (see Window): for many connects
    /// to one host, which can be overloaded.
    adaptive,
    /// Always as many as inFlightLimit() allows: for one connect to
    /// each of many hosts, where no single host sees more than one
    /// probe, and answer times differ from host to host rather than
    /// with the pace (a phone in power save answers 200 ms late at any
    /// pace).
    fixed,
    /// Always the old thread pool's pace (POOL_PACE): for a last try
    /// at ports a host lost when it was asked faster.
    pool,
};

/// How many connects a run keeps in flight, steered by how fast the
/// target answers: TCP's congestion control in miniature, with delay as
/// the signal of overload.
///
/// A host that answers every probe (closed ports refused, or a busy
/// sweep) can be asked faster than it can reply. Its answers then queue
/// up: round trips grow from a few milliseconds to tens or hundreds,
/// and soon after it drops probes outright, open ports included -- a
/// home router does exactly this well before the old thread pool's
/// pace. So the window halves whenever an answer takes much longer than
/// the fastest one seen, at most once per round trip. Otherwise it
/// grows by one per settled connect, doubling every round. It starts,
/// and stays at least, at `min`, the old thread pool's pace (see
/// POOL_PACE): a host that copes with that is never asked to take
/// less. (Growing only one per round after a cut, as TCP does, left the
/// window small for the rest of a scan after a single slow answer.)
///
/// Silence alone never shrinks it: a host that drops closed ports
/// leaves most probes unanswered at any pace, and those only wait out
/// their timeout in parallel. Silence from a host that was answering
/// nearly everything is another matter (see DARK_NS). Plain data with
/// no locking; `run` guards it.
pub const Window = struct {
    size: usize,
    min: usize,
    max: usize,
    /// The fastest answer so far: the round trip with nothing queued.
    fastest_us: ?u64 = null,
    /// Until this time (ns), slower answers are the same slowdown the
    /// last cut already answered: no second cut, and no growth.
    hold_until_ns: i96 = 0,
    /// False: the window stays at `max` (Pace.fixed).
    adaptive: bool = true,
    /// Connects settled so far, and how many of those got an answer.
    settled: u64 = 0,
    answered: u64 = 0,
    /// When the last answer came (ns).
    last_answer_ns: i96 = 0,
    /// The host stopped answering altogether (see DARK_NS); the window
    /// stays put until it answers again.
    dark: bool = false,

    /// How much slower than the fastest answer an answer may be before
    /// it counts as queueing: twice the fastest, plus this much for
    /// ordinary jitter (Wi-Fi especially).
    pub const SLACK_US = 20 * std.time.us_per_ms;
    /// How long a host that answers most probes may answer none before
    /// the run counts it as gone dark. An iPhone on Wi-Fi answers some
    /// 75% of a full scan's probes (refusing closed ports), then, a few
    /// seconds into 10k probes a second, nothing at all for 5-11s: open
    /// ports included, both tries of every port in that stretch. Going
    /// on at full speed only kept it dark and lost those ports for
    /// good; the old thread pool's pace never set it off. So a dark
    /// host gets the window's minimum, that pace, back, and silence
    /// grows it no further until answers resume. A host that drops
    /// closed ports never answers most probes, so it never counts as
    /// dark, and neither does a sweep (Pace.fixed).
    pub const DARK_NS = 500 * std.time.ns_per_ms;

    pub fn init(min: usize, max: usize, pace: Pace) Window {
        std.debug.assert(min >= 1 and min <= max);
        return .{
            .size = if (pace == .fixed) max else min,
            .min = min,
            .max = if (pace == .pool) min else max,
            .adaptive = pace == .adaptive,
        };
    }

    /// One connect settled at `now_ns`, after `rtt_us`.
    pub fn observe(self: *Window, outcome: Outcome, rtt_us: u64, now_ns: i96) void {
        if (!self.adaptive) return;
        self.settled += 1;
        if (outcome != .filtered) {
            self.answered += 1;
            self.last_answer_ns = now_ns;
            self.dark = false;
            const fastest = @min(self.fastest_us orelse rtt_us, rtt_us);
            self.fastest_us = fastest;
            if (rtt_us > 2 * fastest + SLACK_US) {
                if (now_ns >= self.hold_until_ns) {
                    self.size = @max(self.min, self.size / 2);
                    self.hold_until_ns = now_ns + @as(i96, rtt_us) * std.time.ns_per_us;
                }
                return;
            }
        }
        if (outcome == .filtered and self.goneDark(now_ns)) return;
        if (now_ns < self.hold_until_ns) return;
        self.size = @min(self.max, self.size + 1);
    }

    /// Whether a host that answers most probes has stopped answering
    /// altogether; the first time, the window drops to its minimum.
    fn goneDark(self: *Window, now_ns: i96) bool {
        if (self.dark) return true;
        if (self.answered == 0 or 2 * self.answered < self.settled) return false;
        if (now_ns - self.last_answer_ns < DARK_NS) return false;
        self.dark = true;
        self.size = self.min;
        return true;
    }
};

/// A run's `source` and Window, shared by its loops: one call at a time.
fn Shared(comptime Job: type, comptime Source: type) type {
    return struct {
        source: Source,
        io: std.Io,
        loops: usize,
        window: Window,
        mutex: std.Io.Mutex = .init,

        const Take = union(enum) {
            job: Job,
            /// This loop holds its share of the window already.
            full,
            /// The source has no more.
            dry,
        };

        /// The next connect for a loop that has `in_flight` going.
        fn take(self: *@This(), in_flight: usize) Take {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (in_flight >= @max(1, self.window.size / self.loops)) return .full;
            return if (self.source.next()) |job| .{ .job = job } else .dry;
        }

        fn done(self: *@This(), job: Job, outcome: Outcome, elapsed_us: u64) void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            self.window.observe(outcome, elapsed_us, nowNs(self.io));
            self.source.done(job, outcome, elapsed_us);
        }
    };
}

fn loopDetached(comptime Job: type, allocator: std.mem.Allocator, io: std.Io, shared: anytype, capacity: usize) void {
    loop(Job, allocator, io, shared, capacity) catch {};
}

/// One thread's share of a run: keep its share of the window in flight
/// until the source runs dry and all of its connects have settled.
fn loop(comptime Job: type, allocator: std.mem.Allocator, io: std.Io, shared: anytype, capacity: usize) !void {
    var flight = try Flight(Job).init(allocator, capacity);
    defer flight.deinit(allocator);

    var dry = false;
    while (true) {
        // Top up, a batch at a time, while the window has room.
        var room_left = false;
        var batch: usize = 0;
        while (!dry and flight.len < flight.jobs.len) : (batch += 1) {
            if (batch == START_BATCH) {
                room_left = true;
                break;
            }
            const job: Job = switch (shared.take(flight.len)) {
                .job => |job| job,
                .full => break,
                .dry => {
                    dry = true;
                    break;
                },
            };
            const started = nowNs(io);
            switch (start(job.target)) {
                .done => |outcome| shared.done(job, outcome, elapsedUs(started, nowNs(io))),
                .pending => |sock| flight.add(job, sock, started),
            }
        }
        if (flight.len == 0) {
            if (dry) return;
            continue;
        }

        // Sleep until something settles or the earliest deadline, or
        // just look, when the batch stopped short of the window.
        const now = nowNs(io);
        const wait_ms = if (room_left) 0 else msUntil(now, flight.earliestDeadline());
        waitSettled(flight.socks[0..flight.len], flight.fds, wait_ms, flight.settled[0..flight.len]);

        // Report everything that settled or ran out of time. Walking
        // backwards keeps swap-removal from skipping a slot.
        const after = nowNs(io);
        var i = flight.len;
        while (i > 0) {
            i -= 1;
            const settled = flight.settled[i] != 0;
            if (!settled and after < flight.deadlines[i]) continue;
            const outcome = finish(flight.socks[i], settled);
            const job = flight.jobs[i];
            const elapsed = elapsedUs(flight.started[i], after);
            flight.remove(i);
            shared.done(job, outcome, elapsed);
        }
    }
}

/// The connects in flight, as parallel arrays, so the sockets can go
/// straight to poll/select. Removal swaps the last slot in.
fn Flight(comptime Job: type) type {
    return struct {
        jobs: []Job,
        socks: []Socket,
        started: []i96,
        deadlines: []i96,
        settled: []u8,
        fds: []PollFd,
        len: usize = 0,

        const Self = @This();

        fn init(allocator: std.mem.Allocator, capacity: usize) !Self {
            const jobs = try allocator.alloc(Job, capacity);
            errdefer allocator.free(jobs);
            const socks = try allocator.alloc(Socket, capacity);
            errdefer allocator.free(socks);
            const started = try allocator.alloc(i96, capacity);
            errdefer allocator.free(started);
            const deadlines = try allocator.alloc(i96, capacity);
            errdefer allocator.free(deadlines);
            const settled = try allocator.alloc(u8, capacity);
            errdefer allocator.free(settled);
            const fds = try allocator.alloc(PollFd, capacity);
            return .{ .jobs = jobs, .socks = socks, .started = started, .deadlines = deadlines, .settled = settled, .fds = fds };
        }

        fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.jobs);
            allocator.free(self.socks);
            allocator.free(self.started);
            allocator.free(self.deadlines);
            allocator.free(self.settled);
            allocator.free(self.fds);
        }

        fn add(self: *Self, job: Job, sock: Socket, started: i96) void {
            const i = self.len;
            self.jobs[i] = job;
            self.socks[i] = sock;
            self.started[i] = started;
            self.deadlines[i] = started + @as(i96, job.target.timeout_ms) * std.time.ns_per_ms;
            self.len += 1;
        }

        fn remove(self: *Self, i: usize) void {
            const last = self.len - 1;
            self.jobs[i] = self.jobs[last];
            self.socks[i] = self.socks[last];
            self.started[i] = self.started[last];
            self.deadlines[i] = self.deadlines[last];
            self.settled[i] = self.settled[last];
            self.len = last;
        }

        fn earliestDeadline(self: *const Self) i96 {
            var earliest = self.deadlines[0];
            for (self.deadlines[1..self.len]) |d| earliest = @min(earliest, d);
            return earliest;
        }
    };
}

/// Connect to one target and wait for its verdict, on this thread.
/// The single-connect form of `run`, for callers that need just one.
pub fn connectOnce(io: std.Io, target: Target) Outcome {
    const started = nowNs(io);
    const sock = switch (start(target)) {
        .done => |outcome| return outcome,
        .pending => |sock| sock,
    };
    const deadline = started + @as(i96, target.timeout_ms) * std.time.ns_per_ms;
    var settled = [1]u8{0};
    var fds: [1]PollFd = undefined;
    while (true) {
        const now = nowNs(io);
        if (now >= deadline) break;
        waitSettled(&.{sock}, &fds, msUntil(now, deadline), &settled);
        if (settled[0] != 0) break;
    }
    return finish(sock, settled[0] != 0);
}

const Started = union(enum) {
    /// Settled at once (loopback often refuses right away).
    done: Outcome,
    /// In flight: wait on it, then finish it.
    pending: Socket,
};

/// Begin a non-blocking connect.
fn start(target: Target) Started {
    if (comptime is_windows) {
        var sock: usize = undefined;
        return switch (c_bindings.tcpProbeStart(target.ip, target.port, @intCast(target.timeout_ms), &sock)) {
            .open => .{ .done = .open },
            .refused => .{ .done = .refused },
            .filtered => .{ .done = .filtered },
            .pending => .{ .pending = sock },
        };
    }

    // A blocking connect to a dead host stalls ~75s in SYN retransmits,
    // so the socket goes non-blocking before connecting.
    const fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
    if (fd < 0) return .{ .done = .filtered };

    const raw_flags = std.c.fcntl(fd, std.posix.F.GETFL, @as(c_int, 0));
    // O_NONBLOCK lives in a packed bit struct on macOS, so flip the bit
    // through an integer round-trip.
    var oflags: std.posix.O = @bitCast(@as(u32, @bitCast(raw_flags)));
    oflags.NONBLOCK = true;
    if (raw_flags < 0 or std.c.fcntl(fd, std.posix.F.SETFL, @as(u32, @bitCast(oflags))) < 0) {
        _ = std.c.close(fd);
        return .{ .done = .filtered };
    }

    var addr = std.posix.sockaddr.in{
        .port = std.mem.nativeToBig(u16, target.port),
        // @bitCast copies the bytes as-is, which is exactly the network
        // byte order sockaddr expects.
        .addr = @bitCast(target.ip),
    };
    const rc = std.c.connect(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
    const outcome: Outcome = if (rc == 0) .open else switch (std.c.errno(rc)) {
        // In progress. An interrupted connect carries on in the
        // background just the same.
        .INPROGRESS, .INTR => return .{ .pending = fd },
        else => |err| classify(@backingInt(err)),
    };
    _ = std.c.close(fd);
    return .{ .done = outcome };
}

/// Wait at most wait_ms for any of `socks` to settle, setting
/// settled[i] for each that did. A failed or interrupted wait (a signal
/// handler ran: Ctrl+C, or the status line's resize redraw) marks
/// nothing; the caller simply waits again with the time left. `fds` is
/// scratch space for poll(), one per socket (unused on Windows).
fn waitSettled(socks: []const Socket, fds: []PollFd, wait_ms: c_int, settled: []u8) void {
    if (comptime is_windows) {
        if (!c_bindings.tcpProbeWait(socks, wait_ms, settled)) @memset(settled[0..socks.len], 0);
        return;
    }
    // Rebuilt each time from the sockets in flight: cheap next to the
    // poll itself, and it keeps one list to swap-remove from.
    const watched = fds[0..socks.len];
    for (watched, socks) |*pfd, fd| pfd.* = .{ .fd = fd, .events = std.posix.POLL.OUT, .revents = 0 };
    const rc = std.c.poll(watched.ptr, @intCast(watched.len), wait_ms);
    for (watched, settled[0..socks.len]) |pfd, *s| s.* = @intFromBool(rc > 0 and pfd.revents != 0);
}

/// A pending connect's verdict, closing its socket. `settled` false
/// means its deadline came first: still in flight then is "no answer",
/// never "open", but a refusal that just landed still counts.
fn finish(sock: Socket, settled: bool) Outcome {
    if (comptime is_windows) {
        return switch (c_bindings.tcpProbeFinish(sock, settled)) {
            .open => .open,
            .refused => .refused,
            .filtered, .pending => .filtered,
        };
    }
    defer _ = std.c.close(sock);
    var so_error: c_int = 0;
    var opt_len: std.posix.socklen_t = @sizeOf(c_int);
    if (std.c.getsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.ERROR, @ptrCast(&so_error), &opt_len) != 0) {
        return .filtered;
    }
    if (!settled and so_error == 0) return .filtered;
    return classify(so_error);
}

/// POSIX: only an actively refused connection proves "closed but
/// present"; every other error (timeout, unreachable, ...) is silence.
fn classify(so_error: c_int) Outcome {
    return switch (so_error) {
        0 => .open,
        @backingInt(std.posix.E.CONNREFUSED), @backingInt(std.posix.E.CONNRESET) => .refused,
        else => .filtered,
    };
}

fn nowNs(io: std.Io) i96 {
    return std.Io.Clock.now(.awake, io).nanoseconds;
}

/// Milliseconds from `now` until `deadline`, rounded up so a wait never
/// wakes just short of it and spins; zero once it has passed.
fn msUntil(now: i96, deadline: i96) c_int {
    if (deadline <= now) return 0;
    const ms = @divFloor(deadline - now + std.time.ns_per_ms - 1, std.time.ns_per_ms);
    return @intCast(@min(ms, std.math.maxInt(c_int)));
}

fn elapsedUs(started: i96, finished: i96) u64 {
    return @intCast(@max(0, @divTrunc(finished - started, std.time.ns_per_us)));
}
