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
/// it needs no locks of its own.
///
/// A connect this machine cannot start (no socket, no local port to
/// send from) waits and is tried again (see Held): it is never reported
/// as unanswered, since it never asked the target anything. Fails when
/// nothing at all could be set up, or with error.OutOfSockets when a
/// connect could not start for STALL_LIMIT_NS; `done` is never called
/// for the connects that did not start.
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

    {
        var threads: [MAX_LOOPS]?std.Thread = @splat(null);
        defer for (threads) |t| if (t) |thread| thread.join();
        for (threads[1..loops]) |*t| {
            // A loop that cannot start costs only its share of the
            // window: the others still drain the source.
            t.* = std.Thread.spawn(.{}, loopDetached, .{ Job, allocator, io, &shared, capacity }) catch null;
        }
        try loop(Job, allocator, io, &shared, capacity);
    }
    if (shared.starved.load(.monotonic)) return error.OutOfSockets;
}

/// How long a loop goes on retrying a connect it cannot start (see
/// Held) before it gives up on the run. macOS frees a closed socket
/// only in a sweep that runs about every 2 s: back-to-back full
/// loopback scans leave so many waiting that socket() fails with
/// ENOBUFS until the next sweep (seen on an M3 Pro; no sysctl raises
/// the limit). This outlasts two sweeps.
pub const STALL_LIMIT_NS = 5 * std.time.ns_per_s;
/// The pause before a connect that could not start is tried again. It
/// doubles while the shortage lasts, up to MAX_PAUSE_NS: a descriptor
/// freed by a connect settling is taken up within a millisecond, and a
/// sweep within a tenth of a second, while a long wait costs a few
/// dozen system calls.
const FIRST_PAUSE_NS = 1 * std.time.ns_per_ms;
const MAX_PAUSE_NS = 100 * std.time.ns_per_ms;

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

/// MAX_LOOPS on macOS. There a connect to a closed port on the machine
/// itself is refused inside the connect call, under the kernel's TCP
/// locks, so loopback work does not spread over threads: past three,
/// they mostly wait on each other. On an 11-core Mac, 5 loops took
/// twice the kernel CPU of 3 and were 40% slower on `ns -p 127.0.0.1
/// 1-65535`; 2 were slower again. Scans that wait on the network, a
/// LAN host's full range included, took the same time with 3 as 5.
const MAX_LOOPS_MACOS = 3;

/// MAX_LOOPS on Windows. Its connects' system calls do run in parallel,
/// but on the one machine measured, a 24-thread i9-12900K, the scan
/// was fastest with four loops and slowed down again past them:
/// `ns -p 127.0.0.1 1-65535` took 2.45s with 4 against 2.86s with 8
/// (and 7.6s with 1), the kernel CPU rising from 7.9s to 10.1s. Why is
/// not known; that CPU's slower efficiency cores may play a part. A
/// router's 1-1024 took the same 0.88s with 1 to 8. Linux keeps
/// MAX_LOOPS: there (WSL2, same machine) loopback kept getting faster
/// up to 6-8 loops.
const MAX_LOOPS_WINDOWS = 4;

fn loopCount() usize {
    const cpus = std.Thread.getCpuCount() catch 1;
    const most: usize = switch (builtin.os.tag) {
        .macos => MAX_LOOPS_MACOS,
        .windows => MAX_LOOPS_WINDOWS,
        else => MAX_LOOPS,
    };
    return std.math.clamp(cpus / 2, 1, most);
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
        /// A loop gave up on the run (see STALL_LIMIT_NS): the others
        /// start nothing more either.
        starved: std.atomic.Value(bool) = .init(false),

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
    var held: Held(Job) = .{};

    var dry = false;
    while (true) {
        if (shared.starved.load(.monotonic)) {
            // The run is over: only the connects in flight still settle.
            held = .{};
            dry = true;
        }

        // Top up, a batch at a time, while the window has room: first
        // the connects that could not start, once their pause is over.
        var room_left = false;
        var batch: usize = 0;
        while (flight.len < flight.jobs.len) : (batch += 1) {
            if (batch == START_BATCH) {
                room_left = true;
                break;
            }
            const started = nowNs(io);
            const job: Job = if (held.due(started)) held.pop() else if (!held.open()) break else take: {
                if (!dry) switch (shared.take(flight.len)) {
                    .job => |job| break :take job,
                    .full => break,
                    .dry => dry = true,
                };
                // No target left to tell a suspect from a shortage: it
                // counts as unanswered, as it always did.
                if (held.dropSuspect()) |suspect| shared.done(suspect, .filtered, 0);
                break;
            };
            const attempt = start(job.target);
            if (attempt == .unprobed) {
                if (!held.hold(job, attempt.unprobed, started)) {
                    shared.starved.store(true, .monotonic);
                    held = .{};
                    dry = true;
                }
                continue;
            }
            if (held.started()) |suspect| shared.done(suspect, .filtered, 0);
            switch (attempt) {
                .done => |outcome| shared.done(job, outcome, elapsedUs(started, nowNs(io))),
                .pending => |sock| flight.add(job, sock, started),
                .unprobed => unreachable,
            }
        }
        if (flight.len == 0) {
            if (held.short) {
                // Nothing in flight to free what is short: pause.
                const now = nowNs(io);
                if (held.retry_at > now) io.sleep(.fromNanoseconds(held.retry_at - now), .awake) catch {};
                continue;
            }
            if (dry and held.len == 0) return;
            continue;
        }

        // Sleep until something settles, the earliest deadline or the
        // next try at a connect that could not start, or just look,
        // when the batch stopped short of the window.
        const now = nowNs(io);
        const until = if (held.short) @min(held.retry_at, flight.earliestDeadline()) else flight.earliestDeadline();
        const wait_ms = if (room_left) 0 else msUntil(now, until);
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

/// Connects a loop took from its source but could not start, for want
/// of something on this machine (see Shortage). The loop tries them
/// again before anything new, after a pause that doubles while the
/// shortage lasts (FIRST_PAUSE_NS up to MAX_PAUSE_NS), and gives up on
/// the run once it has lasted STALL_LIMIT_NS. Meanwhile it starts
/// nothing new, so its connects in flight settle and free their
/// sockets. Before, such a connect counted as unanswered: a scan that
/// ran out of sockets reported every port it never probed as filtered,
/// and on macOS finished a full loopback range in 30 ms with no open
/// ports.
///
/// A lone `.address` failure while connects were starting fine is only
/// a suspect: the target itself may be one no connect can reach. The
/// loop goes on to the next target; if that one starts, the suspect
/// counts as unanswered, as it always did, and if not, the shortage is
/// real and both wait. Hence two at most.
fn Held(comptime Job: type) type {
    return struct {
        jobs: [2]Job = undefined,
        len: usize = 0,
        /// jobs[0] is a suspect, waiting on the next target's start.
        suspect: bool = false,
        /// The last start failed: short of something since `since`.
        short: bool = false,
        since: i96 = 0,
        retry_at: i96 = 0,
        pause: i96 = FIRST_PAUSE_NS,

        const Self = @This();

        /// Whether jobs[0] is to be tried again now.
        fn due(self: *const Self, now: i96) bool {
            return self.len > 0 and !self.suspect and (!self.short or now >= self.retry_at);
        }

        /// Whether the loop may take new connects from its source: not
        /// while short, except one to test a suspect against.
        fn open(self: *const Self) bool {
            return self.len == 0 or self.suspect;
        }

        fn pop(self: *Self) Job {
            const job = self.jobs[0];
            self.jobs[0] = self.jobs[1];
            self.len -= 1;
            return job;
        }

        /// A connect could not start at `now`. False once the shortage
        /// has lasted STALL_LIMIT_NS: time to give up.
        fn hold(self: *Self, job: Job, shortage: Shortage, now: i96) bool {
            std.debug.assert(self.len < self.jobs.len);
            self.jobs[self.len] = job;
            self.len += 1;
            if (shortage == .address and !self.short and self.len == 1) {
                self.suspect = true;
                return true;
            }
            self.suspect = false;
            if (!self.short) {
                self.short = true;
                self.since = now;
                self.pause = FIRST_PAUSE_NS;
            }
            self.retry_at = now + self.pause;
            self.pause = @min(2 * self.pause, MAX_PAUSE_NS);
            return now - self.since < STALL_LIMIT_NS;
        }

        /// A connect started, so nothing is short any more. Returns the
        /// suspect, if any: its failure was its target's own.
        fn started(self: *Self) ?Job {
            self.short = false;
            return self.dropSuspect();
        }

        fn dropSuspect(self: *Self) ?Job {
            if (!self.suspect) return null;
            self.suspect = false;
            return self.pop();
        }
    };
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
    // A connect that cannot start waits as in a run (see Held). Alone,
    // though, nothing tells a target no connect can reach from used-up
    // ports, so `.address` counts as unanswered, as does a shortage
    // that outlasts STALL_LIMIT_NS.
    const first = nowNs(io);
    var started = first;
    var pause: i96 = FIRST_PAUSE_NS;
    const sock = while (true) : (started = nowNs(io)) {
        switch (start(target)) {
            .done => |outcome| return outcome,
            .pending => |sock| break sock,
            .unprobed => |shortage| if (shortage == .address or started - first >= STALL_LIMIT_NS) return .filtered,
        }
        io.sleep(.fromNanoseconds(pause), .awake) catch {};
        pause = @min(2 * pause, MAX_PAUSE_NS);
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
    /// Never sent, for want of something on this machine: no word on
    /// the target at all.
    unprobed: Shortage,
};

/// What a connect that could not start was short of.
const Shortage = enum {
    /// A socket (out of descriptors, or kernel memory: macOS's ENOBUFS,
    /// see STALL_LIMIT_NS), or buffers to connect it with. Always this
    /// machine's doing.
    socket,
    /// A local port to connect from (EADDRNOTAVAIL): the ephemeral
    /// ports are used up, or the target is one no connect can reach,
    /// such as port 0 on macOS and Windows or 0.0.0.0 on Windows. Only
    /// another target can tell which (see Held).
    address,
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
            .no_socket => .{ .unprobed = .socket },
            .no_address => .{ .unprobed = .address },
        };
    }

    // A blocking connect to a dead host stalls ~75s in SYN retransmits,
    // so the socket goes non-blocking before connecting.
    const fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
    if (fd < 0) return .{ .unprobed = .socket };

    const raw_flags = std.c.fcntl(fd, std.posix.F.GETFL, @as(c_int, 0));
    // O_NONBLOCK lives in a packed bit struct on macOS, so flip the bit
    // through an integer round-trip.
    var oflags: std.posix.O = @bitCast(@as(u32, @bitCast(raw_flags)));
    oflags.NONBLOCK = true;
    if (raw_flags < 0 or std.c.fcntl(fd, std.posix.F.SETFL, @as(u32, @bitCast(oflags))) < 0) {
        _ = std.c.close(fd);
        return .{ .unprobed = .socket };
    }

    var addr = std.posix.sockaddr.in{
        .port = std.mem.nativeToBig(u16, target.port),
        // @bitCast copies the bytes as-is, which is exactly the network
        // byte order sockaddr expects.
        .addr = @bitCast(target.ip),
    };
    const rc = std.c.connect(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
    const started: Started = if (rc == 0) .{ .done = connected(fd) } else switch (std.c.errno(rc)) {
        // In progress. An interrupted connect carries on in the
        // background just the same.
        .INPROGRESS, .INTR => return .{ .pending = fd },
        // Short of something here: nothing went out.
        .NOBUFS, .NOMEM, .AGAIN => .{ .unprobed = .socket },
        .ADDRNOTAVAIL => .{ .unprobed = .address },
        else => |err| .{ .done = classify(@backingInt(err)) },
    };
    _ = std.c.close(fd);
    return started;
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
            .filtered, .pending, .no_socket, .no_address => .filtered,
        };
    }
    defer _ = std.c.close(sock);
    var so_error: c_int = 0;
    var opt_len: std.posix.socklen_t = @sizeOf(c_int);
    if (std.c.getsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.ERROR, @ptrCast(&so_error), &opt_len) != 0) {
        return .filtered;
    }
    if (!settled and so_error == 0) return .filtered;
    if (so_error == 0) return connected(sock);
    return classify(so_error);
}

/// The verdict on a connect that succeeded: open, unless it reached
/// its own socket. When a connect to one of the machine's own
/// addresses happens to get the target port as its source port, the
/// OS completes it as a simultaneous open with itself, so it succeeds
/// with nothing listening. `ns -p 127.0.0.1 1-65535` reported such
/// phantom ports, inside the ephemeral range, in most runs on Linux
/// and in some on Windows (#90). Nothing answered, so it counts as
/// refused.
fn connected(fd: std.posix.fd_t) Outcome {
    var local: std.posix.sockaddr.in = undefined;
    var peer: std.posix.sockaddr.in = undefined;
    var local_len: std.posix.socklen_t = @sizeOf(@TypeOf(local));
    var peer_len: std.posix.socklen_t = @sizeOf(@TypeOf(peer));
    if (std.c.getsockname(fd, @ptrCast(&local), &local_len) != 0) return .open;
    if (std.c.getpeername(fd, @ptrCast(&peer), &peer_len) != 0) return .open;
    const self = local.port == peer.port and local.addr == peer.addr;
    return if (self) .refused else .open;
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
