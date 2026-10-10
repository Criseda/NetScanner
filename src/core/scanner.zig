//! NetScanner's scanning engine: host discovery and port scanning.
//!
//! Everything here runs without root privileges. Host discovery pairs a
//! fast TCP-connect sweep with an ARP-table harvest, because many LAN
//! devices (phones, tablets, printers) silently drop TCP packets yet
//! still answer ARP. A slower one-ping-per-host sweep remains available
//! as a fallback.

const std = @import("std");
const builtin = @import("builtin");
const Thread = std.Thread;
const utils = @import("utils.zig");
const c_bindings = @import("bindings");
const oui = @import("oui.zig");
const ports = @import("ports.zig");
const resolver = @import("resolver.zig");
const progress = @import("progress.zig");
const rtt = @import("rtt.zig");
const connects = @import("connects.zig");

/// Cap for one discovery connect attempt, in milliseconds. Bounds
/// discovery probes, so filtered hosts cost little.
/// Windows used to need 3000 here: it retried a refused connect for
/// about 2s before reporting it. src/c/tcp_probe.c now turns those
/// retries off, so refusals arrive in milliseconds on every OS.
const CONNECT_TIMEOUT_MS: u32 = 500;
/// Cap for one port-scan connect attempt, in milliseconds: where the
/// learned timeout starts, and the most it can grow to. An open port
/// answers quickly on a LAN, and closed-vs-filtered both mean "not
/// open" and stay silent, so a short wait only costs accuracy against
/// unusually slow hosts -- never against the common case. Do not raise
/// it without remeasuring large filtered ranges.
const PORT_TIMEOUT_MS: u32 = 500;
/// The least a learned port-scan timeout waits, in milliseconds. LAN
/// hosts answer in a few milliseconds, and in about 20 even under a
/// full scan's load, so this leaves ample headroom; it is also nmap's
/// default minimum (--min-rtt-timeout).
const PORT_TIMEOUT_FLOOR_MS: u32 = 100;
comptime {
    // probePort retries a learned wait only when two tries fit in one
    // full wait, so the floor must leave room for that.
    std.debug.assert(2 * PORT_TIMEOUT_FLOOR_MS <= PORT_TIMEOUT_MS);
}

// ---------------------------------------------------------------------------
// TCP connecting with a timeout. Shared by port scanning ("is this port
// open?") and discovery probing ("is anyone home?").
// ---------------------------------------------------------------------------

/// What one TCP connect attempt found.
pub const ProbeOutcome = connects.Outcome;

/// Connect to ip:port, waiting at most CONNECT_TIMEOUT_MS.
/// This is the discovery verdict ("is anyone home?"): both open and
/// refused prove a host is up.
/// std.Io's connect takes a `timeout` option, but Zig 0.17 leaves it
/// unimplemented (it panics) on every OS, so the timeout is our own
/// (see connects.zig). Scans themselves make many connects at once
/// through connects.run; this is the one-at-a-time form.
pub fn tcpConnect(io: std.Io, ip: [4]u8, port: u16) ProbeOutcome {
    return tcpConnectPort(io, ip, port, CONNECT_TIMEOUT_MS);
}

/// Connect to ip:port, waiting at most timeout_ms. This is the
/// port-scan verdict ("is this port open?"): only open matters, while
/// refused and filtered both mean "not open" and stay silent in the
/// scan output.
pub fn tcpConnectPort(io: std.Io, ip: [4]u8, port: u16, timeout_ms: u32) ProbeOutcome {
    return connects.connectOnce(io, .{ .ip = ip, .port = port, .timeout_ms = timeout_ms });
}

// ---------------------------------------------------------------------------
// What every part of a scan shares: where output goes, how progress is
// reported, and whether to stop early.
// ---------------------------------------------------------------------------

/// One scan's reporting and control, handed to every worker by value.
/// Holds only pointers and plain values, all of which outlive the
/// workers (they are joined before the scan returns).
const Run = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    /// Serializes everything the scan prints, so lines never interleave.
    stdout_mutex: *std.Io.Mutex,
    tracker: *progress.Tracker,
    /// Print results as they are found, plus --json progress events.
    stream: bool,
    json: bool,
    display: ?progress.Display,
    cancel: ?*const std.atomic.Value(bool),

    /// For either options struct: both name these fields the same.
    /// `own_tracker` counts when the caller passes no tracker of its own.
    fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        stdout_mutex: *std.Io.Mutex,
        own_tracker: *progress.Tracker,
        options: anytype,
    ) Run {
        return .{
            .io = io,
            .allocator = allocator,
            .stdout_mutex = stdout_mutex,
            .tracker = options.tracker orelse own_tracker,
            .stream = options.stream_results,
            .json = options.json,
            .display = options.display,
            .cancel = options.cancel,
        };
    }

    /// True once the caller asked the scan to stop. Worker pools check
    /// it before taking the next unit of work; work in flight finishes.
    fn stopRequested(self: Run) bool {
        const flag = self.cancel orelse return false;
        return flag.load(.monotonic);
    }

    fn startPhase(self: Run, phase: progress.Phase, total: usize) void {
        self.tracker.startPhase(self.io, phase, total);
    }

    fn addFound(self: Run) void {
        self.tracker.addFound();
    }

    /// Count one finished unit of the current phase. With --json and
    /// streaming on, print `{"type":"progress","phase":...,"done":N,
    /// "total":M}` whenever that moves the whole percentage.
    fn advance(self: Run) void {
        if (!self.tracker.advance() or !(self.json and self.stream)) return;
        self.stdout_mutex.lockUncancelable(self.io);
        defer self.stdout_mutex.unlock(self.io);
        const done = self.tracker.claim() orelse return;
        const phase = self.tracker.phase orelse return;
        var buf: [128]u8 = undefined;
        var writer: std.Io.File.Writer = .initStreaming(.stdout(), self.io, &buf);
        writer.interface.print("{{\"type\":\"progress\",\"phase\":\"{s}\",\"done\":{d},\"total\":{d}}}\n", .{
            @tagName(phase), done, self.tracker.total,
        }) catch return;
        writer.interface.flush() catch {};
    }

    /// The display may draw from now on: the scan's header is out.
    fn beginDisplay(self: Run) void {
        if (self.display) |d| d.begin();
    }

    /// The display clears for good: results print next. Idempotent.
    fn endDisplay(self: Run) void {
        if (self.display) |d| d.end();
    }
};

/// Appended to a text summary's closing line after the scan was stopped
/// early, so partial results never pass for a complete scan.
pub fn interruptedNote(stopped: bool) []const u8 {
    return if (stopped) ", interrupted" else "";
}

// ---------------------------------------------------------------------------
// Port scanning: try every TCP port in a range on one IP.
// ---------------------------------------------------------------------------

pub const ScanOptions = struct {
    /// Print each open port as it is found ("Open port: N", or a `port`
    /// event with --json), plus --json `progress` events. The CLI turns
    /// this off only for its status line, where the closing table is
    /// the one listing. Tests turn it off too: test binaries running
    /// under `zig build test` speak the build protocol over stdout, and
    /// stray writes hang the runner.
    stream_results: bool = true,
    /// Per-probe wait cap in milliseconds, fixed for the whole scan.
    /// Null learns it from the host's own answers instead (see
    /// LearnedTimeout). Exposed as `ns -p ... --timeout <ms>` for
    /// unusually slow networks, or to pin the wait exactly.
    timeout_ms: ?u16 = null,
    /// Stream `{"type":"port",...}` lines instead of "Open port: N (name)",
    /// plus `progress` events (phase `ports`), when stream_results is on.
    json: bool = false,
    /// Counts the scan's progress (phase `ports`) and open ports for
    /// whoever shows it. Optional: the scan keeps its own otherwise.
    tracker: ?*progress.Tracker = null,
    /// Shows `tracker` while the scan runs (the CLI's status line). It
    /// is down again by the time scanPorts returns.
    display: ?progress.Display = null,
    /// Set (from a Ctrl+C handler, say) to stop early: no new ports are
    /// probed, and the open ports found so far come back.
    cancel: ?*const std.atomic.Value(bool) = null,
};

/// Scan start_port..end_port (inclusive) on one IP and return the
/// open ports, sorted ascending. Callers pass start_port <= end_port
/// (the CLI swaps reversed ranges itself); anything else is
/// error.InvalidPortRange.
///
/// Many connects stay in flight at once (connects.run), as many as the
/// host keeps answering promptly: no thread per port, no sleeps, no
/// per-port stderr. A second pass then retries the ports a learned
/// wait left unanswered, and a third the ones still silent when the
/// second showed the host had been losing probes (see
/// PortScan.needsThirdPass). Only open ports print, and
/// only when options.stream_results is set; closed and filtered both
/// mean "not open" and stay silent either way.
pub fn scanPorts(
    allocator: std.mem.Allocator,
    io: std.Io,
    ip_address: [4]u8,
    start_port: u16,
    end_port: u16,
    options: ScanOptions,
) !std.ArrayList(u16) {
    if (start_port > end_port) return error.InvalidPortRange;
    const total: usize = @as(usize, end_port) - start_port + 1;

    var stdout_mutex: std.Io.Mutex = .init;
    var own_tracker: progress.Tracker = .{};
    const run: Run = .init(allocator, io, &stdout_mutex, &own_tracker, options);

    var scan: PortScan = .{
        .run = run,
        .ip = ip_address,
        .next_port = start_port,
        .end = end_port,
        .fixed_ms = options.timeout_ms,
        .estimator = .init(PORT_TIMEOUT_FLOOR_MS, PORT_TIMEOUT_MS),
    };
    defer scan.retries.deinit(allocator);
    errdefer scan.open_ports.deinit(allocator);
    // Room for every port up front, so deferring one never fails
    // halfway through a scan.
    if (options.timeout_ms == null) try scan.retries.ensureTotalCapacity(allocator, total);

    run.startPhase(.ports, total);
    // A port scan prints no header, so the display can start at once.
    // The caller prints the results, once it is down again.
    run.beginDisplay();
    defer run.endDisplay();

    // First every port gets one try; then the ports a learned wait
    // left unanswered get their second (see PortScan.firstTry).
    try connects.run(PortProbe, allocator, io, &scan, .adaptive);
    scan.pass = .retry;
    try connects.run(PortProbe, allocator, io, &scan, .adaptive);
    if (scan.needsThirdPass()) {
        scan.pass = .third;
        try connects.run(PortProbe, allocator, io, &scan, .pool);
    }

    std.mem.sort(u16, scan.open_ports.items, {}, u16LessThan);
    return scan.open_ports;
}

fn u16LessThan(_: void, a: u16, b: u16) bool {
    return a < b;
}

/// One port's connect, as connects.run carries it.
const PortProbe = struct {
    target: connects.Target,
    /// A first try with a learned wait: if unanswered, the port gets a
    /// second try in the retry pass instead of counting as not open.
    deferrable: bool,
};

/// One port scan's state: the source connects.run pulls ports from and
/// reports verdicts to, first for every port, then for the retries.
/// connects.run calls it one call at a time, so it needs no locks.
const PortScan = struct {
    run: Run,
    ip: [4]u8,
    pass: enum { first, retry, third } = .first,
    /// The next port the first pass tries; past `end` once it is done.
    next_port: u32,
    end: u32,
    /// `--timeout`: the same wait for every probe, and no retry pass.
    fixed_ms: ?u16,
    /// Otherwise the wait is learned from this host's answers as the
    /// scan goes.
    estimator: rtt.RttEstimator,
    open_ports: std.ArrayList(u16) = .empty,
    /// Ports a learned wait left unanswered, for their second try.
    /// The second pass then moves the ones still unanswered to the
    /// front, `silent_twice` of them, for a third try if it comes to
    /// that. (Each slot is handed out before any port can settle into
    /// it, so the list is never read where it was just written.)
    retries: std.ArrayList(u16) = .empty,
    next_retry: usize = 0,
    silent_twice: usize = 0,
    /// Second tries that got an answer: the first one was lost.
    answered_twice: usize = 0,
    next_third: usize = 0,
    /// Progress in half ports: a port settled by its first try counts
    /// two halves, a deferred one a half per try. So the `ports` phase
    /// keeps one unit per port, and still climbs through the first
    /// pass of a host whose ports nearly all wait for a second try.
    half_units: usize = 0,

    /// The next port to try, or null when this pass is done or the
    /// scan was asked to stop.
    pub fn next(self: *PortScan) ?PortProbe {
        if (self.run.stopRequested()) return null;
        switch (self.pass) {
            .first => {
                if (self.next_port > self.end) return null;
                const port: u16 = @intCast(self.next_port);
                self.next_port += 1;
                return self.firstTry(port);
            },
            .retry => {
                if (self.next_retry >= self.retries.items.len) return null;
                const port = self.retries.items[self.next_retry];
                self.next_retry += 1;
                // The wait learned by now.
                return self.probe(port, self.estimator.timeoutMs(), false);
            },
            .third => {
                if (self.next_third >= self.silent_twice) return null;
                const port = self.retries.items[self.next_third];
                self.next_third += 1;
                return self.probe(port, self.estimator.timeoutMs(), false);
            },
        }
    }

    /// Least second tries answered before a scan counts its first pass
    /// as lossy (see needsThirdPass). The lossy hosts measured answered
    /// 4k-26k; scanme.nmap.org, 170 ms away, answers a few hundred as
    /// slow refusals that missed a tight wait (#71), which a third
    /// pass would only add a wait for. So it takes a scan big enough
    /// to overload a host in the first place.
    const LOSSY_MIN_ANSWERS = 1000;

    /// Whether the ports silent on both tries get a third, slower one.
    /// They do when many second tries got the answer the first did
    /// not: then the host was losing probes, not dropping closed ports.
    /// An iPhone on Wi-Fi, scanned at full pace, answered most of its
    /// 15-60k second tries, yet in 3 of 16 runs an open port still
    /// missed both: the phone answered nothing at all for seconds, or
    /// was busy enough to drop the port's SYN twice. A mesh router lost
    /// two of its ports in every such run. The third pass goes at the
    /// old thread pool's pace (connects.Pace.pool), which neither lost
    /// more ports to than before. A host that drops closed ports
    /// answers next to none of its retries, and one with a dropped port
    /// or two (a firewall on the path) has too few: neither pays for a
    /// third pass.
    fn needsThirdPass(self: *const PortScan) bool {
        if (self.run.stopRequested() or self.silent_twice == 0) return false;
        return self.answered_twice >= LOSSY_MIN_ANSWERS and
            10 * self.answered_twice >= self.retries.items.len;
    }

    /// A port's first try. A learned wait is used only when two tries
    /// of it fit in PORT_TIMEOUT_MS, and an unanswered first try earns
    /// a second, so one lost SYN cannot hide an open port. (The OS
    /// retransmits a SYN only after a second or more, well past either
    /// wait, so the single full wait never had a second try.) The
    /// second try waits for the end of the scan: right away, a host
    /// that stalls for a moment would miss both. Otherwise, on a slow
    /// link, the probe waits the full PORT_TIMEOUT_MS once, as a fixed
    /// timeout did. Either way no port costs more than it used to.
    fn firstTry(self: *PortScan, port: u16) PortProbe {
        if (self.fixed_ms) |ms| return self.probe(port, ms, false);
        const learned_ms = self.estimator.timeoutMs();
        if (2 * learned_ms > PORT_TIMEOUT_MS) return self.probe(port, PORT_TIMEOUT_MS, false);
        return self.probe(port, learned_ms, true);
    }

    fn probe(self: *PortScan, port: u16, timeout_ms: u32, deferrable: bool) PortProbe {
        return .{
            .target = .{ .ip = self.ip, .port = port, .timeout_ms = timeout_ms },
            .deferrable = deferrable,
        };
    }

    /// One port's verdict. An answer, open or refused, teaches its
    /// round trip to the probes that follow. Only open ports are
    /// recorded; closed (refused) and filtered (timeout) both mean "not
    /// open" and stay silent, which also keeps large filtered ranges
    /// from drowning in per-port stderr lines. Every probed port counts
    /// toward progress, open or not, and only after its `port` event,
    /// so a frontend never sees 100% before the last hit.
    pub fn done(self: *PortScan, p: PortProbe, outcome: ProbeOutcome, elapsed_us: u64) void {
        if (outcome != .filtered) self.estimator.observe(elapsed_us);
        const port = p.target.port;
        if (self.pass == .retry) {
            if (outcome == .filtered) {
                self.retries.items[self.silent_twice] = port;
                self.silent_twice += 1;
            } else {
                self.answered_twice += 1;
            }
        }
        // Progress was full after the second pass already.
        if (self.pass == .third) {
            if (outcome == .open) self.recordOpen(port);
            return;
        }
        switch (outcome) {
            .open => self.recordOpen(port),
            .refused => {},
            .filtered => if (p.deferrable) {
                self.retries.appendAssumeCapacity(port);
                self.advanceHalves(1);
                return;
            },
        }
        self.advanceHalves(if (self.pass == .first) 2 else 1);
    }

    fn recordOpen(self: *PortScan, port: u16) void {
        const run = self.run;
        if (run.stream) printOpenPort(run.io, run.stdout_mutex, port, run.json);
        run.addFound();
        self.open_ports.append(run.allocator, port) catch |err| {
            std.debug.print("Error appending port {}: {}\n", .{ port, err });
        };
    }

    /// Count `halves` more half ports, advancing progress by every
    /// whole port they complete.
    fn advanceHalves(self: *PortScan, halves: usize) void {
        const before = self.half_units;
        self.half_units += halves;
        for (before / 2..self.half_units / 2) |_| self.run.advance();
    }
};

/// One streamed port-scan hit, in text or JSON form, named from the
/// embedded port table. JSON always carries all four service fields
/// (null when unknown) so consumers need no presence checks.
fn printOpenPort(io: std.Io, stdout_mutex: *std.Io.Mutex, port: u16, json: bool) void {
    const service = ports.lookup(port);
    if (json) {
        var bufs: [4][768]u8 = undefined;
        utils.printStdout(io, stdout_mutex, "{{\"type\":\"port\",\"port\":{d},\"service\":{s},\"iana\":{s},\"description\":{s},\"category\":{s}}}\n", .{
            port,
            utils.jsonStringOrNull(&bufs[0], if (service) |s| s.name else null),
            utils.jsonStringOrNull(&bufs[1], if (service) |s| s.iana else null),
            utils.jsonStringOrNull(&bufs[2], if (service) |s| s.description else null),
            utils.jsonStringOrNull(&bufs[3], if (service) |s| s.category else null),
        });
    } else if (service) |s| {
        utils.printStdout(io, stdout_mutex, "Open port: {d} ({s})\n", .{ port, s.name });
    } else {
        utils.printStdout(io, stdout_mutex, "Open port: {d}\n", .{port});
    }
}

// ---------------------------------------------------------------------------
// Host discovery: one TCP connect per IP, many in flight at once
// (sweepHosts). The ping fallback (scanNetworkPing) does not
// use this machinery; it runs waves of ping processes (pingSweep).
// ---------------------------------------------------------------------------

pub const NetworkScanOptions = struct {
    resolve_hostname: bool = false,
    resolve_vendor: bool = false,
    oui_file: ?[]const u8 = null,
    /// Emit one JSON object per line (`--json`) instead of the
    /// human-readable text, for programs that drive `ns`.
    json: bool = false,
    /// Print each host as it is found ("Host ... is online", or a
    /// `host` event with --json), plus --json `progress` events. Off,
    /// the closing summary is the only listing (the CLI's status line).
    stream_results: bool = true,
    /// Counts the scan's progress and hosts found for whoever shows it.
    /// Optional: the scan keeps its own otherwise.
    tracker: ?*progress.Tracker = null,
    /// Shows `tracker` while the scan runs (the CLI's status line):
    /// from just after the header to just before the results.
    display: ?progress.Display = null,
    /// Set (from a Ctrl+C handler, say) to stop early: worker pools
    /// take no new work, and the hosts found so far are reported.
    cancel: ?*const std.atomic.Value(bool) = null,
};

/// State shared by every worker of a discovery sweep. It lives on the
/// caller's stack and holds nothing but pointers plus plain values, so
/// passing it to threads by value is safe. All threads are joined
/// before the sweep returns.
const Discovery = struct {
    run: Run,
    found: *std.ArrayList([4]u8),
    found_mutex: *std.Io.Mutex,
    ip_mac_map: *std.AutoHashMap([4]u8, [6]u8),
    ip_mac_mutex: *std.Io.Mutex,

    /// Record a host as found and count it, then print it, tagged with
    /// how it was found, when results stream.
    fn reportHost(self: Discovery, ip: [4]u8, comptime source: HostSource) void {
        const run = self.run;
        self.found_mutex.lockUncancelable(run.io);
        defer self.found_mutex.unlock(run.io);
        self.found.append(run.allocator, ip) catch return;
        run.addFound();
        if (run.stream) printHost(run.io, run.stdout_mutex, ip, source, run.json);
    }

    fn isFound(self: Discovery, ip: [4]u8) bool {
        self.found_mutex.lockUncancelable(self.run.io);
        defer self.found_mutex.unlock(self.run.io);
        for (self.found.items) |known| {
            if (std.mem.eql(u8, &known, &ip)) return true;
        }
        return false;
    }

    fn recordMac(self: Discovery, ip: [4]u8, mac: [6]u8) void {
        self.ip_mac_mutex.lockUncancelable(self.run.io);
        defer self.ip_mac_mutex.unlock(self.run.io);
        self.ip_mac_map.put(ip, mac) catch return;
    }
};

/// How a host was found. Text output tags only ARP hosts (" (arp)");
/// JSON output always names the source.
const HostSource = enum { tcp, arp, ping };

/// One streamed discovery hit, e.g. `Host 192.168.1.10 is online (arp)`
/// or `{"type":"host","ip":"192.168.1.10","source":"arp"}`.
fn printHost(io: std.Io, stdout_mutex: *std.Io.Mutex, ip: [4]u8, comptime source: HostSource, json: bool) void {
    if (json) {
        utils.printStdout(io, stdout_mutex, "{{\"type\":\"host\",\"ip\":\"{d}.{d}.{d}.{d}\",\"source\":\"" ++ @tagName(source) ++ "\"}}\n", .{
            ip[0], ip[1], ip[2], ip[3],
        });
    } else {
        const suffix = if (source == .arp) " (arp)" else "";
        utils.printStdout(io, stdout_mutex, "Host {d}.{d}.{d}.{d} is online" ++ suffix ++ "\n", .{
            ip[0], ip[1], ip[2], ip[3],
        });
    }
}

/// Probe one TCP port on every IP in the list, many at a time
/// (connects.run), and return once each has answered or timed
/// out. A connect that succeeds or is actively refused proves a host is
/// up; only silence means "no answer". Every probed IP counts toward
/// the current phase, answered or not. A stop request keeps new IPs
/// from being probed.
fn sweepHosts(shares: Discovery, ips: []const [4]u8) void {
    const HostProbe = struct { target: connects.Target };
    const Sweep = struct {
        discovery: Discovery,
        ips: []const [4]u8,
        index: usize = 0,

        pub fn next(self: *@This()) ?HostProbe {
            if (self.index >= self.ips.len or self.discovery.run.stopRequested()) return null;
            const ip = self.ips[self.index];
            self.index += 1;
            return .{ .target = .{ .ip = ip, .port = TCP_PROBE_PORT, .timeout_ms = CONNECT_TIMEOUT_MS } };
        }

        pub fn done(self: *@This(), probe: HostProbe, outcome: ProbeOutcome, _: u64) void {
            if (outcome != .filtered) self.discovery.reportHost(probe.target.ip, .tcp);
            self.discovery.run.advance();
        }
    };
    var sweep: Sweep = .{ .discovery = shares, .ips = ips };
    connects.run(HostProbe, shares.run.allocator, shares.run.io, &sweep, .fixed) catch |err| {
        std.debug.print("tcp sweep skipped: {}\n", .{err});
    };
}

/// The end of both subnet scans, once discovery is done: details (MAC,
/// manufacturer, name) when asked for, then the results. The display
/// comes down only now, so it shows the name lookups too, and the
/// elapsed time covers everything up to the results.
fn reportResults(d: Discovery, options: NetworkScanOptions, started: std.Io.Timestamp) void {
    const run = d.run;
    std.mem.sort([4]u8, d.found.items, {}, ipLessThan);

    if (!options.resolve_hostname and !options.resolve_vendor) {
        const elapsed_ns = started.durationTo(std.Io.Clock.now(.awake, run.io)).nanoseconds;
        run.endDisplay();
        printSummary(run, d.found.items, elapsed_ns);
        return;
    }

    // Lives through printing: vendor names from --oui-file point into it.
    var oui_db = oui.OuiDatabase.init(run.allocator);
    defer oui_db.deinit();
    const details = collectDetails(d, options, &oui_db) catch {
        // No memory for the details: the plain list still names every host.
        const elapsed_ns = started.durationTo(std.Io.Clock.now(.awake, run.io)).nanoseconds;
        run.endDisplay();
        printSummary(run, d.found.items, elapsed_ns);
        return;
    };
    defer {
        for (details) |detail| {
            if (detail.hostname) |h| run.allocator.free(h);
        }
        run.allocator.free(details);
    }
    const elapsed_ns = started.durationTo(std.Io.Clock.now(.awake, run.io)).nanoseconds;
    run.endDisplay();
    printDetails(run, details, options, elapsed_ns);
}

/// Print the closing recap: every found host sorted numerically, then
/// a one-line count plus elapsed time. When results streamed, this
/// block is the diffable record of them; otherwise it is the only one.
/// It takes the lock once for the whole block instead of per line.
fn printSummary(run: Run, found: []const [4]u8, elapsed_ns: i96) void {
    // JSON consumers already have every host from the streamed events;
    // the recap is just the closing count.
    if (run.json) {
        printJsonSummary(run, found.len, elapsed_ns);
        return;
    }

    const seconds = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
    const noun: []const u8 = if (found.len == 1) "host" else "hosts";

    run.stdout_mutex.lockUncancelable(run.io);
    defer run.stdout_mutex.unlock(run.io);
    var buf: [1024]u8 = undefined;
    var writer: std.Io.File.Writer = .initStreaming(.stdout(), run.io, &buf);
    const out = &writer.interface;
    for (found) |ip| {
        out.print("{d}.{d}.{d}.{d}\n", .{ ip[0], ip[1], ip[2], ip[3] }) catch return;
        out.flush() catch return;
    }
    out.print("{d} {s} up ({d:.1}s{s})\n", .{ found.len, noun, seconds, interruptedNote(run.stopRequested()) }) catch {};
    out.flush() catch {};
}

/// `{"type":"summary","hosts":N,"elapsed_ms":M}`: always the last line
/// of a `--json` subnet scan.
fn printJsonSummary(run: Run, host_count: usize, elapsed_ns: i96) void {
    const elapsed_ms: i64 = @intCast(@divTrunc(elapsed_ns, std.time.ns_per_ms));
    utils.printStdout(run.io, run.stdout_mutex, "{{\"type\":\"summary\",\"hosts\":{d},\"elapsed_ms\":{d}}}\n", .{ host_count, elapsed_ms });
}

pub const HostDetail = struct {
    ip: [4]u8,
    hostname: ?[]const u8 = null,
    mac: ?[6]u8 = null,
    vendor: ?[]const u8 = null,
};

/// One HostDetail per found host (already sorted), with the MAC from
/// the ARP table, the manufacturer from the OUI database, and the
/// hostname, as asked for. Name lookups are the slow part (seconds
/// after the sweep), so they run in parallel as the `identify` phase.
/// Caller frees the hostnames and the slice.
fn collectDetails(d: Discovery, options: NetworkScanOptions, oui_db: *oui.OuiDatabase) ![]HostDetail {
    const run = d.run;
    const found = d.found.items;
    const details = try run.allocator.alloc(HostDetail, found.len);
    for (details, found) |*detail, ip| {
        var mac = d.ip_mac_map.get(ip);
        // Fall back to SendARP on Windows for any missing MAC addresses (e.g. localhost)
        // when vendor resolution is requested.
        if (mac == null and options.resolve_vendor) {
            var ip_buf: [16]u8 = undefined;
            mac = c_bindings.getMacSendArp(utils.ipToCString(&ip_buf, ip).ptr);
        }
        detail.* = .{ .ip = ip, .mac = mac };
    }

    if (options.resolve_vendor) {
        if (options.oui_file) |fpath| {
            oui_db.loadFile(fpath) catch |err| {
                std.debug.print("warning: failed to load oui file '{s}': {}\n", .{ fpath, err });
            };
        }
        for (details) |*detail| {
            if (detail.mac) |mac| detail.vendor = oui_db.lookup(mac);
        }
    }

    if (options.resolve_hostname and details.len > 0) resolveHostnames(run, details);
    return details;
}

/// Look up every host's name, 16 at a time, as the `identify` phase. A
/// stop request keeps the pool from starting new lookups.
fn resolveHostnames(run: Run, details: []HostDetail) void {
    run.startPhase(.identify, details.len);
    const Job = struct {
        run: Run,
        details: []HostDetail,
        next: *std.atomic.Value(usize),
    };
    var next_idx: std.atomic.Value(usize) = .init(0);
    const job = Job{ .run = run, .details = details, .next = &next_idx };
    const worker = struct {
        fn work(j: Job) void {
            while (!j.run.stopRequested()) {
                const idx = j.next.fetchAdd(1, .monotonic);
                if (idx >= j.details.len) break;
                j.details[idx].hostname = resolver.resolveHostName(j.run.allocator, j.details[idx].ip);
                j.run.advance();
            }
        }
    }.work;

    const worker_count = @min(details.len, 16);
    var threads: std.ArrayList(Thread) = .empty;
    defer {
        for (threads.items) |t| t.join();
        threads.deinit(run.allocator);
    }
    for (0..worker_count) |_| {
        if (Thread.spawn(.{}, worker, .{job})) |t| {
            threads.append(run.allocator, t) catch {
                t.join();
                break;
            };
        } else |_| break;
    }
    if (threads.items.len == 0) {
        // Fallback: execute synchronously if thread spawning fails or system is single-threaded
        worker(job);
    }
}

/// The closing table (text) or one `host_detail` event per host plus
/// the summary (JSON). Takes the lock once for the whole block.
fn printDetails(run: Run, details: []const HostDetail, options: NetworkScanOptions, elapsed_ns: i96) void {
    const seconds = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
    const noun: []const u8 = if (details.len == 1) "host" else "hosts";

    run.stdout_mutex.lockUncancelable(run.io);
    defer run.stdout_mutex.unlock(run.io);
    var buf: [2048]u8 = undefined;
    var writer: std.Io.File.Writer = .initStreaming(.stdout(), run.io, &buf);
    const out = &writer.interface;

    var ip_str_buf: [15]u8 = undefined;
    var mac_str_buf: [17]u8 = undefined;

    if (run.json) {
        // One host_detail per host; unresolved fields are null, and only
        // the fields that were asked for appear at all.
        var h_buf: [768]u8 = undefined;
        var v_buf: [768]u8 = undefined;
        for (details) |d| {
            const ip_str = utils.formatIp(&ip_str_buf, d.ip);
            out.print("{{\"type\":\"host_detail\",\"ip\":\"{s}\"", .{ip_str}) catch return;
            if (options.resolve_hostname) {
                if (d.hostname) |h| {
                    out.print(",\"hostname\":\"{s}\"", .{utils.jsonEscape(&h_buf, h)}) catch return;
                } else {
                    out.writeAll(",\"hostname\":null") catch return;
                }
            }
            if (options.resolve_vendor) {
                if (d.mac) |m| {
                    out.print(",\"mac\":\"{s}\"", .{utils.formatMac(&mac_str_buf, m)}) catch return;
                } else {
                    out.writeAll(",\"mac\":null") catch return;
                }
                if (d.vendor) |v| {
                    out.print(",\"vendor\":\"{s}\"", .{utils.jsonEscape(&v_buf, v)}) catch return;
                } else {
                    out.writeAll(",\"vendor\":null") catch return;
                }
            }
            out.writeAll("}\n") catch return;
            out.flush() catch return;
        }
        const elapsed_ms: i64 = @intCast(@divTrunc(elapsed_ns, std.time.ns_per_ms));
        out.print("{{\"type\":\"summary\",\"hosts\":{d},\"elapsed_ms\":{d}}}\n", .{ details.len, elapsed_ms }) catch {};
        out.flush() catch {};
        return;
    }

    if (details.len > 0) {
        if (options.resolve_hostname and options.resolve_vendor) {
            out.print("{s: <17}{s: <26}{s: <19}{s}\n", .{ "IP", "HOSTNAME", "MAC", "MANUFACTURER" }) catch return;
            for (details) |d| {
                const ip_str = utils.formatIp(&ip_str_buf, d.ip);
                const h_str = d.hostname orelse "-";
                const mac_str = if (d.mac) |m| utils.formatMac(&mac_str_buf, m) else "-";
                const v_str = d.vendor orelse "-";
                out.print("{s: <17}{s: <26}{s: <19}{s}\n", .{ ip_str, h_str, mac_str, v_str }) catch return;
                out.flush() catch return;
            }
        } else if (options.resolve_hostname) {
            out.print("{s: <17}{s}\n", .{ "IP", "HOSTNAME" }) catch return;
            for (details) |d| {
                const ip_str = utils.formatIp(&ip_str_buf, d.ip);
                const h_str = d.hostname orelse "-";
                out.print("{s: <17}{s}\n", .{ ip_str, h_str }) catch return;
                out.flush() catch return;
            }
        } else if (options.resolve_vendor) {
            out.print("{s: <17}{s: <19}{s}\n", .{ "IP", "MAC", "MANUFACTURER" }) catch return;
            for (details) |d| {
                const ip_str = utils.formatIp(&ip_str_buf, d.ip);
                const mac_str = if (d.mac) |m| utils.formatMac(&mac_str_buf, m) else "-";
                const v_str = d.vendor orelse "-";
                out.print("{s: <17}{s: <19}{s}\n", .{ ip_str, mac_str, v_str }) catch return;
                out.flush() catch return;
            }
        }
    }

    out.print("{d} {s} up ({d:.1}s{s})\n", .{ details.len, noun, seconds, interruptedNote(run.stopRequested()) }) catch {};
    out.flush() catch {};
}

fn ipLessThan(_: void, a: [4]u8, b: [4]u8) bool {
    return utils.ipToU32(a) < utils.ipToU32(b);
}

/// Print the one-line header every network scan starts with.
fn printScanHeader(run: Run, cidr: []const u8, range: utils.IpRange) void {
    if (run.json) {
        var cidr_buf: [128]u8 = undefined;
        utils.printStdout(run.io, run.stdout_mutex, "{{\"type\":\"start\",\"mode\":\"subnet\",\"cidr\":\"{s}\",\"first\":\"{d}.{d}.{d}.{d}\",\"last\":\"{d}.{d}.{d}.{d}\"}}\n", .{
            utils.jsonEscape(&cidr_buf, cidr),
            range.start[0],
            range.start[1],
            range.start[2],
            range.start[3],
            range.end[0],
            range.end[1],
            range.end[2],
            range.end[3],
        });
        return;
    }
    utils.printStdout(run.io, run.stdout_mutex, "Scanning network: {s} (Range: {d}.{d}.{d}.{d} - {d}.{d}.{d}.{d})\n", .{
        cidr,
        range.start[0],
        range.start[1],
        range.start[2],
        range.start[3],
        range.end[0],
        range.end[1],
        range.end[2],
        range.end[3],
    });
}

/// How many ping(1) processes run at once. A /24 still pings every
/// host at once; larger ranges go in waves of this many, instead of
/// starting a process per host all together (a /16 would be 65,534,
/// far past the per-user process limit).
const MAX_PING_PROCESSES = 256;

/// Ping every IP in the list and return which answered, in input order.
/// Hosts never pinged (after a stop request) count as unanswered.
/// Caller frees the result.
///
/// Pings run in waves of up to MAX_PING_PROCESSES, so a /24 takes about
/// one ping wait. Each wave is spawned from this thread, one process
/// after another (std's spawn allocates, which only slows down when
/// hundreds of threads do it at once), then every ping gets a thread of
/// its own to wait on it. So results arrive in completion order: a dead
/// host no longer holds back the answers behind it, as it did when the
/// pings were reaped in input order.
///
/// `observer.pinged(index, answered)` runs on the waiting thread as each
/// ping ends. After a stop request no new pings start. Those running
/// are waited for, never killed: killing would discard the exit status
/// of pings that had already answered, and their hosts with it. The
/// wait is short. A terminal Ctrl+C reaches the pings too (they share
/// ns's process group or console), and each gives up after about 1s
/// anyway. If a ping cannot even start (out of processes, say), the
/// sweep stops, waits for the pings already running, and returns that
/// error.
fn pingSweep(run: Run, ips: []const [4]u8, observer: anytype) ![]bool {
    const alive = try run.allocator.alloc(bool, ips.len);
    errdefer run.allocator.free(alive);
    // Hosts never pinged (the sweep was stopped) count as unanswered.
    @memset(alive, false);

    var first: usize = 0;
    while (first < ips.len and !run.stopRequested()) {
        const last = @min(first + MAX_PING_PROCESSES, ips.len);
        try pingWave(run, ips, first, last, alive, observer);
        first = last;
    }
    return alive;
}

/// One wave of pingSweep: ips[first..last], at most MAX_PING_PROCESSES.
fn pingWave(
    run: Run,
    ips: []const [4]u8,
    first: usize,
    last: usize,
    alive: []bool,
    observer: anytype,
) !void {
    const Waiter = struct {
        run: Run,
        child: std.process.Child,
        index: usize,
        alive: []bool,
        observer: @TypeOf(observer),

        fn wait(w: *@This()) void {
            const term = w.child.wait(w.run.io) catch null;
            const answered = if (term) |t| switch (t) {
                .exited => |code| code == 0,
                else => false,
            } else false;
            w.alive[w.index] = answered;
            w.observer.pinged(w.index, answered);
        }
    };
    var waiters: [MAX_PING_PROCESSES]Waiter = undefined;
    var threads: [MAX_PING_PROCESSES]?Thread = undefined;
    var spawned: usize = 0;
    var spawn_error: ?anyerror = null;

    for (ips[first..last], first..) |ip, index| {
        if (run.stopRequested()) break;
        var ip_buf: [15]u8 = undefined;
        const ip_text = utils.formatIp(&ip_buf, ip);
        var argv_buf: [9][]const u8 = undefined;
        const child = std.process.spawn(run.io, .{
            .argv = pingArgv(&argv_buf, ip_text),
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        }) catch |err| {
            spawn_error = err;
            break;
        };
        waiters[spawned] = .{ .run = run, .child = child, .index = index, .alive = alive, .observer = observer };
        spawned += 1;
    }

    // A thread per ping, so each is heard the moment it ends. If a
    // thread cannot start, its ping is waited for after the others.
    for (waiters[0..spawned], threads[0..spawned]) |*waiter, *thread| {
        thread.* = Thread.spawn(.{}, Waiter.wait, .{waiter}) catch null;
    }
    for (waiters[0..spawned], threads[0..spawned]) |*waiter, thread| {
        if (thread) |t| t.join() else waiter.wait();
    }
    if (spawn_error) |err| return err;
}

/// One ping(1) command line that waits about 1s for a single reply,
/// built in `buf`. Every OS spells that differently:
/// - Windows: -n 1 -w 1000 (milliseconds), and no quiet flag.
/// - Linux: -W 1 waits 1s for the reply. -W counts seconds here but
///   milliseconds on macOS, so the two flag lists must not be merged:
///   macOS's -W 1000 would make Linux wait ~17 minutes per dead host.
/// - macOS: -W 1000 is in milliseconds, yet an unanswered ping still
///   took 2s there, so -t 1 caps the whole run at 1s.
fn pingArgv(buf: *[9][]const u8, ip: []const u8) []const []const u8 {
    const flags: []const []const u8 = switch (comptime builtin.os.tag) {
        .windows => &.{ "-n", "1", "-w", "1000" },
        .macos => &.{ "-c", "1", "-W", "1000", "-t", "1", "-q" },
        else => &.{ "-c", "1", "-W", "1", "-q" },
    };
    buf[0] = "ping";
    @memcpy(buf[1..][0..flags.len], flags);
    buf[1 + flags.len] = ip;
    return buf[0 .. flags.len + 2];
}

/// Slow path: ICMP ping sweep. Kept as a fallback for networks where
/// TCP probing is filtered; prefer scanNetwork.
pub fn scanNetworkPing(
    allocator: std.mem.Allocator,
    io: std.Io,
    cidr: []const u8,
    options: NetworkScanOptions,
) !void {
    const network = try utils.parseCidr(cidr);
    const ip_range = try utils.getIpRange(network);

    var stdout_mutex: std.Io.Mutex = .init;
    var own_tracker: progress.Tracker = .{};
    const run: Run = .init(allocator, io, &stdout_mutex, &own_tracker, options);
    printScanHeader(run, cidr, ip_range);
    // After the header: nothing else reaches stdout until the results.
    run.beginDisplay();
    // Down on every return path; reportResults takes it down first.
    defer run.endDisplay();
    const started = std.Io.Clock.now(.awake, io);

    const hosts = utils.usableHosts(network, ip_range);
    var targets = try utils.collectIps(allocator, hosts.start, hosts.end);
    defer targets.deinit(allocator);

    var found: std.ArrayList([4]u8) = .empty;
    defer found.deinit(allocator);
    var found_mutex: std.Io.Mutex = .init;
    var ip_mac_map = std.AutoHashMap([4]u8, [6]u8).init(allocator);
    defer ip_mac_map.deinit();
    var ip_mac_mutex: std.Io.Mutex = .init;
    const discovery = Discovery{
        .run = run,
        .found = &found,
        .found_mutex = &found_mutex,
        .ip_mac_map = &ip_mac_map,
        .ip_mac_mutex = &ip_mac_mutex,
    };

    // Each host that answers is reported the moment its ping ends.
    const Sweep = struct {
        discovery: Discovery,
        ips: []const [4]u8,

        pub fn pinged(self: @This(), index: usize, answered: bool) void {
            if (answered) self.discovery.reportHost(self.ips[index], .ping);
            self.discovery.run.advance();
        }
    };
    run.startPhase(.sweep, targets.items.len);
    const alive = try pingSweep(run, targets.items, Sweep{ .discovery = discovery, .ips = targets.items });
    allocator.free(alive);

    // MACs for --vendor; the ping sweep confirmed every host itself.
    if (dumpArpTable(allocator, io)) |table| {
        defer allocator.free(table);
        var lines = std.mem.splitScalar(u8, table, '\n');
        while (lines.next()) |line| {
            const entry = utils.parseArpEntry(line) orelse continue;
            if (entry.mac) |mac| discovery.recordMac(entry.ip, mac);
        }
    }

    reportResults(discovery, options, started);
}

// ---------------------------------------------------------------------------
// Fast path: TCP-connect sweep plus ARP harvest. This is what `ns -s`
// runs by default.
// ---------------------------------------------------------------------------

const TCP_PROBE_PORT = 80;

/// Find live hosts in a subnet, fast and without root.
///
/// Three steps: probe one common TCP port per IP (a connect that
/// succeeds or is actively refused proves the host is up; only a
/// timeout means "no answer"), read the `arp -a` table for quiet
/// devices that ignore TCP, then ping each harvest-only candidate
/// once before reporting it -- ARP entries linger after hosts leave,
/// so a complete entry alone is not proof.
pub fn scanNetwork(
    allocator: std.mem.Allocator,
    io: std.Io,
    cidr: []const u8,
    options: NetworkScanOptions,
) !void {
    const network = try utils.parseCidr(cidr);
    const ip_range = try utils.getIpRange(network);

    var stdout_mutex: std.Io.Mutex = .init;
    var own_tracker: progress.Tracker = .{};
    const run: Run = .init(allocator, io, &stdout_mutex, &own_tracker, options);
    printScanHeader(run, cidr, ip_range);
    // After the header: nothing else reaches stdout until the results.
    run.beginDisplay();
    // Down on every return path; reportResults takes it down first.
    defer run.endDisplay();
    const started = std.Io.Clock.now(.awake, io);

    const hosts = utils.usableHosts(network, ip_range);

    var found: std.ArrayList([4]u8) = .empty;
    defer found.deinit(allocator);
    var found_mutex: std.Io.Mutex = .init;
    var ip_mac_map = std.AutoHashMap([4]u8, [6]u8).init(allocator);
    defer ip_mac_map.deinit();
    var ip_mac_mutex: std.Io.Mutex = .init;

    const discovery = Discovery{
        .run = run,
        .found = &found,
        .found_mutex = &found_mutex,
        .ip_mac_map = &ip_mac_map,
        .ip_mac_mutex = &ip_mac_mutex,
    };
    var targets = try utils.collectIps(allocator, hosts.start, hosts.end);
    defer targets.deinit(allocator);
    run.startPhase(.sweep, targets.items.len);
    sweepHosts(discovery, targets.items);

    harvestArp(discovery, hosts.start, hosts.end);

    reportResults(discovery, options, started);
}

/// Read the local ARP table for in-range hosts the TCP sweep missed,
/// then ping each candidate once before reporting it. The ping matters:
/// entries linger up to ~20min after a host leaves, so a complete entry
/// alone is not proof. Needs no privileges; `arp -a` exists on macOS,
/// Linux and Windows, and all three table formats are parsed.
fn harvestArp(shares: Discovery, first_ip: [4]u8, last_ip: [4]u8) void {
    const run = shares.run;
    // No size until the table is read: the display shows just the label.
    run.startPhase(.arp, 0);
    const table = dumpArpTable(run.allocator, run.io) orelse return;
    defer run.allocator.free(table);

    var candidates: std.ArrayList([4]u8) = .empty;
    defer candidates.deinit(run.allocator);
    var lines = std.mem.splitScalar(u8, table, '\n');
    while (lines.next()) |line| {
        const entry = utils.parseArpEntry(line) orelse continue;
        if (entry.mac) |mac| {
            shares.recordMac(entry.ip, mac);
        }
        if (!utils.ipInRange(entry.ip, first_ip, last_ip)) continue;
        if (shares.isFound(entry.ip)) continue;

        // If the OS kernel's neighbor table explicitly marks this entry as actively
        // REACHABLE or in DELAY state (e.g. Linux `ip neigh`), the kernel has recently
        // exchanged packets with this host and confirmed its Layer 2 presence. We can
        // report it immediately without waiting on an ICMP ping.
        if (entry.is_reachable) {
            shares.reportHost(entry.ip, .arp);
            continue;
        }

        candidates.append(run.allocator, entry.ip) catch continue;
    }
    // After a stop request the table above still supplied MACs (reading
    // it is instant), but confirming candidates means another ping wait.
    if (candidates.items.len == 0 or run.stopRequested()) return;

    // One unit per candidate, done once its fate is known: it answered
    // the ping (and is reported "(arp)" right then), or it did not.
    // Windows gives an unanswered candidate a second check (SendARP,
    // below) and counts it once that ends.
    run.startPhase(.arp, candidates.items.len);
    const Confirm = struct {
        discovery: Discovery,
        candidates: []const [4]u8,

        pub fn pinged(self: @This(), index: usize, answered: bool) void {
            if (answered) self.discovery.reportHost(self.candidates[index], .arp);
            if (answered or builtin.os.tag != .windows) self.discovery.run.advance();
        }
    };
    const alive = pingSweep(run, candidates.items, Confirm{ .discovery = shares, .candidates = candidates.items }) catch |err| {
        std.debug.print("arp check skipped: {}\n", .{err});
        return;
    };
    defer run.allocator.free(alive);
    if (comptime builtin.os.tag != .windows) return;

    var unconfirmed: std.ArrayList([4]u8) = .empty;
    defer unconfirmed.deinit(run.allocator);
    for (candidates.items, alive) |ip, is_up| {
        if (!is_up) unconfirmed.append(run.allocator, ip) catch continue;
    }
    if (unconfirmed.items.len == 0) return;

    // For unconfirmed candidates that dropped ICMP ping (e.g. firewalled IoT,
    // GL.iNet, TP-Link smart plugs), verify live Layer 2 presence via SendARP on Windows.
    const ArpJob = struct {
        shares: Discovery,
        targets: [][4]u8,
        next: *std.atomic.Value(usize),
    };
    var next_idx: std.atomic.Value(usize) = .init(0);
    const job = ArpJob{
        .shares = shares,
        .targets = unconfirmed.items,
        .next = &next_idx,
    };
    const arp_worker = struct {
        fn work(j: ArpJob) void {
            while (!j.shares.run.stopRequested()) {
                const idx = j.next.fetchAdd(1, .monotonic);
                if (idx >= j.targets.len) break;
                const ip = j.targets[idx];
                var ip_buf: [16]u8 = undefined;
                if (c_bindings.getMacSendArp(utils.ipToCString(&ip_buf, ip).ptr)) |mac| {
                    j.shares.recordMac(ip, mac);
                    j.shares.reportHost(ip, .arp);
                }
                j.shares.run.advance();
            }
        }
    }.work;

    const worker_count = @min(unconfirmed.items.len, 8);
    var threads: std.ArrayList(Thread) = .empty;
    defer {
        for (threads.items) |t| t.join();
        threads.deinit(run.allocator);
    }
    for (0..worker_count) |_| {
        if (Thread.spawn(.{}, arp_worker, .{job})) |t| {
            threads.append(run.allocator, t) catch {
                t.join();
                break;
            };
        } else |_| break;
    }
    if (threads.items.len == 0) {
        // Fallback: execute synchronously if thread spawning fails or system is single-threaded
        arp_worker(job);
    }
}

/// Dump the neighbour table. Prefers `arp -a`, falls back to
/// `ip neigh show` (minimal Linux distros often lack net-tools).
/// Returns the output for the caller to free, or null when neither
/// tool exists -- then discovery just ends after the TCP sweep.
///
/// macOS reads the kernel table directly instead: since macOS 27 the
/// OS hides it from anything a third-party binary spawns, so `arp -a`
/// run from `ns` always prints nothing. Even the direct read needs
/// `ns` codesigned with a reverse-DNS identifier (build.zig does that)
/// and a shell, not another third-party program, as its parent.
pub fn dumpArpTable(allocator: std.mem.Allocator, io: std.Io) ?[]u8 {
    if (comptime builtin.os.tag == .macos) {
        if (c_bindings.dumpArpTable(allocator)) |table| {
            // A LAN host always has at least its gateway in the table,
            // so empty means macOS filtered it: say why the MAC column
            // and quiet-host harvest will be blank instead of failing
            // silently.
            if (table.len == 0) {
                std.debug.print("arp table is empty: macOS hides it unless ns is codesigned with an " ++
                    "identifier (`zig build` on a Mac does this) and launched directly from a shell; " ++
                    "MAC addresses, manufacturers and quiet hosts will be missing\n", .{});
            }
            return table;
        }
    }
    const commands = [_][]const []const u8{
        &.{ "arp", "-a" },
        &.{ "ip", "neigh", "show" },
    };
    for (commands) |argv| {
        const result = std.process.run(allocator, io, .{ .argv = argv }) catch |err| {
            // Missing tool: try the next one. Anything else is a real
            // failure, so stop instead of running stranger commands.
            if (err != error.FileNotFound) {
                std.debug.print("arp harvest skipped: {}\n", .{err});
                return null;
            }
            continue;
        };
        allocator.free(result.stderr);
        return result.stdout;
    }
    std.debug.print("arp harvest skipped: neither `arp` nor `ip` found\n", .{});
    return null;
}
