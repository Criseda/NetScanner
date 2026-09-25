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
const resolver = @import("resolver.zig");

pub const NetworkScanOptions = struct {
    resolve_hostname: bool = false,
    resolve_vendor: bool = false,
    oui_file: ?[]const u8 = null,
};

/// How many port-scan workers run at once. One fixed worker per
/// thread, each pulling the next port from a shared counter, so a
/// full 65k range needs only this many threads instead of one per
/// port.
/// Each worker holds at most one socket at a time, so peak fd use is
/// roughly this count plus stdio. macOS defaults to a 256 fd limit,
/// so it gets the smaller pool; Linux (1024) and Windows (Winsock,
/// not fds) take the larger one.
const MAX_PORT_THREADS = if (builtin.os.tag == .macos) 128 else 256;
/// How many discovery workers run at once (same pool pattern: one
/// thread per worker, each pulling the next IP from a shared index).
const MAX_TCP_THREADS = 128;
/// Cap for one discovery connect attempt, in milliseconds. Bounds
/// discovery probes, so filtered hosts cost little.
/// Windows gets the larger bound: refusals there can arrive seconds
/// late behind filtering middleboxes, while clean hosts still resolve
/// in milliseconds through the early signal.
const CONNECT_TIMEOUT_MS: c_int = if (builtin.os.tag == .windows) 3000 else 500;
/// Cap for one port-scan connect attempt, in milliseconds. Shorter
/// than discovery on Windows on purpose: an open port answers quickly
/// on a LAN, and closed-vs-filtered both mean "not open" and stay
/// silent, so the shorter wait only costs accuracy against unusually
/// slow hosts -- never against the common case. Do not raise this to
/// the discovery bound without remeasuring large filtered ranges.
const PORT_TIMEOUT_MS: c_int = 500;

// ---------------------------------------------------------------------------
// TCP connecting with a timeout. Shared by port scanning ("is this port
// open?") and discovery probing ("is anyone home?").
// ---------------------------------------------------------------------------

/// What one TCP connect attempt found.
pub const ProbeOutcome = enum {
    open, // Connected: the port is open.
    refused, // RST: the port is closed, but a host answered.
    filtered, // Timeout or unreachable: no answer at all.
};

/// Connect to ip:port, waiting at most CONNECT_TIMEOUT_MS.
/// This is the discovery verdict ("is anyone home?"): both open and
/// refused prove a host is up, so Windows keeps the generous timeout
/// to let slow RSTs arrive.
/// Zig 0.16 implements no connect timeout itself: POSIX uses the
/// hand-rolled non-blocking recipe below, while Windows goes through
/// the Winsock helper in src/c/tcp_probe.c -- the blocking std.Io
/// connect cannot tell refused apart from filtered there (every
/// failure arrives as error.Unexpected) and has no timeout.
pub fn tcpConnect(ip: [4]u8, port: u16) ProbeOutcome {
    if (comptime builtin.os.tag == .windows) {
        return tcpConnectWinsock(ip, port, CONNECT_TIMEOUT_MS);
    }
    return tcpConnectTimeout(ip, port, CONNECT_TIMEOUT_MS);
}

/// Connect to ip:port, waiting at most timeout_ms. This is the
/// port-scan verdict ("is this port open?"): only open matters, while
/// refused and filtered both mean "not open" and stay silent in the
/// scan output.
pub fn tcpConnectPort(ip: [4]u8, port: u16, timeout_ms: c_int) ProbeOutcome {
    if (comptime builtin.os.tag == .windows) {
        return tcpConnectWinsock(ip, port, timeout_ms);
    }
    return tcpConnectTimeout(ip, port, timeout_ms);
}

/// Windows connect with our own timeout, via the C Winsock helper.
/// The address is formatted on the stack: dotted IPv4 is at most 15
/// characters plus the terminator.
fn tcpConnectWinsock(ip: [4]u8, port: u16, timeout_ms: c_int) ProbeOutcome {
    var addr_buf: [16]u8 = undefined;
    const addr = std.fmt.bufPrintZ(&addr_buf, "{d}.{d}.{d}.{d}", .{
        ip[0], ip[1], ip[2], ip[3],
    }) catch return .filtered;
    return switch (c_bindings.tcpProbe(addr, port, timeout_ms)) {
        .open => .open,
        .refused => .refused,
        .filtered => .filtered,
    };
}

/// POSIX connect with our own timeout. A blocking connect to a dead
/// host stalls ~75s in SYN retransmits -- so: non-blocking socket,
/// connect, poll for writable. Classic man-page recipe, one step at
/// a time.
fn tcpConnectTimeout(ip: [4]u8, port: u16, timeout_ms: c_int) ProbeOutcome {
    const fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
    if (fd < 0) return .filtered;
    defer _ = std.c.close(fd);

    const raw_flags = std.c.fcntl(fd, std.posix.F.GETFL, @as(c_int, 0));
    if (raw_flags < 0) return .filtered;
    // O_NONBLOCK lives in a packed bit struct on macOS, so flip the bit
    // through an integer round-trip.
    var oflags: std.posix.O = @bitCast(@as(u32, @bitCast(raw_flags)));
    oflags.NONBLOCK = true;
    if (std.c.fcntl(fd, std.posix.F.SETFL, @as(u32, @bitCast(oflags))) < 0) return .filtered;

    var addr = std.posix.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        // @bitCast copies the bytes as-is, which is exactly the network
        // byte order sockaddr expects.
        .addr = @bitCast(ip),
    };
    const addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(addr));
    if (std.c.connect(fd, @ptrCast(&addr), addr_len) == 0) return .open;

    // Connection in progress (or already refused): wait until the socket
    // turns writable, but no longer than our timeout.
    var pfd = [_]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.OUT,
        .revents = 0,
    }};
    if (std.c.poll(&pfd, 1, timeout_ms) <= 0) return .filtered;

    // Writable: ask the socket what actually happened.
    var so_error: c_int = 0;
    var opt_len: std.posix.socklen_t = @sizeOf(c_int);
    if (std.c.getsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.ERROR, @ptrCast(&so_error), &opt_len) != 0) {
        return .filtered;
    }
    return switch (so_error) {
        0 => .open,
        @intFromEnum(std.posix.E.CONNREFUSED), @intFromEnum(std.posix.E.CONNRESET) => .refused,
        else => .filtered,
    };
}

// ---------------------------------------------------------------------------
// Port scanning: try every TCP port in a range on one IP.
// ---------------------------------------------------------------------------

/// Scan start_port..end_port (inclusive) on one IP and return the
/// open ports, sorted ascending. Callers pass start_port <= end_port
/// (the CLI swaps reversed ranges itself); anything else is
/// error.InvalidPortRange.
///
/// A fixed pool of workers pulls ports from a shared atomic counter:
/// no thread-per-port, no sleeps, no per-port stderr. Only open ports
/// print, and only when options.progress is set; closed and filtered
/// both mean "not open" and stay silent either way.
pub const ScanOptions = struct {
    /// Stream "Open port: N" lines while scanning. The CLI keeps this
    /// on for live feedback; tests turn it off, because test binaries
    /// running under `zig build test` speak the build protocol over
    /// stdout and stray writes hang the runner.
    progress: bool = true,
    /// Per-probe wait cap in milliseconds. Null selects
    /// PORT_TIMEOUT_MS. Exposed as `ns -p ... --timeout <ms>` for
    /// unusually slow networks; lower it on a fast LAN for even
    /// quicker sweeps.
    timeout_ms: ?u16 = null,
};

pub fn scanPorts(
    allocator: std.mem.Allocator,
    io: std.Io,
    ip_address: [4]u8,
    start_port: u16,
    end_port: u16,
    options: ScanOptions,
) !std.ArrayList(u16) {
    if (start_port > end_port) return error.InvalidPortRange;

    // One wait cap for every probe in this scan: the explicit
    // override when given, PORT_TIMEOUT_MS otherwise.
    const timeout_ms: c_int = if (options.timeout_ms) |t| t else PORT_TIMEOUT_MS;

    if (start_port == end_port) {
        // One port needs no pool: probe it directly instead of
        // spawning a worker thread for a single connect.
        var open_ports: std.ArrayList(u16) = .empty;
        errdefer open_ports.deinit(allocator);
        if (tcpConnectPort(ip_address, start_port, timeout_ms) == .open) {
            if (options.progress) {
                var stdout_mutex: std.Io.Mutex = .init;
                utils.printStdout(io, &stdout_mutex, "Open port: {}\n", .{start_port});
            }
            try open_ports.append(allocator, start_port);
        }
        return open_ports;
    }

    var open_ports: std.ArrayList(u16) = .empty;
    errdefer open_ports.deinit(allocator);

    // Ports complete out of order, so the final list is sorted before
    // it goes back to the caller (see u16LessThan below).
    var ports_mutex: std.Io.Mutex = .init;
    var stdout_mutex: std.Io.Mutex = .init;
    var next_port: std.atomic.Value(u32) = .init(start_port);
    const end: u32 = end_port;

    const total: usize = @as(usize, end_port) - start_port + 1;
    const worker_count: usize = @min(total, MAX_PORT_THREADS);

    var threads: std.ArrayList(Thread) = .empty;
    // Error path only: if a spawn fails halfway, wait for whatever
    // started before returning the error. The success path joins
    // explicitly below.
    errdefer {
        for (threads.items) |t| t.join();
        threads.deinit(allocator);
    }
    // Pre-size the thread list so a full 65k scan cannot fail halfway
    // with an append error after workers already started.
    try threads.ensureTotalCapacity(allocator, worker_count);

    const shares = PortShares{
        .io = io,
        .ip = ip_address,
        .end = end,
        .allocator = allocator,
        .next_port = &next_port,
        .open_ports = &open_ports,
        .ports_mutex = &ports_mutex,
        .stdout_mutex = &stdout_mutex,
        .progress = options.progress,
        .timeout_ms = timeout_ms,
    };
    for (0..worker_count) |_| {
        const t = try Thread.spawn(.{}, portWorker, .{shares});
        threads.appendAssumeCapacity(t);
    }
    // Success path: wait for every worker, release the handle list,
    // sort what they found, and hand ownership to the caller. (The
    // errdefers above only fire if we return an error.)
    for (threads.items) |t| t.join();
    threads.deinit(allocator);

    std.mem.sort(u16, open_ports.items, {}, u16LessThan);
    return open_ports;
}

fn u16LessThan(_: void, a: u16, b: u16) bool {
    return a < b;
}

/// State shared by every port-scan worker. Lives on the caller's
/// stack; holds nothing but plain values and pointers, so passing it
/// to threads by value is safe. All workers are joined before the
/// scan returns.
const PortShares = struct {
    io: std.Io,
    ip: [4]u8,
    end: u32,
    allocator: std.mem.Allocator,
    next_port: *std.atomic.Value(u32),
    open_ports: *std.ArrayList(u16),
    ports_mutex: *std.Io.Mutex,
    stdout_mutex: *std.Io.Mutex,
    progress: bool,
    timeout_ms: c_int,
};

/// Pull the next port until the range is exhausted. Only open ports
/// are recorded; closed (refused) and filtered (timeout) both mean
/// "not open" and stay silent, which also keeps large filtered ranges
/// from drowning in per-port stderr lines.
fn portWorker(shares: PortShares) void {
    while (true) {
        const port_num = shares.next_port.fetchAdd(1, .monotonic);
        if (port_num > shares.end) break;
        const port: u16 = @intCast(port_num);
        if (tcpConnectPort(shares.ip, port, shares.timeout_ms) != .open) continue;
        if (shares.progress) {
            utils.printStdout(shares.io, shares.stdout_mutex, "Open port: {}\n", .{port});
        }
        shares.ports_mutex.lockUncancelable(shares.io);
        defer shares.ports_mutex.unlock(shares.io);
        shares.open_ports.append(shares.allocator, port) catch |err| {
            std.debug.print("Error appending port {}: {}\n", .{ port, err });
        };
    }
}

// ---------------------------------------------------------------------------
// Host discovery: a fixed pool of workers, each pulling the next IP
// from a shared index. The ping fallback (scanNetworkPing) does not
// use this machinery; it batches child processes instead.
// ---------------------------------------------------------------------------

/// State shared by every worker of a discovery sweep. It lives on the
/// caller's stack and holds nothing but pointers plus plain values, so
/// passing it to threads by value is safe. All threads are joined
/// before the sweep returns.
const Discovery = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stdout_mutex: *std.Io.Mutex,
    found: *std.ArrayList([4]u8),
    found_mutex: *std.Io.Mutex,
    ip_mac_map: *std.AutoHashMap([4]u8, [6]u8),
    ip_mac_mutex: *std.Io.Mutex,

    /// Record a host as found and print it. The suffix tags how it was
    /// found, e.g. " (arp)" for ARP-harvested hosts, "" otherwise.
    fn reportHost(self: Discovery, ip: [4]u8, comptime suffix: []const u8) void {
        self.found_mutex.lockUncancelable(self.io);
        defer self.found_mutex.unlock(self.io);
        self.found.append(self.allocator, ip) catch return;
        utils.printStdout(self.io, self.stdout_mutex, "Host {d}.{d}.{d}.{d} is online" ++ suffix ++ "\n", .{
            ip[0], ip[1], ip[2], ip[3],
        });
    }

    fn isFound(self: Discovery, ip: [4]u8) bool {
        self.found_mutex.lockUncancelable(self.io);
        defer self.found_mutex.unlock(self.io);
        for (self.found.items) |known| {
            if (std.mem.eql(u8, &known, &ip)) return true;
        }
        return false;
    }

    fn recordMac(self: Discovery, ip: [4]u8, mac: [6]u8) void {
        self.ip_mac_mutex.lockUncancelable(self.io);
        defer self.ip_mac_mutex.unlock(self.io);
        self.ip_mac_map.put(ip, mac) catch return;
    }
};

/// Run the TCP probe once per IP in the list and wait for every
/// worker before returning. A fixed pool pulls indexes from a shared
/// atomic counter, so a /16 needs only MAX_TCP_THREADS threads
/// instead of one per IP.
fn sweepHosts(
    allocator: std.mem.Allocator,
    shares: Discovery,
    ips: []const [4]u8,
) void {
    if (ips.len == 0) return;
    const worker_count: usize = @min(ips.len, MAX_TCP_THREADS);

    var next: std.atomic.Value(usize) = .init(0);
    const SweepShares = struct {
        base: Discovery,
        ips: []const [4]u8,
        next: *std.atomic.Value(usize),
    };
    const sweep = SweepShares{
        .base = shares,
        .ips = ips,
        .next = &next,
    };
    const sweepWorker = struct {
        fn run(s: SweepShares) void {
            while (true) {
                const i = s.next.fetchAdd(1, .monotonic);
                if (i >= s.ips.len) break;
                tcpWorker(s.base, s.ips[i]);
            }
        }
    }.run;

    var threads: std.ArrayList(Thread) = .empty;
    defer {
        for (threads.items) |t| t.join();
        threads.deinit(allocator);
    }
    threads.ensureTotalCapacity(allocator, worker_count) catch return;
    for (0..worker_count) |_| {
        const handle = Thread.spawn(.{}, sweepWorker, .{sweep}) catch |err| {
            std.debug.print("SpawnError: {}\n", .{err});
            break;
        };
        threads.append(allocator, handle) catch |err| {
            std.debug.print("Error tracking thread: {}\n", .{err});
            handle.join();
            break;
        };
    }
}

/// Print the closing recap: every found host sorted numerically, then
/// a one-line count plus elapsed time. The streaming "is online" lines
/// stay as live progress; this block is the diffable record, so it
/// takes the lock once for the whole block instead of per line.
fn printSummary(io: std.Io, stdout_mutex: *std.Io.Mutex, found: [][4]u8, elapsed_ns: i96) void {
    std.mem.sort([4]u8, found, {}, ipLessThan);

    const seconds = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
    const noun: []const u8 = if (found.len == 1) "host" else "hosts";

    stdout_mutex.lockUncancelable(io);
    defer stdout_mutex.unlock(io);
    var buf: [1024]u8 = undefined;
    var writer: std.Io.File.Writer = .init(.stdout(), io, &buf);
    const out = &writer.interface;
    for (found) |ip| {
        out.print("{d}.{d}.{d}.{d}\n", .{ ip[0], ip[1], ip[2], ip[3] }) catch return;
        out.flush() catch return;
    }
    out.print("{d} {s} up ({d:.1}s)\n", .{ found.len, noun, seconds }) catch {};
    out.flush() catch {};
}

pub const HostDetail = struct {
    ip: [4]u8,
    hostname: ?[]const u8 = null,
    mac: ?[6]u8 = null,
    vendor: ?[]const u8 = null,
};

fn printDetailedSummary(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout_mutex: *std.Io.Mutex,
    found: [][4]u8,
    ip_mac_map: *std.AutoHashMap([4]u8, [6]u8),
    options: NetworkScanOptions,
    elapsed_ns: i96,
) void {
    std.mem.sort([4]u8, found, {}, ipLessThan);

    // Initialize OUI database at function scope so custom vendor strings stay alive through printing.
    var oui_db = oui.OuiDatabase.init(allocator);
    defer oui_db.deinit();

    var details = allocator.alloc(HostDetail, found.len) catch return;
    // Pre-initialize fields to safe defaults (null pointers) immediately upon allocation.
    // This ensures the defer cleanup block never reads uninitialized pointers if an early
    // exit or panic occurs while populating host details.
    for (details) |*d| {
        d.* = .{
            .ip = undefined,
            .mac = null,
            .hostname = null,
            .vendor = null,
        };
    }
    defer {
        for (details) |d| {
            if (d.hostname) |h| allocator.free(h);
        }
        allocator.free(details);
    }

    for (found, 0..) |ip, i| {
        var mac = ip_mac_map.get(ip);
        // Fall back to SendARP on Windows for any missing MAC addresses (e.g. localhost)
        // when vendor resolution is requested.
        if (mac == null and options.resolve_vendor) {
            var ip_buf: [16]u8 = undefined;
            if (std.fmt.bufPrintZ(&ip_buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] })) |ip_str| {
                mac = c_bindings.getMacSendArp(ip_str.ptr);
            } else |_| {}
        }
        details[i] = HostDetail{
            .ip = ip,
            .mac = mac,
        };
    }

    // Resolve vendors if requested
    if (options.resolve_vendor) {
        if (options.oui_file) |fpath| {
            oui_db.loadFile(fpath) catch |err| {
                std.debug.print("warning: failed to load oui file '{s}': {}\n", .{ fpath, err });
            };
        }
        for (details) |*d| {
            if (d.mac) |mac| {
                d.vendor = oui_db.lookup(mac);
            }
        }
    }

    // Resolve hostnames in parallel if requested
    if (options.resolve_hostname and details.len > 0) {
        const Job = struct {
            allocator: std.mem.Allocator,
            details: []HostDetail,
            next: *std.atomic.Value(usize),
        };
        var next_idx: std.atomic.Value(usize) = .init(0);
        const job = Job{
            .allocator = allocator,
            .details = details,
            .next = &next_idx,
        };
        const worker = struct {
            fn run(j: Job) void {
                while (true) {
                    const idx = j.next.fetchAdd(1, .monotonic);
                    if (idx >= j.details.len) break;
                    j.details[idx].hostname = resolver.resolveHostName(j.allocator, j.details[idx].ip);
                }
            }
        }.run;

        const worker_count = @min(details.len, 16);
        var threads: std.ArrayList(Thread) = .empty;
        defer {
            for (threads.items) |t| t.join();
            threads.deinit(allocator);
        }
        for (0..worker_count) |_| {
            if (Thread.spawn(.{}, worker, .{job})) |t| {
                threads.append(allocator, t) catch {
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

    const seconds = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
    const noun: []const u8 = if (details.len == 1) "host" else "hosts";

    stdout_mutex.lockUncancelable(io);
    defer stdout_mutex.unlock(io);
    var buf: [2048]u8 = undefined;
    var writer: std.Io.File.Writer = .init(.stdout(), io, &buf);
    const out = &writer.interface;

    var ip_str_buf: [16]u8 = undefined;
    var mac_str_buf: [17]u8 = undefined;

    if (details.len > 0) {
        if (options.resolve_hostname and options.resolve_vendor) {
            out.print("{s: <17}{s: <26}{s: <19}{s}\n", .{ "IP", "HOSTNAME", "MAC", "MANUFACTURER" }) catch return;
            for (details) |d| {
                const ip_str = std.fmt.bufPrint(&ip_str_buf, "{d}.{d}.{d}.{d}", .{ d.ip[0], d.ip[1], d.ip[2], d.ip[3] }) catch "";
                const h_str = d.hostname orelse "-";
                const mac_str = if (d.mac) |m| utils.formatMac(&mac_str_buf, m) else "-";
                const v_str = d.vendor orelse "-";
                out.print("{s: <17}{s: <26}{s: <19}{s}\n", .{ ip_str, h_str, mac_str, v_str }) catch return;
                out.flush() catch return;
            }
        } else if (options.resolve_hostname) {
            out.print("{s: <17}{s}\n", .{ "IP", "HOSTNAME" }) catch return;
            for (details) |d| {
                const ip_str = std.fmt.bufPrint(&ip_str_buf, "{d}.{d}.{d}.{d}", .{ d.ip[0], d.ip[1], d.ip[2], d.ip[3] }) catch "";
                const h_str = d.hostname orelse "-";
                out.print("{s: <17}{s}\n", .{ ip_str, h_str }) catch return;
                out.flush() catch return;
            }
        } else if (options.resolve_vendor) {
            out.print("{s: <17}{s: <19}{s}\n", .{ "IP", "MAC", "MANUFACTURER" }) catch return;
            for (details) |d| {
                const ip_str = std.fmt.bufPrint(&ip_str_buf, "{d}.{d}.{d}.{d}", .{ d.ip[0], d.ip[1], d.ip[2], d.ip[3] }) catch "";
                const mac_str = if (d.mac) |m| utils.formatMac(&mac_str_buf, m) else "-";
                const v_str = d.vendor orelse "-";
                out.print("{s: <17}{s: <19}{s}\n", .{ ip_str, mac_str, v_str }) catch return;
                out.flush() catch return;
            }
        }
    }

    out.print("{d} {s} up ({d:.1}s)\n", .{ details.len, noun, seconds }) catch {};
    out.flush() catch {};
}

fn ipLessThan(_: void, a: [4]u8, b: [4]u8) bool {
    return utils.ipToU32(a) < utils.ipToU32(b);
}

/// Print the one-line header every network scan starts with.
fn printScanHeader(io: std.Io, stdout_mutex: *std.Io.Mutex, cidr: []const u8, range: utils.IpRange) void {
    utils.printStdout(io, stdout_mutex, "Scanning network: {s} (Range: {d}.{d}.{d}.{d} - {d}.{d}.{d}.{d})\n", .{
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

/// Ping every IP in the list with one child process each, all running
/// concurrently. Returns which hosts answered, same order as input.
/// Caller frees the result.
///
/// One batch instead of one process per thread: libc serializes
/// concurrent system() calls process-wide, which used to turn every
/// ping sweep serial (~2s/host). posix-spawned children have no such
/// lock, so a whole subnet resolves in about one wait each.
///
/// The command line differs per OS: POSIX ping takes -c/-W/-q while
/// Windows ping takes -n/-w (milliseconds) and has no quiet flag.
fn pingSweep(allocator: std.mem.Allocator, io: std.Io, ips: []const [4]u8) ![]bool {
    const alive = try allocator.alloc(bool, ips.len);
    errdefer allocator.free(alive);

    const ip_strings = try allocator.alloc([]const u8, ips.len);
    defer {
        for (ip_strings) |s| allocator.free(s);
        allocator.free(ip_strings);
    }
    for (ips, 0..) |ip, i| {
        ip_strings[i] = try utils.ipBytesToString(allocator, ip);
    }

    var children: std.ArrayList(std.process.Child) = .empty;
    defer children.deinit(allocator);
    for (ip_strings) |ip_string| {
        var argv: [7][]const u8 = undefined;
        const argc: usize = if (comptime builtin.os.tag == .windows) blk: {
            argv[0..6].* = [_][]const u8{ "ping", "-n", "1", "-w", "1000", ip_string };
            break :blk 6;
        } else blk: {
            // ping(1) -W units: milliseconds on macOS, seconds elsewhere --
            // both spell ~1s. Matches the WARNING in src/c/ping.c.
            const wait_arg: []const u8 = if (comptime builtin.os.tag == .macos) "1000" else "1";
            argv[0..7].* = [_][]const u8{ "ping", "-c", "1", "-W", wait_arg, "-q", ip_string };
            break :blk 7;
        };
        const child = try std.process.spawn(io, .{
            .argv = argv[0..argc],
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        });
        try children.append(allocator, child);
    }

    for (children.items, 0..) |*child, i| {
        const term = child.wait(io) catch {
            alive[i] = false;
            continue;
        };
        alive[i] = switch (term) {
            .exited => |code| code == 0,
            else => false,
        };
    }
    return alive;
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
    printScanHeader(io, &stdout_mutex, cidr, ip_range);
    const started = std.Io.Clock.now(.awake, io);

    // Single-threaded from here: one batch, then report. No locks needed
    // beyond the printer's own mutex.
    const hosts = utils.usableHosts(network, ip_range);
    var targets = try utils.collectIps(allocator, hosts.start, hosts.end);
    defer targets.deinit(allocator);

    const alive = try pingSweep(allocator, io, targets.items);
    defer allocator.free(alive);

    var found: std.ArrayList([4]u8) = .empty;
    defer found.deinit(allocator);
    for (targets.items, alive) |ip, is_up| {
        if (!is_up) continue;
        found.append(allocator, ip) catch continue;
        utils.printStdout(io, &stdout_mutex, "Host {d}.{d}.{d}.{d} is online\n", .{
            ip[0], ip[1], ip[2], ip[3],
        });
    }

    var ip_mac_map = std.AutoHashMap([4]u8, [6]u8).init(allocator);
    defer ip_mac_map.deinit();

    if (dumpArpTable(allocator, io)) |table| {
        defer allocator.free(table);
        var lines = std.mem.splitScalar(u8, table, '\n');
        while (lines.next()) |line| {
            const entry = utils.parseArpEntry(line) orelse continue;
            if (entry.mac) |mac| {
                ip_mac_map.put(entry.ip, mac) catch continue;
            }
        }
    }

    const elapsed = started.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds;
    if (options.resolve_hostname or options.resolve_vendor) {
        printDetailedSummary(allocator, io, &stdout_mutex, found.items, &ip_mac_map, options, elapsed);
    } else {
        printSummary(io, &stdout_mutex, found.items, elapsed);
    }
}

/// Ping one host through the C helper. Returns true when it answers.
/// Anything the ping cannot even attempt (bad address, no memory)
/// counts as unanswered rather than as an error. On Windows a failed
/// ping also logs the Winsock error, so silent misses stay diagnosable.
pub fn pingHost(allocator: std.mem.Allocator, ip: [4]u8) bool {
    const ip_string = utils.ipBytesToString(allocator, ip) catch return false;
    defer allocator.free(ip_string);

    const ip_with_null = allocator.dupeZ(u8, ip_string) catch return false;
    defer allocator.free(ip_with_null);

    const ok = c_bindings.pingHost(ip_with_null.ptr);
    if (!ok) {
        const err = c_bindings.pingLastError();
        if (err != 0) std.debug.print("ping {s} failed: Winsock error {d}\n", .{ ip_string, err });
    }
    return ok;
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
    printScanHeader(io, &stdout_mutex, cidr, ip_range);
    const started = std.Io.Clock.now(.awake, io);

    const hosts = utils.usableHosts(network, ip_range);

    var found: std.ArrayList([4]u8) = .empty;
    defer found.deinit(allocator);
    var found_mutex: std.Io.Mutex = .init;
    var ip_mac_map = std.AutoHashMap([4]u8, [6]u8).init(allocator);
    defer ip_mac_map.deinit();
    var ip_mac_mutex: std.Io.Mutex = .init;

    const shares = Discovery{
        .io = io,
        .allocator = allocator,
        .stdout_mutex = &stdout_mutex,
        .found = &found,
        .found_mutex = &found_mutex,
        .ip_mac_map = &ip_mac_map,
        .ip_mac_mutex = &ip_mac_mutex,
    };
    var targets = try utils.collectIps(allocator, hosts.start, hosts.end);
    defer targets.deinit(allocator);
    sweepHosts(allocator, shares, targets.items);

    harvestArp(shares, hosts.start, hosts.end);

    const elapsed = started.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds;
    if (options.resolve_hostname or options.resolve_vendor) {
        printDetailedSummary(allocator, io, &stdout_mutex, found.items, &ip_mac_map, options, elapsed);
    } else {
        printSummary(io, &stdout_mutex, found.items, elapsed);
    }
}

fn tcpWorker(shares: Discovery, ip: [4]u8) void {
    if (tcpProbe(ip)) shares.reportHost(ip, "");
}

/// Returns true when the host answers on the probe port or actively
/// refuses the connection. Both prove a host is there; only a timeout
/// (or unreachable network) means "no answer".
fn tcpProbe(ip: [4]u8) bool {
    return switch (tcpConnect(ip, TCP_PROBE_PORT)) {
        .open, .refused => true,
        .filtered => false,
    };
}

/// Read the local ARP table for in-range hosts the TCP sweep missed,
/// then ping each candidate once before reporting it. The ping matters:
/// entries linger up to ~20min after a host leaves, so a complete entry
/// alone is not proof. Needs no privileges; `arp -a` exists on macOS,
/// Linux and Windows, and all three table formats are parsed.
fn harvestArp(shares: Discovery, first_ip: [4]u8, last_ip: [4]u8) void {
    const table = dumpArpTable(shares.allocator, shares.io) orelse return;
    defer shares.allocator.free(table);

    var candidates: std.ArrayList([4]u8) = .empty;
    defer candidates.deinit(shares.allocator);
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
            shares.reportHost(entry.ip, " (arp)");
            continue;
        }

        candidates.append(shares.allocator, entry.ip) catch continue;
    }
    if (candidates.items.len == 0) return;

    // One batch for all candidates: only hosts that answer get the
    // "(arp)" report.
    const alive = pingSweep(shares.allocator, shares.io, candidates.items) catch return;
    defer shares.allocator.free(alive);
    var unconfirmed: std.ArrayList([4]u8) = .empty;
    defer unconfirmed.deinit(shares.allocator);

    for (candidates.items, alive) |ip, is_up| {
        if (is_up) {
            shares.reportHost(ip, " (arp)");
        } else {
            unconfirmed.append(shares.allocator, ip) catch continue;
        }
    }

    if (unconfirmed.items.len == 0) return;

    // For unconfirmed candidates that dropped ICMP ping (e.g. firewalled IoT,
    // GL.iNet, TP-Link smart plugs), verify live Layer 2 presence via SendARP on Windows.
    if (comptime builtin.os.tag == .windows) {
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
            fn run(j: ArpJob) void {
                while (true) {
                    const idx = j.next.fetchAdd(1, .monotonic);
                    if (idx >= j.targets.len) break;
                    const ip = j.targets[idx];
                    var ip_buf: [16]u8 = undefined;
                    const ip_str = std.fmt.bufPrintZ(&ip_buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch continue;
                    if (c_bindings.getMacSendArp(ip_str.ptr)) |mac| {
                        j.shares.recordMac(ip, mac);
                        j.shares.reportHost(ip, " (arp)");
                    }
                }
            }
        }.run;

        const worker_count = @min(unconfirmed.items.len, 8);
        var threads: std.ArrayList(Thread) = .empty;
        defer {
            for (threads.items) |t| t.join();
            threads.deinit(shares.allocator);
        }
        for (0..worker_count) |_| {
            if (Thread.spawn(.{}, arp_worker, .{job})) |t| {
                threads.append(shares.allocator, t) catch {
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
