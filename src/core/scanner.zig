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

/// How many ports to probe at once.
const MAX_PORT_THREADS = 100;
/// How many ping processes to run at once.
const MAX_PING_THREADS = 15;
/// How many TCP probes to run at once.
const MAX_TCP_THREADS = 128;
/// Cap for one TCP connect attempt, in milliseconds. Bounds discovery
/// probes and port scans alike, so filtered hosts cost little.
const CONNECT_TIMEOUT_MS = 500;

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
/// Zig 0.16 implements no connect timeout itself, hence the hand-rolled
/// one below (POSIX) and the plain blocking fallback (Windows).
pub fn tcpConnect(io: std.Io, ip: [4]u8, port: u16) ProbeOutcome {
    if (comptime builtin.os.tag == .windows) {
        return tcpConnectBlocking(io, ip, port);
    }
    return tcpConnectTimeout(ip, port);
}

fn tcpConnectBlocking(io: std.Io, ip: [4]u8, port: u16) ProbeOutcome {
    const addr = std.Io.net.IpAddress{ .ip4 = .{ .bytes = ip, .port = port } };
    var stream = addr.connect(io, .{
        .mode = .stream,
        .protocol = .tcp,
        .timeout = .none,
    }) catch |err| {
        return if (err == error.ConnectionRefused or err == error.ConnectionResetByPeer)
            .refused
        else
            .filtered;
    };
    defer stream.close(io);
    return .open;
}

/// POSIX connect with our own timeout. A blocking connect to a dead
/// host stalls ~75s in SYN retransmits -- so: non-blocking socket,
/// connect, poll for writable. Classic man-page recipe, one step at
/// a time.
fn tcpConnectTimeout(ip: [4]u8, port: u16) ProbeOutcome {
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
    if (std.c.poll(&pfd, 1, CONNECT_TIMEOUT_MS) <= 0) return .filtered;

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

pub fn scanPorts(
    allocator: std.mem.Allocator,
    io: std.Io,
    ip_address: [4]u8,
    start_port: u16,
    end_port: u16,
) !std.ArrayList(u16) {
    var open_ports: std.ArrayList(u16) = .empty;
    errdefer open_ports.deinit(allocator);

    var ports_mutex: std.Io.Mutex = .init;
    var stdout_mutex: std.Io.Mutex = .init;
    var sem: std.Io.Semaphore = .{ .permits = MAX_PORT_THREADS };

    var threads: std.ArrayList(Thread) = .empty;
    errdefer {
        for (threads.items) |t| t.join();
        threads.deinit(allocator);
    }

    var port: u16 = start_port;
    while (true) {
        // Port 137 (NetBIOS) is skipped: it is noisy and commonly
        // filtered, so probing it adds time without information.
        if (port == 137) {
            if (port == end_port) break;
            port += 1;
            continue;
        }
        sem.waitUncancelable(io);
        const ctx = PortScanCtx{
            .io = io,
            .ip = ip_address,
            .port = port,
            .allocator = allocator,
            .open_ports = &open_ports,
            .ports_mutex = &ports_mutex,
            .stdout_mutex = &stdout_mutex,
            .sem = &sem,
        };
        const t = Thread.spawn(.{}, checkPortWorker, .{ctx}) catch |err| {
            std.debug.print("SpawnError: {}\n", .{err});
            sem.post(io);
            if (port == end_port or port == 65535) break;
            port += 1;
            continue;
        };
        threads.append(allocator, t) catch |err| {
            std.debug.print("Error tracking thread: {}\n", .{err});
            // Thread is already running; detach is not available here, join it now.
            t.join();
            sem.post(io);
        };
        // Ports are u16: stop explicitly at the top instead of wrapping to 0.
        if (port == end_port or port == 65535) break;
        port += 1;
    }

    // Join all spawned threads before returning the list.
    for (threads.items) |t| t.join();
    threads.deinit(allocator);

    return open_ports;
}

const PortScanCtx = struct {
    io: std.Io,
    ip: [4]u8,
    port: u16,
    allocator: std.mem.Allocator,
    open_ports: *std.ArrayList(u16),
    ports_mutex: *std.Io.Mutex,
    stdout_mutex: *std.Io.Mutex,
    sem: *std.Io.Semaphore,
};

fn checkPortWorker(ctx: PortScanCtx) void {
    defer ctx.sem.post(ctx.io);
    checkPort(ctx);
}

fn checkPort(ctx: PortScanCtx) void {
    const io = ctx.io;
    // Small throttle to avoid overwhelming the target.
    io.sleep(.{ .nanoseconds = 5 * std.time.ns_per_ms }, .awake) catch {};

    switch (tcpConnect(io, ctx.ip, ctx.port)) {
        .open => {
            utils.printStdout(io, ctx.stdout_mutex, "Open port: {}\n", .{ctx.port});
            ctx.ports_mutex.lockUncancelable(io);
            defer ctx.ports_mutex.unlock(io);
            ctx.open_ports.append(ctx.allocator, ctx.port) catch |err| {
                std.debug.print("Error appending port {}: {}\n", .{ ctx.port, err });
            };
        },
        // Closed port: expected, stay quiet.
        .refused => {},
        // Unreachable or filtered: one stderr line, then move on.
        .filtered => std.debug.print("Port {d}: no answer (filtered?)\n", .{ctx.port}),
    }
}

// ---------------------------------------------------------------------------
// Host discovery: one worker thread per IP, capped by a semaphore.
// Both sweeps (fast TCP and fallback ping) share this machinery and only
// differ in their worker function.
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
    sem: *std.Io.Semaphore,

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
};

/// Run `worker` once per IP in the list, capped by the semaphore in
/// shares, and wait for every thread before returning.
fn sweepHosts(
    allocator: std.mem.Allocator,
    shares: Discovery,
    ips: []const [4]u8,
    comptime worker: fn (Discovery, [4]u8) void,
) void {
    var threads: std.ArrayList(Thread) = .empty;
    defer {
        for (threads.items) |t| t.join();
        threads.deinit(allocator);
    }

    for (ips) |ip| {
        shares.sem.waitUncancelable(shares.io);
        const handle = Thread.spawn(.{}, worker, .{ shares, ip }) catch |err| {
            std.debug.print("SpawnError: {}\n", .{err});
            shares.sem.post(shares.io);
            continue;
        };
        threads.append(allocator, handle) catch |err| {
            std.debug.print("Error tracking thread: {}\n", .{err});
            handle.join();
            shares.sem.post(shares.io);
        };
    }
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

/// Slow path: one ICMP ping process per host. Kept as a fallback for
/// networks where TCP probing is filtered; prefer scanNetwork.
pub fn scanNetworkPing(allocator: std.mem.Allocator, io: std.Io, cidr: []const u8) !void {
    const network = try utils.parseCidr(cidr);
    const ip_range = try utils.getIpRange(network);

    var stdout_mutex: std.Io.Mutex = .init;
    printScanHeader(io, &stdout_mutex, cidr, ip_range);

    var sem: std.Io.Semaphore = .{ .permits = MAX_PING_THREADS };
    var found: std.ArrayList([4]u8) = .empty;
    defer found.deinit(allocator);
    var found_mutex: std.Io.Mutex = .init;
    const shares = Discovery{
        .io = io,
        .allocator = allocator,
        .stdout_mutex = &stdout_mutex,
        .found = &found,
        .found_mutex = &found_mutex,
        .sem = &sem,
    };

    const hosts = utils.usableHosts(network, ip_range);
    var targets = try utils.collectIps(allocator, hosts.start, hosts.end);
    defer targets.deinit(allocator);
    sweepHosts(allocator, shares, targets.items, pingWorker);
}

fn pingWorker(shares: Discovery, ip: [4]u8) void {
    defer shares.sem.post(shares.io);
    if (pingHost(shares.allocator, ip)) shares.reportHost(ip, "");
}

/// Ping one host through the C helper. Returns true when it answers.
/// Anything the ping cannot even attempt (bad address, no memory)
/// counts as unanswered rather than as an error.
pub fn pingHost(allocator: std.mem.Allocator, ip: [4]u8) bool {
    const ip_string = utils.ipBytesToString(allocator, ip) catch return false;
    defer allocator.free(ip_string);

    const ip_with_null = allocator.dupeZ(u8, ip_string) catch return false;
    defer allocator.free(ip_with_null);

    return c_bindings.pingHost(ip_with_null.ptr);
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
pub fn scanNetwork(allocator: std.mem.Allocator, io: std.Io, cidr: []const u8) !void {
    const network = try utils.parseCidr(cidr);
    const ip_range = try utils.getIpRange(network);

    var stdout_mutex: std.Io.Mutex = .init;
    printScanHeader(io, &stdout_mutex, cidr, ip_range);

    const hosts = utils.usableHosts(network, ip_range);

    var sem: std.Io.Semaphore = .{ .permits = MAX_TCP_THREADS };
    var found: std.ArrayList([4]u8) = .empty;
    defer found.deinit(allocator);
    var found_mutex: std.Io.Mutex = .init;
    const shares = Discovery{
        .io = io,
        .allocator = allocator,
        .stdout_mutex = &stdout_mutex,
        .found = &found,
        .found_mutex = &found_mutex,
        .sem = &sem,
    };
    var targets = try utils.collectIps(allocator, hosts.start, hosts.end);
    defer targets.deinit(allocator);
    sweepHosts(allocator, shares, targets.items, tcpWorker);

    harvestArp(shares, hosts.start, hosts.end);
}

fn tcpWorker(shares: Discovery, ip: [4]u8) void {
    defer shares.sem.post(shares.io);
    if (tcpProbe(shares.io, ip)) shares.reportHost(ip, "");
}

/// Returns true when the host answers on the probe port or actively
/// refuses the connection. Both prove a host is there; only a timeout
/// (or unreachable network) means "no answer".
fn tcpProbe(io: std.Io, ip: [4]u8) bool {
    return switch (tcpConnect(io, ip, TCP_PROBE_PORT)) {
        .open, .refused => true,
        .filtered => false,
    };
}

/// Read the local ARP table for in-range hosts the TCP sweep missed,
/// then ping each candidate once before reporting it. The ping matters:
/// entries linger up to ~20min after a host leaves, so a complete entry
/// alone is not proof. Needs no privileges; `arp -a` exists on macOS,
/// Linux and Windows (only the first two formats are parsed for now).
fn harvestArp(shares: Discovery, first_ip: [4]u8, last_ip: [4]u8) void {
    const table = readArpTable(shares) orelse return;
    defer shares.allocator.free(table);

    var candidates: std.ArrayList([4]u8) = .empty;
    defer candidates.deinit(shares.allocator);
    var lines = std.mem.splitScalar(u8, table, '\n');
    while (lines.next()) |line| {
        const ip = utils.parseArpLine(line) orelse continue;
        if (!utils.ipInRange(ip, first_ip, last_ip)) continue;
        if (shares.isFound(ip)) continue;
        candidates.append(shares.allocator, ip) catch continue;
    }
    if (candidates.items.len == 0) return;

    // One ping each, in parallel over the shared semaphore (all TCP
    // permits are free again by now). Only hosts that answer get the
    // "(arp)" report.
    sweepHosts(shares.allocator, shares, candidates.items, verifyWorker);
}

/// Dump the neighbour table. Prefers `arp -a`, falls back to
/// `ip neigh show` (minimal Linux distros often lack net-tools).
/// Returns the output for the caller to free, or null when neither
/// tool exists -- then discovery just ends after the TCP sweep.
fn readArpTable(shares: Discovery) ?[]u8 {
    const commands = [_][]const []const u8{
        &.{ "arp", "-a" },
        &.{ "ip", "neigh", "show" },
    };
    for (commands) |argv| {
        const result = std.process.run(shares.allocator, shares.io, .{ .argv = argv }) catch |err| {
            // Missing tool: try the next one. Anything else is a real
            // failure, so stop instead of running stranger commands.
            if (err != error.FileNotFound) {
                std.debug.print("arp harvest skipped: {}\n", .{err});
                return null;
            }
            continue;
        };
        shares.allocator.free(result.stderr);
        return result.stdout;
    }
    std.debug.print("arp harvest skipped: neither `arp` nor `ip` found\n", .{});
    return null;
}

fn verifyWorker(shares: Discovery, ip: [4]u8) void {
    defer shares.sem.post(shares.io);
    if (pingHost(shares.allocator, ip)) shares.reportHost(ip, " (arp)");
}
