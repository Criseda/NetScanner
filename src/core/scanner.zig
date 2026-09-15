const std = @import("std");
const builtin = @import("builtin");
const Thread = std.Thread;
const utils = @import("utils.zig");
const c_bindings = @import("bindings");

const MAX_THREADS = 100; // Adjust this value based on your system's capabilities
const MAX_PING_THREADS = 15;

// Scan port functionality

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
    var sem: std.Io.Semaphore = .{ .permits = MAX_THREADS };

    var threads: std.ArrayList(Thread) = .empty;
    errdefer {
        for (threads.items) |t| t.join();
        threads.deinit(allocator);
    }

    var port: u16 = start_port;
    while (true) {
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
    checkPort(ctx) catch |err| {
        std.debug.print("Error checking port {}: {}\n", .{ ctx.port, err });
    };
}

fn checkPort(ctx: PortScanCtx) !void {
    const io = ctx.io;
    // Small throttle to avoid overwhelming the target.
    io.sleep(.{ .nanoseconds = 5 * std.time.ns_per_ms }, .awake) catch {};

    const addr = std.Io.net.IpAddress{ .ip4 = .{ .bytes = ctx.ip, .port = ctx.port } };

    var stream = addr.connect(io, .{ .mode = .stream, .protocol = .tcp }) catch |err| {
        switch (err) {
            error.ConnectionRefused => return, // Expected for closed ports; stay quiet.
            error.AccessDenied => {
                std.debug.print("Access denied for port {}\n", .{ctx.port});
                return;
            },
            error.Timeout => {
                std.debug.print("Connection timed out for port {}\n", .{ctx.port});
                return;
            },
            else => {
                std.debug.print("Error connecting to port {}: {}\n", .{ ctx.port, err });
                return;
            },
        }
    };
    defer stream.close(io);

    utils.printStdout(io, ctx.stdout_mutex, "Open port: {}\n", .{ctx.port});
    ctx.ports_mutex.lockUncancelable(io);
    defer ctx.ports_mutex.unlock(io);
    ctx.open_ports.append(ctx.allocator, ctx.port) catch |err| {
        std.debug.print("Error appending port {}: {}\n", .{ ctx.port, err });
    };
}

// Network scanner functionality

pub const NetworkScanResult = struct {
    ip: []const u8,
    name: []const u8,
    manufacturer: []const u8,
    mac_address: []const u8,
};

pub fn scanNetwork(allocator: std.mem.Allocator, io: std.Io, cidr: []const u8) !void {
    const network = try utils.parseCidr(cidr);
    const ip_range = try utils.getIpRange(network);

    var stdout_mutex: std.Io.Mutex = .init;
    utils.printStdout(io, &stdout_mutex, "Scanning network: {s} (Range: {d}.{d}.{d}.{d} - {d}.{d}.{d}.{d})\n", .{
        cidr,
        ip_range.start[0],
        ip_range.start[1],
        ip_range.start[2],
        ip_range.start[3],
        ip_range.end[0],
        ip_range.end[1],
        ip_range.end[2],
        ip_range.end[3],
    });

    var threads: std.ArrayList(Thread) = .empty;
    errdefer {
        for (threads.items) |t| t.join();
        threads.deinit(allocator);
    }

    var sem: std.Io.Semaphore = .{ .permits = MAX_PING_THREADS };

    // Skip the network and broadcast addresses: they are not hosts.
    // (/31 and /32 have no such addresses, so only skip for prefix < 31.)
    var first_ip = ip_range.start;
    var last_ip = ip_range.end;
    if (network.prefix_len < 31) {
        utils.incrementIP(&first_ip);
        utils.decrementIP(&last_ip);
    }

    var current_ip = first_ip;
    while (true) {
        sem.waitUncancelable(io);
        const ctx = PingScanCtx{
            .io = io,
            .ip = current_ip,
            .allocator = allocator,
            .stdout_mutex = &stdout_mutex,
            .sem = &sem,
        };
        const handle = Thread.spawn(.{}, scanIPWorker, .{ctx}) catch |err| {
            std.debug.print("SpawnError: {}\n", .{err});
            sem.post(io);
            if (std.mem.eql(u8, &current_ip, &last_ip)) break;
            utils.incrementIP(&current_ip);
            continue;
        };
        threads.append(allocator, handle) catch |err| {
            std.debug.print("Error tracking thread: {}\n", .{err});
            handle.join();
            sem.post(io);
        };
        if (std.mem.eql(u8, &current_ip, &last_ip)) break;
        utils.incrementIP(&current_ip);
    }

    // Join all spawned threads.
    for (threads.items) |handle| {
        handle.join();
    }
    threads.deinit(allocator);
}

const PingScanCtx = struct {
    io: std.Io,
    ip: [4]u8,
    allocator: std.mem.Allocator,
    stdout_mutex: *std.Io.Mutex,
    sem: *std.Io.Semaphore,
};

fn scanIPWorker(ctx: PingScanCtx) void {
    defer ctx.sem.post(ctx.io);
    scanIP(ctx) catch |err| {
        std.debug.print("Error scanning host: {}\n", .{err});
    };
}

fn scanIP(ctx: PingScanCtx) !void {
    // Check if the IP is online using ICMP ping
    pingHost(ctx.allocator, ctx.io, ctx.stdout_mutex, ctx.ip) catch |err| {
        std.debug.print("Error pinging host: {}\n", .{err});
        return;
    };
}

pub fn pingHost(allocator: std.mem.Allocator, io: std.Io, stdout_mutex: *std.Io.Mutex, ip: [4]u8) !void {
    const ip_string = try utils.ipBytesToString(allocator, ip);
    defer allocator.free(ip_string);

    if (!std.unicode.utf8ValidateSlice(ip_string)) {
        return error.InvalidWtf8;
    }

    const ip_with_null = try allocator.dupeZ(u8, ip_string);
    defer allocator.free(ip_with_null);

    if (c_bindings.pingHost(ip_with_null.ptr)) {
        utils.printStdout(io, stdout_mutex, "Host {s} is online\n", .{ip_string});
    }
}

// ---------------------------------------------------------------------------
// Experiment 2: TCP-connect discovery + ARP harvest.
//
// Faster alternative to one-ping-process-per-host, in two steps:
//   1. TCP-connect to one common port per IP. A connect that succeeds OR is
//      actively refused (RST) proves the host is up; only a timeout means
//      "no answer". No subprocess per host, real concurrency.
//   2. Afterwards, read the `arp -a` table. Every connect attempt (even a
//      failed one) triggers ARP, and sleeping Apple devices often answer
//      ARP while ignoring ping and TCP. Anything with a complete entry
//      that step 1 missed gets printed as "(arp)".
// ---------------------------------------------------------------------------

const TCP_PROBE_PORT = 80;
const TCP_PROBE_TIMEOUT_MS = 500;
const MAX_TCP_THREADS = 128;

pub fn scanTcp(allocator: std.mem.Allocator, io: std.Io, cidr: []const u8) !void {
    const network = try utils.parseCidr(cidr);
    const ip_range = try utils.getIpRange(network);

    var stdout_mutex: std.Io.Mutex = .init;
    utils.printStdout(io, &stdout_mutex, "Scanning network: {s} (Range: {d}.{d}.{d}.{d} - {d}.{d}.{d}.{d})\n", .{
        cidr,
        ip_range.start[0],
        ip_range.start[1],
        ip_range.start[2],
        ip_range.start[3],
        ip_range.end[0],
        ip_range.end[1],
        ip_range.end[2],
        ip_range.end[3],
    });

    // Same skip rule as the ping sweep: no network/broadcast addresses.
    var first_ip = ip_range.start;
    var last_ip = ip_range.end;
    if (network.prefix_len < 31) {
        utils.incrementIP(&first_ip);
        utils.decrementIP(&last_ip);
    }

    var found: std.ArrayList([4]u8) = .empty;
    defer found.deinit(allocator);
    var found_mutex: std.Io.Mutex = .init;

    var threads: std.ArrayList(Thread) = .empty;
    errdefer {
        for (threads.items) |t| t.join();
        threads.deinit(allocator);
    }

    var sem: std.Io.Semaphore = .{ .permits = MAX_TCP_THREADS };

    var current_ip = first_ip;
    while (true) {
        sem.waitUncancelable(io);
        const ctx = TcpScanCtx{
            .io = io,
            .ip = current_ip,
            .allocator = allocator,
            .found = &found,
            .found_mutex = &found_mutex,
            .stdout_mutex = &stdout_mutex,
            .sem = &sem,
        };
        const handle = Thread.spawn(.{}, tcpProbeWorker, .{ctx}) catch |err| {
            std.debug.print("SpawnError: {}\n", .{err});
            sem.post(io);
            if (std.mem.eql(u8, &current_ip, &last_ip)) break;
            utils.incrementIP(&current_ip);
            continue;
        };
        threads.append(allocator, handle) catch |err| {
            std.debug.print("Error tracking thread: {}\n", .{err});
            handle.join();
            sem.post(io);
        };
        if (std.mem.eql(u8, &current_ip, &last_ip)) break;
        utils.incrementIP(&current_ip);
    }

    for (threads.items) |handle| {
        handle.join();
    }
    threads.deinit(allocator);

    harvestArp(allocator, io, &stdout_mutex, first_ip, last_ip, &found, &found_mutex);
}

const TcpScanCtx = struct {
    io: std.Io,
    ip: [4]u8,
    allocator: std.mem.Allocator,
    found: *std.ArrayList([4]u8),
    found_mutex: *std.Io.Mutex,
    stdout_mutex: *std.Io.Mutex,
    sem: *std.Io.Semaphore,
};

fn tcpProbeWorker(ctx: TcpScanCtx) void {
    defer ctx.sem.post(ctx.io);
    if (!tcpProbe(ctx.io, ctx.ip)) return;

    ctx.found_mutex.lockUncancelable(ctx.io);
    defer ctx.found_mutex.unlock(ctx.io);
    ctx.found.append(ctx.allocator, ctx.ip) catch return;

    utils.printStdout(ctx.io, ctx.stdout_mutex, "Host {d}.{d}.{d}.{d} is online\n", .{
        ctx.ip[0], ctx.ip[1], ctx.ip[2], ctx.ip[3],
    });
}

/// Returns true when the host answers a TCP connect (open port) or
/// actively refuses it (RST on a closed port). Both prove a host is
/// there; only a timeout (or unreachable network) means "no answer".
fn tcpProbe(io: std.Io, ip: [4]u8) bool {
    // Windows keeps the plain blocking connect for now.
    if (comptime builtin.os.tag == .windows) {
        return tcpProbeBlocking(io, ip);
    }
    return tcpProbeTimeout(ip);
}

fn tcpProbeBlocking(io: std.Io, ip: [4]u8) bool {
    const addr = std.Io.net.IpAddress{ .ip4 = .{ .bytes = ip, .port = TCP_PROBE_PORT } };
    var stream = addr.connect(io, .{
        .mode = .stream,
        .protocol = .tcp,
        .timeout = .none,
    }) catch |err| {
        return err == error.ConnectionRefused or err == error.ConnectionResetByPeer;
    };
    defer stream.close(io);
    return true;
}

/// POSIX connect with our own timeout. Zig 0.16 has no connect timeout
/// yet, and a blocking connect to a dead host stalls ~75s in SYN
/// retransmits -- so: non-blocking socket, connect, poll for writable.
/// Classic man-page recipe, one step at a time.
fn tcpProbeTimeout(ip: [4]u8) bool {
    const fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
    if (fd < 0) return false;
    defer _ = std.c.close(fd);

    const raw_flags = std.c.fcntl(fd, std.posix.F.GETFL, @as(c_int, 0));
    if (raw_flags < 0) return false;
    // O_NONBLOCK lives in a packed bit struct on macOS, so flip the bit
    // through an integer round-trip.
    var oflags: std.posix.O = @bitCast(@as(u32, @bitCast(raw_flags)));
    oflags.NONBLOCK = true;
    if (std.c.fcntl(fd, std.posix.F.SETFL, @as(u32, @bitCast(oflags))) < 0) return false;

    var addr = std.posix.sockaddr.in{
        .port = std.mem.nativeToBig(u16, TCP_PROBE_PORT),
        // @bitCast copies the bytes as-is, which is exactly the network
        // byte order sockaddr expects.
        .addr = @bitCast(ip),
    };
    const addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(addr));
    if (std.c.connect(fd, @ptrCast(&addr), addr_len) == 0) return true;

    // Connection in progress (or already refused): wait until the socket
    // turns writable, but no longer than our probe timeout.
    var pfd = [_]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.OUT,
        .revents = 0,
    }};
    if (std.c.poll(&pfd, 1, TCP_PROBE_TIMEOUT_MS) <= 0) return false;

    // Writable: ask the socket what actually happened.
    var so_error: c_int = 0;
    var opt_len: std.posix.socklen_t = @sizeOf(c_int);
    if (std.c.getsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.ERROR, @ptrCast(&so_error), &opt_len) != 0) {
        return false;
    }
    return so_error == 0 or
        so_error == @intFromEnum(std.posix.E.CONNREFUSED) or
        so_error == @intFromEnum(std.posix.E.CONNRESET);
}

/// Read the local ARP table and report in-range hosts the TCP sweep
/// missed. Needs no privileges; `arp -a` exists on macOS, Linux and
/// Windows (only the first two formats are parsed for now).
fn harvestArp(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout_mutex: *std.Io.Mutex,
    first_ip: [4]u8,
    last_ip: [4]u8,
    found: *std.ArrayList([4]u8),
    found_mutex: *std.Io.Mutex,
) void {
    const result = std.process.run(allocator, io, .{ .argv = &.{ "arp", "-a" } }) catch |err| {
        std.debug.print("arp harvest skipped: {}\n", .{err});
        return;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        const ip = utils.parseArpLine(line) orelse continue;
        if (!utils.ipInRange(ip, first_ip, last_ip)) continue;

        found_mutex.lockUncancelable(io);
        var seen = false;
        for (found.items) |known| {
            if (std.mem.eql(u8, &known, &ip)) {
                seen = true;
                break;
            }
        }
        found_mutex.unlock(io);

        if (!seen) {
            utils.printStdout(io, stdout_mutex, "Host {d}.{d}.{d}.{d} is online (arp)\n", .{
                ip[0], ip[1], ip[2], ip[3],
            });
        }
    }
}
