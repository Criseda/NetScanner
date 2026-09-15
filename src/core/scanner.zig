const std = @import("std");
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

    var current_ip = ip_range.start;
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
            if (std.mem.eql(u8, &current_ip, &ip_range.end)) break;
            utils.incrementIP(&current_ip);
            continue;
        };
        threads.append(allocator, handle) catch |err| {
            std.debug.print("Error tracking thread: {}\n", .{err});
            handle.join();
            sem.post(io);
        };
        if (std.mem.eql(u8, &current_ip, &ip_range.end)) break;
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
