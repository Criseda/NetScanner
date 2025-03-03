const std = @import("std");
const net = std.net;
const posix = std.posix;
const Thread = std.Thread;
const Mutex = Thread.Mutex;
const spawn = Thread.spawn;
const utils = @import("utils.zig");
const c_bindings = @import("bindings");
const builtin = @import("builtin");
const native_os = builtin.os.tag;

const MAX_THREADS = 100; // Adjust this value based on your system's capabilities
const MAX_PING_THREADS = 15;

// Scan port functionality

pub fn scanPorts(allocator: std.mem.Allocator, ip_address: [4]u8, start_port: u16, end_port: u16) !std.ArrayList(u16) {
    var open_ports = std.ArrayList(u16).init(allocator);
    errdefer open_ports.deinit();

    var semaphore = Thread.Semaphore{ .permits = MAX_THREADS };

    var port: u16 = start_port;
    while (port <= end_port) {
        if (port == 137) {
            port += 1;
            continue;
        }
        semaphore.wait();
        _ = Thread.spawn(.{}, checkPortWrapper, .{ ip_address, port, &open_ports, &semaphore }) catch |err| {
            std.debug.print("SpawnError: {}\n", .{err});
            semaphore.post();
            port += 1;
            continue;
        };
        if (port == 65535) {
            break;
        }
        port += 1;
    }

    // Wait for all threads to complete
    var i: usize = 0;
    while (i < MAX_THREADS) : (i += 1) {
        semaphore.wait();
    }

    return open_ports;
}

fn checkPortWrapper(ip_address: [4]u8, port: u16, open_ports: *std.ArrayList(u16), semaphore: *Thread.Semaphore) !void {
    defer semaphore.post();
    try checkPort(ip_address, port, open_ports);
}

fn checkPort(ip_address: [4]u8, port: u16, open_ports: *std.ArrayList(u16)) !void {
    std.time.sleep(std.time.ns_per_ms * 5); // 10ms delay, adjust as needed

    const address = net.Address.initIp4(ip_address, port);

    const stdout = std.io.getStdOut().writer();

    const stream = net.tcpConnectToAddress(address) catch |err| {
        switch (err) {
            error.ConnectionRefused => {
                std.debug.print("Port is closed: {}\n", .{port});
                return;
            }, // Expected for closed ports
            error.PermissionDenied => {
                std.debug.print("Access denied for port {}\n", .{port});
                return;
            },
            error.ConnectionTimedOut => {
                std.debug.print("Connection timed out for port {}\n", .{port});
                return;
            },
            error.Unexpected => {
                std.debug.print("Unexpected error for port {}\n", .{port});
                return;
            },
            else => {
                std.debug.print("Error connecting to port {}: {}\n", .{ port, err });
                return;
            },
        }
    };
    defer stream.close();

    try stdout.print("Open port: {}\n", .{port});
    open_ports.append(port) catch |err| {
        std.debug.print("Error appending port {}: {}\n", .{ port, err });
    };
}

// Network scanner functionality

pub const NetworkScanResult = struct {
    ip: []const u8,
    name: []const u8,
    manufacturer: []const u8,
    mac_address: []const u8,
};

pub fn scanNetwork(allocator: std.mem.Allocator, cidr: []const u8) !void {
    const network = try utils.parseCidr(cidr);
    const ip_range = try utils.getIpRange(network);
    const stdout = std.io.getStdOut().writer();

    try stdout.print("Scanning network: {s} (Range: {d}.{d}.{d}.{d} - {d}.{d}.{d}.{d})\n", .{
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

    var threads = std.ArrayList(Thread).init(allocator);
    defer threads.deinit();

    var semaphore = Thread.Semaphore{ .permits = MAX_PING_THREADS };

    var current_ip = ip_range.start;
    while (true) {
        semaphore.wait();
        const handle = try Thread.spawn(.{}, scanIPWrapper, .{ current_ip, allocator, &semaphore });
        try threads.append(handle);
        if (std.mem.eql(u8, &current_ip, &ip_range.end)) break;
        utils.incrementIP(&current_ip);
    }

    // Join all spawned threads.
    for (threads.items) |handle| {
        handle.join();
    }
}

fn scanIPWrapper(ip: [4]u8, allocator: std.mem.Allocator, semaphore: *Thread.Semaphore) !void {
    defer semaphore.post();
    try scanIP(allocator, ip);
}

fn scanIP(allocator: std.mem.Allocator, ip: [4]u8) !void {

    // Check if the IP is online using ICMP ping
    _ = pingHost(allocator, ip) catch |err| {
        std.debug.print("Error pinging host: {}\n", .{err});
        return;
    };
}

pub fn pingHost(allocator: std.mem.Allocator, ip: [4]u8) !void {
    const stdout = std.io.getStdOut().writer();
    const ip_string = try utils.ipBytesToString(allocator, ip);
    defer allocator.free(ip_string);

    if (!std.unicode.utf8ValidateSlice(ip_string)) {
        return error.InvalidWtf8;
    }

    const ip_with_null = try allocator.dupeZ(u8, ip_string);
    defer allocator.free(ip_with_null);

    if (c_bindings.pingHost(ip_with_null.ptr)) {
        try stdout.print("Host {s} is online\n", .{ip_string});
    }
}
