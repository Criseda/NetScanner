const std = @import("std");
const net = std.net;
const posix = std.posix;
const Thread = std.Thread;
const Mutex = Thread.Mutex;
const spawn = Thread.spawn;
const utils = @import("utils.zig");
const builtin = @import("builtin");
const native_os = builtin.os.tag;

const MAX_THREADS = 100; // Adjust this value based on your system's capabilities

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

    std.debug.print("Open port: {}\n", .{port});
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
    std.debug.print("Scanning network range: {d}.{d}.{d}.{d} - {d}.{d}.{d}.{d}\n", .{
        ip_range.start[0], ip_range.start[1], ip_range.start[2], ip_range.start[3],
        ip_range.end[0],   ip_range.end[1],   ip_range.end[2],   ip_range.end[3],
    });

    var semaphore = Thread.Semaphore{ .permits = MAX_THREADS };

    var current_ip = ip_range.start;
    while (true) {
        semaphore.wait();
        _ = Thread.spawn(.{}, scanIPWrapper, .{ current_ip, &semaphore, allocator }) catch |err| {
            std.debug.print("SpawnError: {}\n", .{err});
            semaphore.post();
            utils.incrementIP(&current_ip);
            continue;
        };
        if (std.mem.eql(u8, &current_ip, &ip_range.end)) {
            break;
        }
        utils.incrementIP(&current_ip);
    }

    // Wait for all threads to complete
    var i: usize = 0;
    while (i < MAX_THREADS) : (i += 1) {
        semaphore.wait();
    }
}

fn scanIPWrapper(ip: [4]u8, semaphore: *Thread.Semaphore, allocator: std.mem.Allocator) !void {
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
    const ip_string = try utils.ipBytesToString(allocator, ip);

    std.debug.print("Pinging host: {s}\n", .{ip_string});

    defer allocator.free(ip_string);

    if (!std.unicode.utf8ValidateSlice(ip_string)) {
        return error.InvalidWtf8;
    }

    const ping_command = switch (native_os) {
        .windows => &[_][]const u8{ "ping", "-n", "1", "-w", "1000", ip_string },
        .linux, .macos => &[_][]const u8{ "ping", "-c", "1", "-W", "1", ip_string },
        else => return error.UnsupportedOS,
    };

    var child = std.process.Child.init(ping_command, allocator);
    child.stderr_behavior = .Ignore;
    child.stdout_behavior = .Ignore;

    child.spawn() catch |err| {
        std.debug.print("Error spawning ping process: {?}\n", .{err});
        return error.ProcessError;
    };

    const term = try child.wait();

    switch (term) {
        .Exited => |code| {
            if (code == 0) {
                std.debug.print("Host {s} is online\n", .{ip_string});
            }
        },
        else => {},
    }
}
