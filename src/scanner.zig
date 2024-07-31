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
    ip: [4]u8,
    name: []const u8,
    manufacturer: []const u8,
    mac_address: []const u8,
};

pub fn scanNetwork(allocator: std.mem.Allocator, cidr: []const u8) !std.ArrayList(NetworkScanResult) {
    var results = std.ArrayList(NetworkScanResult).init(allocator);
    errdefer results.deinit();

    const network = try utils.parseCidr(cidr); // implement this function in utils.zig
    const ip_range = try utils.getIpRange(network); // implement this function in utils.zig

    var semaphore = Thread.Semaphore{ .permits = MAX_THREADS };

    var current_ip = ip_range.start;
    while (current_ip <= ip_range.end) {
        semaphore.wait();
        _ = Thread.spawn(.{}, scanIPWrapper, .{ current_ip, &results, &semaphore, allocator }) catch |err| {
            std.debug.print("SpawnError: {}\n", .{err});
            semaphore.post();
            current_ip += 1;
            continue;
        };
        current_ip += 1;
    }

    // Wait for all threads to complete
    var i: usize = 0;
    while (i < MAX_THREADS) : (i += 1) {
        semaphore.wait();
    }

    return results;
}

fn scanIPWrapper(ip: []const u8, results: *std.ArrayList(NetworkScanResult), semaphore: *Thread.Semaphore, allocator: std.mem.Allocator) !void {
    defer semaphore.post();
    try scanIP(allocator, ip, results);
}

fn scanIP(allocator: std.mem.Allocator, ip: []const u8, results: *std.ArrayList(NetworkScanResult)) !void {
    // Check if the IP is online using ICMP ping
    if (try pingHost(allocator, ip)) {
        // const name = try getHostName(allocator, ip); //TODO: IMPLEMENT
        // const manufacturer = try getManufacturer(allocator, ip); //TODO: IMPLEMENT
        // const mac_address = try getMacAddress(allocator, ip); //TODO: IMPLEMENT
        const name: []const u8 = "Unknown";
        const manufacturer: []const u8 = "Unknown";
        const mac_address: []const u8 = "Unknown";

        try results.append(NetworkScanResult{
            .ip = ip,
            .name = name,
            .manufacturer = manufacturer,
            .mac_address = mac_address,
        });
    }
}

pub fn pingHost(allocator: std.mem.Allocator, ip: []const u8) !bool {
    const ping_command = switch (native_os) {
        .windows => &[_][]const u8{ "ping", "-n", "1", "-w", "1000", ip },
        .linux, .macos => &[_][]const u8{ "ping", "-c", "1", "-W", "1", ip },
        else => return error.UnsupportedOS,
    };

    var child = std.process.Child.init(ping_command, allocator);
    child.stderr_behavior = .Ignore;
    child.stdout_behavior = .Ignore;

    try child.spawn();

    const term = try child.wait();

    return switch (term) {
        .Exited => |code| code == 0,
        else => false,
    };
}
