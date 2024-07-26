const std = @import("std");
const net = std.net;
const posix = std.posix;
const Thread = std.Thread;
const Mutex = Thread.Mutex;
const spawn = Thread.spawn;
const SpawnConfig = Thread.SpawnConfig;
const utils = @import("utils.zig");

const MAX_THREADS = 100; // Adjust this value based on your system's capabilities

pub fn scanPorts(allocator: std.mem.Allocator, ip_address: [4]u8, start_port: u16, end_port: u16) !std.ArrayList(u16) {
    var open_ports = std.ArrayList(u16).init(allocator);
    errdefer open_ports.deinit();

    var semaphore = Thread.Semaphore{ .permits = MAX_THREADS };

    var port: u16 = start_port;
    while (port <= end_port) : (port += 1) {
        if (port == 137) {
            continue;
        }
        semaphore.wait();
        _ = try Thread.spawn(.{}, checkPortWrapper, .{ ip_address, port, &open_ports, &semaphore });
    }

    // Wait for all threads to complete
    var i: usize = 0;
    while (i < MAX_THREADS) : (i += 1) {
        semaphore.wait();
    }

    return open_ports;
}

fn checkPortWrapper(ip_address: [4]u8, port: u16, open_ports: *std.ArrayList(u16), semaphore: *Thread.Semaphore) void {
    defer semaphore.post();
    checkPort(ip_address, port, open_ports) catch |err| {
        std.debug.print("Error checking port {}: {}\n", .{ port, err });
    };
}
fn checkPort(ip_address: [4]u8, port: u16, open_ports: *std.ArrayList(u16)) !void {
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
