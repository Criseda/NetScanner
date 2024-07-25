const std = @import("std");
const net = std.net;
const posix = std.posix;
const Thread = std.Thread;
const Mutex = Thread.Mutex;
const spawn = Thread.spawn;
const SpawnConfig = Thread.SpawnConfig;
const utils = @import("utils.zig");

// pub fn scanPorts(allocator: std.mem.Allocator, ip_address: [4]u8) !std.ArrayList(u16) {
//     // Create a new ArrayList to store the open ports
//     var open_ports = std.ArrayList(u16).init(allocator);

//     var port: u16 = 3000; // Start scanning from port 1
//     while (port <= 65535) : (port += 1) {
//         std.debug.print("Checking port: {}\n", .{port});
//         const address = net.Address.initIp4(ip_address, port);
//         const stream = net.tcpConnectToAddress(address) catch {
//             continue;
//         };
//         defer stream.close();
//         // found an open port, add it to the list
//         std.debug.print("Open port: {}\n", .{port});
//         try open_ports.append(port);
//     }
//     return open_ports;
// }
const MAX_THREADS = 20; // Adjust this value based on your system's capabilities

pub fn scanPorts(allocator: std.mem.Allocator, ip_address: [4]u8) !std.ArrayList(u16) {
    var open_ports = std.ArrayList(u16).init(allocator);
    errdefer open_ports.deinit();

    var semaphore = Thread.Semaphore{ .permits = MAX_THREADS };

    var port: u16 = 1;
    while (port <= 65535) : (port += 1) {
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

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const ip_address = [4]u8{ 192, 168, 0, 13 };
    const open_ports = try scanPorts(allocator, ip_address);
    defer open_ports.deinit();

    const stdout = std.io.getStdOut().writer();
    try stdout.print("Open ports: {d}\n", .{open_ports.items});
}
