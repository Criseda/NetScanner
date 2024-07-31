const std = @import("std");
const net = std.net;
const posix = std.posix;
const Thread = std.Thread;
const Mutex = Thread.Mutex;
const spawn = Thread.spawn;
const utils = @import("utils.zig");

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

fn scanIPWrapper(ip: [4]u8, results: *std.ArrayList(NetworkScanResult), semaphore: *Thread.Semaphore, allocator: std.mem.Allocator) !void {
    defer semaphore.post();
    try scanIP(ip, results, allocator);
}

fn scanIP(ip: [4]u8, results: *std.ArrayList(NetworkScanResult)) !void {
    // Check if the IP is online using ICMP ping
    if (try pingHost(ip)) {
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

pub fn pingHost(ip: [4]u8) !bool { //TODO: set this back to private once debugging is done
    // Create a raw socket for ICMP
    std.debug.print("Creating socket...\n", .{});
    const socket = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.RAW, std.posix.IPPROTO.ICMP);
    errdefer std.posix.close(socket);

    // Allow the socket to reuse the address
    std.debug.print("Setting socket options...\n", .{});
    try std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
    const address = std.net.Address.initIp4(ip, 0);

    std.debug.print("Preparing ICMP packet...\n", .{});
    // Prepare the ICMP echo request packet
    var packet: [64]u8 = undefined;
    const id: u16 = 0x1234; // Arbitrary identifier
    const seq: u16 = 0x0100; // Sequence number

    // ICMP header
    packet[0] = 8; // Type: Echo Request
    packet[1] = 0; // Code: 0
    packet[2] = 0; // Checksum (to be filled in later)
    packet[3] = 0; // Checksum (to be filled in later)
    packet[4] = @intCast(id & 0xFF); // Identifier (lower byte)
    packet[5] = @intCast((id >> 8) & 0xFF); // Identifier (upper byte)
    packet[6] = @intCast(seq & 0xFF); //[0]; // Sequence number
    packet[7] = @intCast((seq >> 8) & 0xFF); //[1]; // Sequence number

    std.debug.print("Calculating checksum...\n", .{});
    // Calculate checksum (simple placeholder, not a real checksum calculation)
    const chk_sum = checksum(packet[0..8]);
    packet[2] = @intCast(chk_sum & 0xFF); // Lower byte
    packet[3] = @intCast((chk_sum >> 8) & 0xFF); // Higher byte
    // print chksum
    std.debug.print("Checksum: {x}\n", .{chk_sum});
    // print packet[2]
    std.debug.print("Packet[2]: {x}\n", .{packet[2]});
    // print packet[3]
    std.debug.print("Packet[3]: {x}\n", .{packet[3]});
    std.debug.print("packet variable: {x}\n", .{packet});

    //print the resulting packet
    std.debug.print("Sending the packet...\n", .{});
    // Send the packet
    const sent_packet = std.posix.sendto(socket, &packet, 0, &address.any, address.getOsSockLen()) catch |err| {
        std.debug.print("Error sending ICMP packet: {}\n", .{err});
        return false;
    };
    std.debug.print("Sent packet {x}\n", .{sent_packet});

    std.debug.print("Receiving reply...\n", .{});
    // Receive the reply
    var buffer: [4096]u8 = undefined;
    const timeout = std.time.ns_per_s * 10; // 10 second timeout
    const start_time = std.time.nanoTimestamp();

    while (std.time.nanoTimestamp() - start_time < timeout) {
        const recv_result = posix.recv(socket, &buffer, 0x40) catch |err| {
            if (err == error.WouldBlock) {
                std.debug.print("Would block, retrying...\n", .{});
                std.time.sleep(1000 * std.time.ns_per_ms); // Sleep for 1s before trying again
                continue;
            }
            return err;
        };

        if (recv_result > 0) {
            std.debug.print("Received reply: {x}\n", .{recv_result});
            return true;
        }
    }

    std.debug.print("Timeout reached.\n", .{});
    return false;
}

fn checksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;

    // Process pairs of bytes
    while (i + 1 < data.len) : (i += 2) {
        sum += @as(u16, data[i]) | (@as(u16, data[i + 1]) << 8);
    }

    // If there's a remaining byte, process it
    if (i < data.len) {
        sum += @as(u16, data[i]);
    }

    // Fold 32-bit sum to 16 bits
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    const checksum_result: u16 = @intCast(~sum & 0xFFFF);

    return checksum_result;
}
