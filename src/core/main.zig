const std = @import("std");
const utils = @import("utils.zig");
const scanner = @import("scanner.zig");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const arena = init.arena.allocator();

    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        try utils.printUsage(io);
        return;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "--help")) {
        try utils.printUsage(io);
    } else if (std.mem.eql(u8, command, "--version")) {
        try utils.printVersion(io);
    } else if (std.mem.eql(u8, command, "-p")) {
        try runPortScan(gpa, io, args);
    } else if (std.mem.eql(u8, command, "-s")) {
        try runSubnetScan(gpa, io, args);
    } else {
        try utils.printUsage(io);
    }
}

/// `ns -p <ip> <port-range> [--timeout <ms>]`: scan one host for
/// open ports. The timeout caps each probe (default 500ms); raise it
/// on slow networks, lower it on fast LANs for quicker sweeps.
fn runPortScan(allocator: std.mem.Allocator, io: std.Io, args: []const [:0]const u8) !void {
    if (args.len < 4) {
        try utils.printUsage(io);
        return;
    }

    const ip_bytes = utils.ipStringToBytes(args[2]) catch {
        std.debug.print("NetScanner: Invalid IP address\n", .{});
        return;
    };

    const port_array = utils.splitStringToIntArray(allocator, args[3], '-') catch {
        std.debug.print("NetScanner: Invalid port range\n", .{});
        return;
    };
    if (port_array.len != 2) {
        std.debug.print("NetScanner: Please provide two ports\n", .{});
        defer allocator.free(port_array);
        return;
    }
    // Accept the range in either order. scanPorts itself rejects
    // reversed ranges (error.InvalidPortRange); the CLI normalizes
    // first so users never have to care which side is larger.
    if (port_array[0] > port_array[1]) {
        const temp = port_array[0];
        port_array[0] = port_array[1];
        port_array[1] = temp;
    }
    defer allocator.free(port_array);

    // Optional `--timeout <ms>` after the range.
    var timeout_ms: ?u16 = null;
    var arg_i: usize = 4;
    while (arg_i < args.len) : (arg_i += 1) {
        if (!std.mem.eql(u8, args[arg_i], "--timeout")) {
            std.debug.print("NetScanner: Unknown option\n", .{});
            return;
        }
        arg_i += 1;
        if (arg_i >= args.len) {
            std.debug.print("NetScanner: --timeout needs a value in milliseconds (1-60000)\n", .{});
            return;
        }
        const parsed = std.fmt.parseInt(u16, args[arg_i], 10) catch {
            std.debug.print("NetScanner: Invalid timeout\n", .{});
            return;
        };
        if (parsed == 0 or parsed > 60000) {
            std.debug.print("NetScanner: Timeout must be 1-60000 ms\n", .{});
            return;
        }
        timeout_ms = parsed;
    }

    const ip_address = [4]u8{ ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3] };

    var open_ports = try scanner.scanPorts(
        allocator,
        io,
        ip_address,
        port_array[0],
        port_array[1],
        .{ .timeout_ms = timeout_ms },
    );
    defer open_ports.deinit(allocator);

    var stdout_mutex: std.Io.Mutex = .init;
    if (open_ports.items.len == 0) {
        utils.printStdout(io, &stdout_mutex, "No open ports found\n", .{});
    } else {
        utils.printStdout(io, &stdout_mutex, "Open ports: ", .{});
        for (open_ports.items, 0..) |port, i| {
            if (i > 0) utils.printStdout(io, &stdout_mutex, ", ", .{});
            utils.printStdout(io, &stdout_mutex, "{d}", .{port});
        }
        utils.printStdout(io, &stdout_mutex, "\n", .{});
    }
}

/// `ns -s <subnet> [--ping]`: find live hosts. Fast TCP + ARP discovery
/// by default, one-ping-per-host with --ping.
fn runSubnetScan(allocator: std.mem.Allocator, io: std.Io, args: []const [:0]const u8) !void {
    if (args.len < 3) {
        try utils.printUsage(io);
        return;
    }
    const cidr = args[2];
    const use_ping = args.len > 3 and std.mem.eql(u8, args[3], "--ping");
    if (use_ping) {
        try scanner.scanNetworkPing(allocator, io, cidr);
    } else {
        try scanner.scanNetwork(allocator, io, cidr);
    }
}
