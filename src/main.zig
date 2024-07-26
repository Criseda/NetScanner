const std = @import("std");
const utils = @import("utils.zig");
const scanner = @import("scanner.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // gets the arguments passed to the program
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try utils.printUsage();
        return;
    }

    const command = args[1];

    // if command is "--help" print the usage
    if (std.mem.eql(u8, command, "--help")) {
        try utils.printUsage();
        return;
    }
    // if command is "--version" print the version
    if (std.mem.eql(u8, command, "--version")) {
        try utils.printVersion();
        return;
    }
    // if command is "-p"
    // - look for the next argument, which should be an IP address
    // - look for the next argument, which should be a port range
    if (std.mem.eql(u8, command, "-p")) {
        if (args.len < 4) {
            try utils.printUsage();
            return;
        }
        const ip_string = args[2];
        const ip_bytes = utils.ipStringToBytes(ip_string) catch {
            std.debug.print("NetScanner: Invalid IP address\n", .{});
            return;
        };
        //print the ip_bytes for now
        std.debug.print("{d}.{d}.{d}.{d}\n", .{ ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3] });

        const port_range = args[3];
        const port_array = utils.splitStringToIntArray(allocator, port_range, '-') catch {
            std.debug.print("NetScanner: Invalid port range\n", .{});
            return;
        };
        if (port_array.len != 2) {
            std.debug.print("NetScanner: Please provide two ports\n", .{});
            defer allocator.free(port_array);
            return;
        }
        //if the first port is more than the second port, swap them
        if (port_array[0] > port_array[1]) {
            const temp = port_array[0];
            port_array[0] = port_array[1];
            port_array[1] = temp;
        }
        defer allocator.free(port_array);
        //print the ports for now
        std.debug.print("{d}-{d}\n", .{ port_array[0], port_array[1] });

        const ip_address = [4]u8{ ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3] };
        const start_port = port_array[0];
        const end_port = port_array[1];

        const open_ports = try scanner.scanPorts(allocator, ip_address, start_port, end_port);
        defer open_ports.deinit();

        const stdout = std.io.getStdOut().writer();
        try stdout.print("Open ports: {d}\n", .{open_ports.items});
    }
    // if command is "-s"
    if (std.mem.eql(u8, command, "-s")) {
        std.debug.print("NetScanner: Subnet scanning is not yet implemented\n", .{});
    }
}
