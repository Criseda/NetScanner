const std = @import("std");
const utils = @import("utils.zig");
const scanner = @import("scanner.zig");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const arena = init.arena.allocator();

    // Gets the arguments passed to the program.
    const args = try init.minimal.args.toSlice(arena);

    if (args.len < 2) {
        try utils.printUsage(io);
        return;
    }

    const command = args[1];

    // if command is "--help" print the usage
    if (std.mem.eql(u8, command, "--help")) {
        try utils.printUsage(io);
        return;
    }
    // if command is "--version" print the version
    if (std.mem.eql(u8, command, "--version")) {
        try utils.printVersion(io);
        return;
    }
    // if command is "-p"
    // - look for the next argument, which should be an IP address
    // - look for the next argument, which should be a port range
    if (std.mem.eql(u8, command, "-p")) {
        if (args.len < 4) {
            try utils.printUsage(io);
            return;
        }
        const ip_string = args[2];
        const ip_bytes = utils.ipStringToBytes(ip_string) catch {
            std.debug.print("NetScanner: Invalid IP address\n", .{});
            return;
        };

        const port_range = args[3];
        const port_array = utils.splitStringToIntArray(gpa, port_range, '-') catch {
            std.debug.print("NetScanner: Invalid port range\n", .{});
            return;
        };
        if (port_array.len != 2) {
            std.debug.print("NetScanner: Please provide two ports\n", .{});
            defer gpa.free(port_array);
            return;
        }
        //if the first port is more than the second port, swap them
        if (port_array[0] > port_array[1]) {
            const temp = port_array[0];
            port_array[0] = port_array[1];
            port_array[1] = temp;
        }
        defer gpa.free(port_array);

        const ip_address = [4]u8{ ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3] };
        const start_port = port_array[0];
        const end_port = port_array[1];

        var open_ports = try scanner.scanPorts(gpa, io, ip_address, start_port, end_port);
        defer open_ports.deinit(gpa);

        var stdout_mutex: std.Io.Mutex = .init;
        if (open_ports.items.len == 0) {
            utils.printStdout(io, &stdout_mutex, "No open ports found\n", .{});
        } else {
            utils.printStdout(io, &stdout_mutex, "Open ports: ", .{});
            for (open_ports.items, 0..) |p, i| {
                if (i > 0) utils.printStdout(io, &stdout_mutex, ", ", .{});
                utils.printStdout(io, &stdout_mutex, "{d}", .{p});
            }
            utils.printStdout(io, &stdout_mutex, "\n", .{});
        }
    }
    // if command is "-s"
    if (std.mem.eql(u8, command, "-s")) {
        // read the next argument, which is the cidr
        if (args.len < 3) {
            try utils.printUsage(io);
            return;
        }
        const cidr = args[2];
        _ = try scanner.scanNetwork(gpa, io, cidr);
    }
}
