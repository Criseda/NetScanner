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
    // Decided up front so even argument errors come out in the format
    // the caller asked for.
    const json = hasFlag(args[2..], "--json");

    if (std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        try utils.printUsage(io);
    } else if (std.mem.eql(u8, command, "--version") or std.mem.eql(u8, command, "-v")) {
        try utils.printVersion(io);
    } else if (std.mem.eql(u8, command, "-p")) {
        try runPortScan(gpa, io, args, json);
    } else if (std.mem.eql(u8, command, "-s")) {
        try runSubnetScan(gpa, io, args, json);
    } else {
        try utils.printUsage(io);
        std.process.exit(1);
    }
}

fn hasFlag(args: []const [:0]const u8, flag: []const u8) bool {
    for (args) |arg| {
        if (std.mem.eql(u8, arg, flag)) return true;
    }
    return false;
}

/// Report a usage or input error and exit with status 1, so callers can
/// tell failure from "scanned, found nothing" without parsing text.
/// Text mode keeps the familiar `NetScanner: ...` line on stderr; JSON
/// mode emits `{"type":"error","message":...}` on stdout, where the
/// caller is already reading events.
fn fail(io: std.Io, json: bool, comptime fmt: []const u8, args: anytype) noreturn {
    var msg_buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(&msg_buf, fmt, args) catch fmt;
    if (json) {
        var esc_buf: [512]u8 = undefined;
        var stdout_mutex: std.Io.Mutex = .init;
        utils.printStdout(io, &stdout_mutex, "{{\"type\":\"error\",\"message\":\"{s}\"}}\n", .{utils.jsonEscape(&esc_buf, msg)});
    } else {
        std.debug.print("NetScanner: {s}\n", .{msg});
    }
    std.process.exit(1);
}

/// `ns -p <ip> <port-range> [--timeout <ms>] [--json]`: scan one host
/// for open ports. The timeout caps each probe (default 500ms); raise it
/// on slow networks, lower it on fast LANs for quicker sweeps.
fn runPortScan(allocator: std.mem.Allocator, io: std.Io, args: []const [:0]const u8, json: bool) !void {
    if (args.len < 4) {
        if (json) fail(io, json, "Usage: ns -p <ip> <port-range>", .{});
        try utils.printUsage(io);
        std.process.exit(1);
    }

    const ip_bytes = utils.ipStringToBytes(args[2]) catch fail(io, json, "Invalid IP address", .{});

    const port_array = utils.splitStringToIntArray(allocator, args[3], '-') catch
        fail(io, json, "Invalid port range", .{});
    defer allocator.free(port_array);
    if (port_array.len != 2) fail(io, json, "Please provide two ports", .{});

    // Accept the range in either order. scanPorts itself rejects
    // reversed ranges (error.InvalidPortRange); the CLI normalizes
    // first so users never have to care which side is larger.
    if (port_array[0] > port_array[1]) {
        const temp = port_array[0];
        port_array[0] = port_array[1];
        port_array[1] = temp;
    }

    // Options after the range: `--timeout <ms>` and `--json`.
    var timeout_ms: ?u16 = null;
    var arg_i: usize = 4;
    while (arg_i < args.len) : (arg_i += 1) {
        if (std.mem.eql(u8, args[arg_i], "--json")) continue;
        if (!std.mem.eql(u8, args[arg_i], "--timeout")) fail(io, json, "Unknown option", .{});
        arg_i += 1;
        if (arg_i >= args.len) fail(io, json, "--timeout needs a value in milliseconds (1-60000)", .{});
        const parsed = std.fmt.parseInt(u16, args[arg_i], 10) catch fail(io, json, "Invalid timeout", .{});
        if (parsed == 0 or parsed > 60000) fail(io, json, "Timeout must be 1-60000 ms", .{});
        timeout_ms = parsed;
    }

    const ip_address = [4]u8{ ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3] };

    const started = std.Io.Clock.now(.awake, io);
    var open_ports = try scanner.scanPorts(
        allocator,
        io,
        ip_address,
        port_array[0],
        port_array[1],
        .{ .timeout_ms = timeout_ms, .json = json },
    );
    defer open_ports.deinit(allocator);
    const elapsed_ns = started.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds;

    var stdout_mutex: std.Io.Mutex = .init;
    if (json) {
        const elapsed_ms: i64 = @intCast(@divTrunc(elapsed_ns, std.time.ns_per_ms));
        utils.printStdout(io, &stdout_mutex, "{{\"type\":\"summary\",\"open_ports\":[", .{});
        for (open_ports.items, 0..) |port, i| {
            if (i > 0) utils.printStdout(io, &stdout_mutex, ",", .{});
            utils.printStdout(io, &stdout_mutex, "{d}", .{port});
        }
        utils.printStdout(io, &stdout_mutex, "],\"elapsed_ms\":{d}}}\n", .{elapsed_ms});
    } else if (open_ports.items.len == 0) {
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

/// `ns -s <subnet> [options]`: find live hosts. Fast TCP + ARP discovery
/// by default, one-ping-per-host with --ping. Optional --resolve,
/// --hostname, --vendor, --oui-file and --json.
fn runSubnetScan(allocator: std.mem.Allocator, io: std.Io, args: []const [:0]const u8, json: bool) !void {
    if (args.len < 3) {
        if (json) fail(io, json, "Usage: ns -s <subnet>", .{});
        try utils.printUsage(io);
        std.process.exit(1);
    }
    const cidr = args[2];
    var use_ping = false;
    var scan_options = scanner.NetworkScanOptions{ .json = json };

    var i: usize = 3;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--ping")) {
            use_ping = true;
        } else if (std.mem.eql(u8, arg, "--json")) {
            // Already read by main.
        } else if (std.mem.eql(u8, arg, "--resolve")) {
            scan_options.resolve_hostname = true;
            scan_options.resolve_vendor = true;
        } else if (std.mem.eql(u8, arg, "--hostname")) {
            scan_options.resolve_hostname = true;
        } else if (std.mem.eql(u8, arg, "--vendor")) {
            scan_options.resolve_vendor = true;
        } else if (std.mem.eql(u8, arg, "--oui-file")) {
            i += 1;
            if (i >= args.len) fail(io, json, "--oui-file requires a file path", .{});
            scan_options.oui_file = args[i];
            scan_options.resolve_vendor = true;
        } else {
            if (!json) try utils.printUsage(io);
            fail(io, json, "Unknown option '{s}'", .{arg});
        }
    }

    // A bad subnet used to escape as a raw Zig error trace; report it
    // like every other input error instead.
    const result = if (use_ping)
        scanner.scanNetworkPing(allocator, io, cidr, scan_options)
    else
        scanner.scanNetwork(allocator, io, cidr, scan_options);
    result catch |err| switch (err) {
        error.InvalidCidr, error.InvalidIpAddress, error.InvalidPrefixLength, error.InvalidCharacter, error.Overflow => fail(io, json, "Invalid subnet '{s}' (use CIDR like 192.168.1.0/24)", .{cidr}),
        else => return err,
    };
}
