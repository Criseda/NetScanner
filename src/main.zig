const std = @import("std");
const utils = @import("utils.zig");

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
    if (std.mem.eql(u8, command, "--version")) {
        try utils.printVersion();
        return;
    }
}
