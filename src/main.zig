const std = @import("std");

pub fn main() !void {
    //print hello world
    const stdout = std.io.getStdOut().writer();
    try stdout.print("Hello, world!\n", .{});
}
