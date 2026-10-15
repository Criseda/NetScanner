const std = @import("std");
const builtin = @import("builtin");
const neighbor_table = @import("core").neighbor_table;

const allocator = std.testing.allocator;

fn expectTable(reply: neighbor_table.Reply) ![]@import("bindings").Neighbor {
    return switch (reply) {
        .table => |table| table,
        else => error.TestExpectedTable,
    };
}

test "parseReply reads entries, MACs and states" {
    const line =
        \\{"type":"neighbors","id":3,"entries":[
        \\{"ip":"192.168.1.1","mac":"aa:bb:cc:dd:ee:0f","state":"reachable"},
        \\{"ip":"192.168.1.20","mac":"AA-BB-CC-DD-EE-10","state":"stale"},
        \\{"ip":"192.168.1.30"}]}
    ;
    const table = try expectTable(try neighbor_table.parseReply(allocator, line, 3));
    defer allocator.free(table);

    try std.testing.expectEqual(3, table.len);
    try std.testing.expectEqual([4]u8{ 192, 168, 1, 1 }, table[0].ip);
    try std.testing.expectEqual([6]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0f }, table[0].mac.?);
    try std.testing.expectEqual(.reachable, table[0].state);
    try std.testing.expectEqual([6]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x10 }, table[1].mac.?);
    try std.testing.expectEqual(.stale, table[1].state);
    // No MAC and no state: kept, and it still gets the confirming ping.
    try std.testing.expectEqual(null, table[2].mac);
    try std.testing.expectEqual(.stale, table[2].state);
}

test "parseReply drops rows the kernel reader would leave out" {
    const line =
        \\{"type":"neighbors","id":1,"entries":[
        \\{"ip":"224.0.0.251","mac":"01:00:5e:00:00:fb"},
        \\{"ip":"0.0.0.0","mac":"aa:bb:cc:dd:ee:ff"},
        \\{"ip":"192.168.1.255","mac":"ff:ff:ff:ff:ff:ff"},
        \\{"ip":"not an ip","mac":"aa:bb:cc:dd:ee:ff"},
        \\{"ip":"192.168.1.5","mac":"garbage"},
        \\{"ip":"192.168.1.6","mac":"aa:bb:cc:dd:ee:06","extra":true}]}
    ;
    const table = try expectTable(try neighbor_table.parseReply(allocator, line, 1));
    defer allocator.free(table);

    try std.testing.expectEqual(1, table.len);
    try std.testing.expectEqual([4]u8{ 192, 168, 1, 6 }, table[0].ip);
}

test "parseReply tells failures, late answers and garbage apart" {
    try std.testing.expectEqual(.failed, try neighbor_table.parseReply(allocator,
        \\{"type":"neighbors","id":2,"error":"sysctl failed"}
    , 2));
    try std.testing.expectEqual(.earlier, try neighbor_table.parseReply(allocator,
        \\{"type":"neighbors","id":1,"entries":[]}
    , 2));
    const bad = [_][]const u8{
        "not json",
        \\{"type":"something_else","id":2,"entries":[]}
        ,
        \\{"type":"neighbors","id":3,"entries":[]}
        ,
        \\{"type":"neighbors","id":2}
        ,
    };
    for (bad) |line| {
        try std.testing.expectError(error.InvalidReply, neighbor_table.parseReply(allocator, line, 2));
    }
}

/// A pipe standing in for stdin; the test writes the parent's replies.
const Pipe = struct {
    read: std.posix.fd_t,
    write: std.posix.fd_t,

    fn open() !Pipe {
        var fds: [2]std.posix.fd_t = undefined;
        if (std.c.pipe(&fds) != 0) return error.PipeFailed;
        return .{ .read = fds[0], .write = fds[1] };
    }

    fn send(self: Pipe, bytes: []const u8) !void {
        if (std.c.write(self.write, bytes.ptr, bytes.len) != @as(isize, @intCast(bytes.len))) return error.WriteFailed;
    }

    fn close(self: Pipe) void {
        _ = std.c.close(self.read);
        _ = std.c.close(self.write);
    }
};

test "awaitReply skips late answers and keeps what follows a line" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const pipe = try Pipe.open();
    defer pipe.close();
    var parent: neighbor_table.Parent = .{ .input = pipe.read };
    defer parent.deinit(allocator);

    // A late answer to request 1, then two answers in one write: the
    // second must still be there for the next request.
    try pipe.send(
        \\{"type":"neighbors","id":1,"entries":[]}
        \\{"type":"neighbors","id":2,"entries":[{"ip":"10.0.0.2","mac":"02:00:00:00:00:02"}]}
        \\{"type":"neighbors","id":3,"entries":[{"ip":"10.0.0.3"}]}
        \\
    );
    const second = parent.awaitReply(allocator, std.testing.io, 2) orelse return error.TestExpectedTable;
    defer allocator.free(second);
    try std.testing.expectEqual(1, second.len);
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 2 }, second[0].ip);

    const third = parent.awaitReply(allocator, std.testing.io, 3) orelse return error.TestExpectedTable;
    defer allocator.free(third);
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 3 }, third[0].ip);
    try std.testing.expect(!parent.gave_up);
}

test "awaitReply gives up on a parent that does not answer" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const pipe = try Pipe.open();
    defer pipe.close();
    var parent: neighbor_table.Parent = .{ .input = pipe.read, .timeout_ms = 50 };
    defer parent.deinit(allocator);

    try std.testing.expectEqual(null, parent.awaitReply(allocator, std.testing.io, 1));
    try std.testing.expect(parent.gave_up);
}

test "awaitReply falls back when the parent cannot read the table" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const pipe = try Pipe.open();
    defer pipe.close();
    var parent: neighbor_table.Parent = .{ .input = pipe.read };
    defer parent.deinit(allocator);

    try pipe.send("{\"type\":\"neighbors\",\"id\":1,\"error\":\"no access\"}\n");
    try std.testing.expectEqual(null, parent.awaitReply(allocator, std.testing.io, 1));
    // A quick "no" is not a hang: the next scan step may ask again.
    try std.testing.expect(!parent.gave_up);
}
