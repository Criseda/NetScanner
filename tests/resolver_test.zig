const std = @import("std");
const builtin = @import("builtin");
const resolver = @import("core").resolver;

test "cleanDomainName strips domain suffix" {
    try std.testing.expectEqualStrings("workstation", resolver.cleanDomainName("workstation.cable.isp.net"));
    try std.testing.expectEqualStrings("myhost", resolver.cleanDomainName("myhost.local"));
    try std.testing.expectEqualStrings("standalone", resolver.cleanDomainName("standalone"));
    try std.testing.expectEqualStrings("spaces", resolver.cleanDomainName("  spaces.local  \n"));
    try std.testing.expectEqualStrings("", resolver.cleanDomainName(""));
    try std.testing.expectEqualStrings("", resolver.cleanDomainName("   \t\r\n"));
    try std.testing.expectEqualStrings("trailing", resolver.cleanDomainName("trailing."));
    try std.testing.expectEqualStrings("first", resolver.cleanDomainName("first.second.third"));
}

/// A loopback stand-in for a host's mDNS responder: answers the first
/// datagram it gets with `reply`.
const Responder = struct {
    socket: std.Io.net.Socket,
    reply: []const u8,

    fn answer(self: *const Responder, io: std.Io) void {
        var buf: [512]u8 = undefined;
        const query = self.socket.receive(io, &buf) catch return;
        self.socket.send(io, &query.from, self.reply) catch {};
    }
};

/// Ask a loopback responder that answers with `reply` for 127.0.0.1's
/// name, and check what queryMdns makes of it.
fn expectMdnsName(expected: ?[]const u8, reply: []const u8) !void {
    if (builtin.single_threaded) return error.SkipZigTest;
    const io = std.testing.io;
    const addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    const socket = addr.bind(io, .{ .mode = .dgram }) catch return error.SkipZigTest;
    defer socket.close(io);
    const responder: Responder = .{ .socket = socket, .reply = reply };
    const thread = try std.Thread.spawn(.{}, Responder.answer, .{ &responder, io });
    defer thread.join();

    var out: [256]u8 = undefined;
    const name = resolver.queryMdns(.{ 127, 0, 0, 1 }, socket.address.getPort(), 1000, &out);
    // If the query never reached the responder, this ends its wait; if
    // it did, the datagram just sits in the socket's buffer.
    socket.send(io, &socket.address, "") catch {};
    if (expected) |want| {
        try std.testing.expectEqualStrings(want, name orelse return error.NoName);
    } else {
        try std.testing.expect(name == null);
    }
}

/// An mDNS response with one PTR answer: `owner` (dotted labels) -> box.local.
fn ptrReply(comptime owner: []const []const u8) []const u8 {
    comptime {
        var packet: []const u8 = &.{ 0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0 };
        for (owner) |label| packet = packet ++ [_]u8{label.len} ++ label;
        packet = packet ++ [_]u8{ 0, 0, 12, 0x80, 1, 0, 0, 0, 120, 0, 11 } ++
            [_]u8{3} ++ "box" ++ [_]u8{5} ++ "local" ++ [_]u8{0};
        const final = packet[0..packet.len].*;
        return &final;
    }
}

test "queryMdns reads the host's answer about its own address" {
    try expectMdnsName("box.local", comptime ptrReply(&.{ "1", "0", "0", "127", "in-addr", "arpa" }));
}

test "queryMdns ignores a PTR answer about another address" {
    try expectMdnsName(null, comptime ptrReply(&.{ "10", "1", "168", "192", "in-addr", "arpa" }));
}
