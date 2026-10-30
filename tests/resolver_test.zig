const std = @import("std");
const builtin = @import("builtin");
const resolver = @import("core").resolver;
const c_bindings = @import("bindings");

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

/// A Node Status Response to resolver.netbios_request naming `entries`
/// (15-byte name, suffix, flags high byte).
fn netbiosReply(comptime entries: []const struct { []const u8, u8, u8 }) []const u8 {
    comptime {
        // Header, echoed name, type, class, TTL, data length: 56 bytes.
        var packet: []const u8 = resolver.netbios_request[0..2] ++ [_]u8{ 0x84, 0 } ++
            [_]u8{ 0, 0, 0, 1, 0, 0, 0, 0 } ++ resolver.netbios_request[12..46] ++
            [_]u8{ 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 0 } ++ [_]u8{entries.len};
        for (entries) |e| {
            var name: [15]u8 = @splat(' ');
            @memcpy(name[0..e[0].len], e[0]);
            packet = packet ++ name ++ [_]u8{ e[1], e[2], 0 };
        }
        const final = packet[0..packet.len].*;
        return &final;
    }
}

test "netbiosName takes the first unique workstation or server name" {
    const reply = comptime netbiosReply(&.{
        .{ "WORKGROUP", 0x00, 0x80 }, // a group name
        .{ "NAS", 0x03, 0x00 }, // the messenger service
        .{ "NAS", 0x20, 0x00 },
    });
    try std.testing.expectEqualStrings("NAS", resolver.netbiosName(reply) orelse return error.NoName);
}

test "netbiosName skips names that are not printable ASCII" {
    const reply = comptime netbiosReply(&.{
        .{ "\x1b[2J", 0x00, 0x00 },
        .{ "BOX", 0x00, 0x00 },
    });
    try std.testing.expectEqualStrings("BOX", resolver.netbiosName(reply) orelse return error.NoName);
}

test "netbiosName rejects replies to another query, and short ones" {
    var reply = (comptime netbiosReply(&.{.{ "BOX", 0x00, 0x00 }}))[0..].*;
    reply[0] ^= 0xff;
    try std.testing.expect(resolver.netbiosName(&reply) == null);
    try std.testing.expect(resolver.netbiosName(reply[0..56]) == null);
}

test "udpExchangeAll ends as soon as the port refuses" {
    const io = std.testing.io;
    // A port nothing listens on: bound, then released.
    const addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    const socket = addr.bind(io, .{ .mode = .dgram }) catch return error.SkipZigTest;
    const port = socket.address.getPort();
    socket.close(io);

    var reply: [64]u8 = undefined;
    var exchange = [1]c_bindings.UdpExchange{.init(port, "hello", &reply)};
    const started = std.Io.Clock.now(.awake, io);
    c_bindings.udpExchangeAll(.{ 127, 0, 0, 1 }, &exchange, 5000);
    const elapsed_ms = started.durationTo(std.Io.Clock.now(.awake, io)).toMilliseconds();
    try std.testing.expect(exchange[0].reply() == null);
    // The loopback refusal takes microseconds; the wait would take 5s.
    try std.testing.expect(elapsed_ms < 2500);
}
