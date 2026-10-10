const std = @import("std");
const multicast = @import("core").multicast;
const c_bindings = @import("bindings");

test "services_query asks for _services._dns-sd._udp.local PTR" {
    const expected = [_]u8{ 0x4E, 0x53, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 } ++
        [_]u8{9} ++ "_services" ++ [_]u8{7} ++ "_dns-sd" ++ [_]u8{4} ++ "_udp" ++ [_]u8{5} ++ "local" ++
        [_]u8{ 0, 0, 12, 0, 1 };
    try std.testing.expectEqualSlices(u8, expected, multicast.services_query);
}

test "ssdp_search is a well-formed M-SEARCH for everything" {
    try std.testing.expect(std.mem.startsWith(u8, multicast.ssdp_search, "M-SEARCH * HTTP/1.1\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, multicast.ssdp_search, "ST: ssdp:all\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, multicast.ssdp_search, "MAN: \"ssdp:discover\"\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, multicast.ssdp_search, "\r\n\r\n"));
}

test "reverseQuery names the address backwards under in-addr.arpa" {
    var buf: [64]u8 = undefined;
    const query = multicast.reverseQuery(&buf, .{ 192, 168, 1, 10 });
    const expected = [_]u8{ 0x4E, 0x54, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 } ++
        [_]u8{2} ++ "10" ++ [_]u8{1} ++ "1" ++ [_]u8{3} ++ "168" ++ [_]u8{3} ++ "192" ++
        [_]u8{7} ++ "in-addr" ++ [_]u8{4} ++ "arpa" ++ [_]u8{ 0, 0, 12, 0, 1 };
    try std.testing.expectEqualSlices(u8, expected, query);
    // The longest address still fits the buffer.
    _ = multicast.reverseQuery(&buf, .{ 255, 255, 255, 255 });
}

test "classify tells SSDP and DNS replies from everything else" {
    try std.testing.expectEqual(multicast.Kind.ssdp, multicast.classify("HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n\r\n").?);
    try std.testing.expectEqual(multicast.Kind.ssdp, multicast.classify("http/1.1 200 ok\r\n\r\n").?);
    const response = [_]u8{ 0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0 };
    try std.testing.expectEqual(multicast.Kind.mdns, multicast.classify(&response).?);
    // A query (QR clear) proves nothing about the sender's state.
    try std.testing.expect(multicast.classify(multicast.services_query) == null);
    try std.testing.expect(multicast.classify(multicast.ssdp_search) == null);
    try std.testing.expect(multicast.classify("short") == null);
    try std.testing.expect(multicast.classify("") == null);
}

/// An mDNS response header with the given section counts.
fn header(qd: u8, an: u8, ar: u8) [12]u8 {
    return .{ 0, 0, 0x84, 0, 0, qd, 0, an, 0, 0, 0, ar };
}

test "hostName reads the answer to a reverse query" {
    const packet = header(1, 1, 0) ++
        // Question: 10.1.168.192.in-addr.arpa PTR IN (offset 12)
        [_]u8{2} ++ "10" ++ [_]u8{1} ++ "1" ++ [_]u8{3} ++ "168" ++ [_]u8{3} ++ "192" ++
        [_]u8{7} ++ "in-addr" ++ [_]u8{4} ++ "arpa" ++ [_]u8{ 0, 0, 12, 0, 1 } ++
        // Answer: owner points at the question's name, PTR -> printer.local
        [_]u8{ 0xC0, 12, 0, 12, 0x80, 1, 0, 0, 0, 120, 0, 15 } ++
        [_]u8{7} ++ "printer" ++ [_]u8{5} ++ "local" ++ [_]u8{0};
    var out: [256]u8 = undefined;
    try std.testing.expectEqualStrings("printer.local", multicast.hostName(packet, .{ 192, 168, 1, 10 }, &out).?);
    // The same answer names nobody at another address.
    try std.testing.expect(multicast.hostName(packet, .{ 192, 168, 1, 11 }, &out) == null);
}

test "hostName reads the owner of the sender's address record" {
    const packet = header(0, 1, 1) ++
        // Answer: _services._dns-sd._udp.local PTR _ipp._tcp.local (name at offset 12, "local" at 35)
        [_]u8{9} ++ "_services" ++ [_]u8{7} ++ "_dns-sd" ++ [_]u8{4} ++ "_udp" ++ [_]u8{5} ++ "local" ++ [_]u8{0} ++
        [_]u8{ 0, 12, 0, 1, 0, 0, 0, 120, 0, 12 } ++
        [_]u8{4} ++ "_ipp" ++ [_]u8{4} ++ "_tcp" ++ [_]u8{ 0xC0, 35 } ++
        // Additional: tv.local A 192.168.1.20, "local" compressed (offset 35)
        [_]u8{2} ++ "tv" ++ [_]u8{ 0xC0, 35 } ++ [_]u8{ 0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 192, 168, 1, 20 };
    var out: [256]u8 = undefined;
    try std.testing.expectEqualStrings("tv.local", multicast.hostName(packet, .{ 192, 168, 1, 20 }, &out).?);
    try std.testing.expect(multicast.hostName(packet, .{ 192, 168, 1, 21 }, &out) == null);
}

test "hostName rejects malformed and hostile names" {
    var out: [256]u8 = undefined;
    const from = [4]u8{ 10, 0, 0, 1 };
    // A name that points at itself.
    const loop = header(0, 1, 0) ++ [_]u8{ 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 10, 0, 0, 1 };
    try std.testing.expect(multicast.hostName(&loop, from, &out) == null);
    // An escape character in the name, for a terminal to obey.
    const escape = header(0, 1, 0) ++ [_]u8{ 3, 'a', 0x1B, 'b', 0, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 10, 0, 0, 1 };
    try std.testing.expect(multicast.hostName(&escape, from, &out) == null);
    // A record running past the end of the packet.
    const truncated = header(0, 1, 0) ++ [_]u8{ 1, 'a', 0, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 10 };
    try std.testing.expect(multicast.hostName(&truncated, from, &out) == null);
    try std.testing.expect(multicast.hostName("", from, &out) == null);
}

test "localAddress finds no attached subnet for loopback or TEST-NET-1" {
    // Loopback interfaces are skipped, and 192.0.2.0/24 is never assigned.
    try std.testing.expect(c_bindings.MulticastSocket.localAddress(.{ 127, 0, 0, 1 }, .{ 127, 0, 0, 254 }) == null);
    try std.testing.expect(c_bindings.MulticastSocket.localAddress(.{ 192, 0, 2, 1 }, .{ 192, 0, 2, 254 }) == null);
}

test "a discovery socket opens, times out quietly and closes" {
    const socket = c_bindings.MulticastSocket.open(.{ 127, 0, 0, 1 }) orelse return error.SkipZigTest;
    defer socket.close();
    var buf: [512]u8 = undefined;
    try std.testing.expect((try socket.recv(10, &buf)) == null);
}
