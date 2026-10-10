const std = @import("std");
const c_bindings = @import("bindings");

test "c_bindings module imports correctly" {
    _ = c_bindings;
}

test "dumpNeighbors reads the kernel table natively" {
    // netlink, GetIpNetTable2 and sysctl all need no privileges, so the
    // read itself must succeed. Its contents depend on the machine (on
    // macOS the unsigned test binary is handed an empty table).
    const table = c_bindings.dumpNeighbors(std.testing.allocator);
    try std.testing.expect(table != null);
    defer std.testing.allocator.free(table.?);
    for (table.?) |entry| {
        // Multicast and broadcast rows never come back.
        try std.testing.expect(entry.ip[0] != 0 and entry.ip[0] < 224);
        if (entry.mac) |mac| {
            const broadcast: [6]u8 = @splat(0xff);
            try std.testing.expect(!std.mem.eql(u8, &mac, &broadcast));
        }
    }
}
