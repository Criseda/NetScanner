const std = @import("std");
const c_bindings = @import("bindings");

test "c_bindings module imports correctly" {
    _ = c_bindings;
}

test "dumpArpTable reads the kernel table on macOS, null elsewhere" {
    const table = c_bindings.dumpArpTable(std.testing.allocator);
    defer if (table) |t| std.testing.allocator.free(t);
    // The test binary is unsigned and `zig` is its parent, so macOS
    // hands back an empty table; the sysctl itself must still succeed.
    if (@import("builtin").os.tag == .macos) {
        try std.testing.expect(table != null);
    } else {
        try std.testing.expect(table == null);
    }
}
