const std = @import("std");
const c_bindings = @import("bindings");

// Test the ping_host C function
test "ping_host returns boolean" {
    const result = c_bindings.pingHost("8.8.8.8");
    _ = result;
}

test "ping_host handles null input" {
    const result = c_bindings.pingHost(null);
    try std.testing.expectEqual(false, result);
}
