const std = @import("std");

test {
    _ = @import("utils_test.zig");
    _ = @import("scanner_test.zig");
    _ = @import("c_bindings_test.zig");
    _ = @import("ping_test.zig");
}
