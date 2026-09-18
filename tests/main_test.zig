const std = @import("std");

test {
    _ = @import("utils_test.zig");
    _ = @import("scanner_test.zig");
    _ = @import("c_bindings_test.zig");
    _ = @import("ping_test.zig");
    _ = @import("oui_test.zig");
    _ = @import("resolver_test.zig");
}
