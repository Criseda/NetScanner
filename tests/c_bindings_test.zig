const std = @import("std");
const c_bindings = @import("bindings");

test "c_bindings module imports correctly" {
    _ = c_bindings;
}
