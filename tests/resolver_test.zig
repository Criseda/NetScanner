const std = @import("std");
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
