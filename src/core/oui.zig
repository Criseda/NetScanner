//! Embedded OUI manufacturer database for NetScanner.
//! Parses an embedded Wireshark/IEEE `manuf` database at compile time,
//! baking the sorted binary search table directly into the binary's .rodata.

const std = @import("std");
const c_bindings = @import("bindings");

pub const OuiEntry = struct {
    prefix: [3]u8,
    vendor: []const u8,
};

/// The raw Wireshark manuf database file embedded directly into the compiler.
const embedded_manuf_raw = @embedFile("data/manuf.txt");

/// Comparison function for sorting OuiEntry slices in ascending prefix order.
pub fn ouiEntryLessThan(_: void, a: OuiEntry, b: OuiEntry) bool {
    for (0..3) |i| {
        if (a.prefix[i] < b.prefix[i]) return true;
        if (a.prefix[i] > b.prefix[i]) return false;
    }
    return false;
}

/// Parse a single line from a Wireshark `manuf` or IEEE OUI database file.
/// Supports comments (`#`), varying whitespace, and `:` or `-` hex octet delimiters.
/// Returns null for comments, blank lines, or malformed entries.
pub fn parseManufLine(raw_line: []const u8) ?OuiEntry {
    const line = std.mem.trim(u8, raw_line, " \t\r");
    if (line.len == 0 or line[0] == '#') return null;

    var tokens = std.mem.tokenizeAny(u8, line, " \t");
    const mac_str = tokens.next() orelse return null;
    const short_name = tokens.next() orelse return null;
    const rest = tokens.rest();
    const vendor_name = if (rest.len > 0) std.mem.trim(u8, rest, " \t") else short_name;

    var hex_iter = std.mem.tokenizeAny(u8, mac_str, ":-");
    const h0 = hex_iter.next() orelse return null;
    const h1 = hex_iter.next() orelse return null;
    const h2 = hex_iter.next() orelse return null;
    if (h0.len == 0 or h0.len > 2 or h1.len == 0 or h1.len > 2 or h2.len == 0 or h2.len > 2) return null;

    const b0 = std.fmt.parseInt(u8, h0, 16) catch return null;
    const b1 = std.fmt.parseInt(u8, h1, 16) catch return null;
    const b2 = std.fmt.parseInt(u8, h2, 16) catch return null;

    return OuiEntry{
        .prefix = .{ b0, b1, b2 },
        .vendor = vendor_name,
    };
}

/// Count valid entries at compile time to size the embedded table.
fn countEmbeddedEntries(comptime raw: []const u8) usize {
    @setEvalBranchQuota(1_000_000);
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |raw_line| {
        if (parseManufLine(raw_line) != null) {
            count += 1;
        }
    }
    return count;
}

/// Parse the embedded Wireshark manuf database at compile time.
/// Each vendor string slice points directly into the static embedded file in .rodata,
/// requiring zero memory allocation, zero runtime parsing, and zero startup delay.
fn parseEmbeddedDatabase(comptime raw: []const u8) [countEmbeddedEntries(raw)]OuiEntry {
    @setEvalBranchQuota(10_000_000);
    const total = countEmbeddedEntries(raw);
    var table: [total]OuiEntry = undefined;
    var count: usize = 0;

    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |raw_line| {
        if (parseManufLine(raw_line)) |entry| {
            table[count] = entry;
            count += 1;
        }
    }

    std.mem.sort(OuiEntry, &table, {}, ouiEntryLessThan);
    return table;
}

/// Embedded table evaluated at compile time, sorted ascending by prefix for binary search.
pub const EMBEDDED_OUIS: []const OuiEntry = &parseEmbeddedDatabase(embedded_manuf_raw);

fn comparePrefix(key: [3]u8, mid: OuiEntry) std.math.Order {
    for (0..3) |i| {
        if (key[i] < mid.prefix[i]) return .lt;
        if (key[i] > mid.prefix[i]) return .gt;
    }
    return .eq;
}

/// Search embedded table using binary search.
pub fn lookupEmbeddedVendor(mac: [6]u8) ?[]const u8 {
    const target = [3]u8{ mac[0], mac[1], mac[2] };
    const idx = std.sort.binarySearch(OuiEntry, EMBEDDED_OUIS, target, comparePrefix) orelse return null;
    return EMBEDDED_OUIS[idx].vendor;
}

pub const OuiDatabase = struct {
    allocator: std.mem.Allocator,
    custom_entries: ?std.ArrayList(OuiEntry) = null,

    pub fn init(allocator: std.mem.Allocator) OuiDatabase {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *OuiDatabase) void {
        if (self.custom_entries) |*entries| {
            for (entries.items) |e| {
                self.allocator.free(e.vendor);
            }
            entries.deinit(self.allocator);
            self.custom_entries = null;
        }
    }

    /// Load an external Wireshark `manuf` or standard IEEE OUI text file.
    /// Replaces any previously loaded custom entries and sorts entries for binary search.
    pub fn loadFile(self: *OuiDatabase, path: []const u8) !void {
        // Free any previously allocated custom entries before loading a new file.
        self.deinit();

        const path_z = try self.allocator.dupeZ(u8, path);
        defer self.allocator.free(path_z);
        const content = c_bindings.readFileContent(path_z.ptr) orelse return error.FileNotFound;
        defer c_bindings.freeFileContent(content);

        var list: std.ArrayList(OuiEntry) = .empty;
        errdefer {
            for (list.items) |e| self.allocator.free(e.vendor);
            list.deinit(self.allocator);
        }

        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |raw_line| {
            const entry = parseManufLine(raw_line) orelse continue;
            const duped_vendor = try self.allocator.dupe(u8, entry.vendor);
            try list.append(self.allocator, .{
                .prefix = entry.prefix,
                .vendor = duped_vendor,
            });
        }

        std.mem.sort(OuiEntry, list.items, {}, ouiEntryLessThan);

        self.custom_entries = list;
    }

    /// Look up the hardware vendor for a given MAC address.
    /// Checks the custom database if one was loaded; falls back to the embedded
    /// ~2,000 top-vendor table if not found or if no custom database was provided.
    pub fn lookup(self: OuiDatabase, mac: [6]u8) ?[]const u8 {
        if (self.custom_entries) |entries| {
            const target = [3]u8{ mac[0], mac[1], mac[2] };
            const idx = std.sort.binarySearch(OuiEntry, entries.items, target, comparePrefix) orelse return lookupEmbeddedVendor(mac);
            return entries.items[idx].vendor;
        }
        return lookupEmbeddedVendor(mac);
    }
};

test "lookup embedded vendor" {
    // Synology 00:11:32
    const syno_mac = [6]u8{ 0x00, 0x11, 0x32, 0x4f, 0xc2, 0x75 };
    const syno_vendor = lookupEmbeddedVendor(syno_mac);
    try std.testing.expect(syno_vendor != null);
    try std.testing.expectEqualStrings("Synology Incorporated", syno_vendor.?);

    // Raspberry Pi 2C:CF:67
    const pi_mac = [6]u8{ 0x2c, 0xcf, 0x67, 0x89, 0xea, 0x27 };
    const pi_vendor = lookupEmbeddedVendor(pi_mac);
    try std.testing.expect(pi_vendor != null);
    try std.testing.expectEqualStrings("Raspberry Pi (Trading) Ltd", pi_vendor.?);

    // Unknown MAC (locally administered 02:00:00)
    const unknown_mac = [6]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expectEqual(@as(?[]const u8, null), lookupEmbeddedVendor(unknown_mac));
}
