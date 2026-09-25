//! Embedded TCP port names for NetScanner. The IANA service registry
//! (the official assignments) merged with a curated overlay of friendly
//! labels, categories and common unofficial uses, pre-packed by
//! scripts/generate_ports.py into ports.bin and embedded in .rodata.
//! See the generator for the record layout.

const std = @import("std");
const packed_db = @import("packed_db.zig");

/// What NetScanner knows about one TCP port.
pub const Service = struct {
    /// Short display name: the curated label ("RDP"), else the IANA
    /// service name ("ms-wbt-server").
    name: []const u8,
    /// The service name IANA assigns to this port for TCP. Null when the
    /// port is only known from common use, so callers can tell an
    /// official assignment from a de-facto one.
    iana: ?[]const u8,
    description: ?[]const u8,
    /// Coarse group for frontends (web, remote, file, ...). Only curated
    /// ports have one.
    category: ?[]const u8,
};

/// port u16, reserved u16, then label, iana, description and category as
/// u32 string-pool offsets.
const RECORD_SIZE = 20;

const db = packed_db.open(@embedFile("data/ports.bin"), "NSPT", 1, RECORD_SIZE);

pub const EMBEDDED_COUNT: usize = db.entry_count;

/// Look up a TCP port by binary search. No allocations; the returned
/// strings live in .rodata.
pub fn lookup(port: u16) ?Service {
    var low: usize = 0;
    var high: usize = db.entry_count;
    while (low < high) {
        const mid = low + (high - low) / 2;
        const key = portAt(mid);
        if (port < key) {
            high = mid;
        } else if (port > key) {
            low = mid + 1;
        } else {
            return decode(db.record(mid));
        }
    }
    return null;
}

/// The port of entry `index` (index < EMBEDDED_COUNT). Entries are sorted
/// by port, so this also lets tests walk the whole table.
pub fn portAt(index: usize) u16 {
    return std.mem.readInt(u16, db.record(index)[0..2], .little);
}

fn decode(record: []const u8) ?Service {
    const label = poolString(record[4..8]);
    const iana = poolString(record[8..12]);
    return .{
        .name = label orelse iana orelse return null,
        .iana = iana,
        .description = poolString(record[12..16]),
        .category = poolString(record[16..20]),
    };
}

/// The length-prefixed string a record field points at. Offset 0 is the
/// empty string, which means "none"; out-of-bounds offsets read as none
/// too rather than trusting the file.
fn poolString(field: *const [4]u8) ?[]const u8 {
    const offset: usize = std.mem.readInt(u32, field, .little);
    if (offset >= db.strings.len) return null;
    const len: usize = db.strings[offset];
    if (len == 0 or offset + 1 + len > db.strings.len) return null;
    return db.strings[offset + 1 .. offset + 1 + len];
}
