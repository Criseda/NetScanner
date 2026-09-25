//! Shared reader for the lookup tables NetScanner embeds in .rodata
//! (oui.bin, ports.bin). The generators in scripts/ write both with one
//! layout: a 24-byte little-endian header, a table of fixed-size records
//! sorted by key, and a string pool the records point into. Everything is
//! validated at compile time, so a bad or truncated file fails the build
//! instead of a lookup.

const std = @import("std");

pub const HEADER_SIZE = 24;

pub const Header = struct {
    magic: [4]u8,
    version: u32,
    entry_count: u32,
    table_offset: u32,
    strings_offset: u32,
    strings_len: u32,
};

/// A validated table: the raw record bytes and the string pool.
pub const Table = struct {
    entry_count: usize,
    record_size: usize,
    records: []const u8,
    strings: []const u8,

    /// The bytes of record `index` (caller keeps index < entry_count).
    pub fn record(self: Table, index: usize) []const u8 {
        const start = index * self.record_size;
        return self.records[start .. start + self.record_size];
    }
};

/// Parse `bytes` and check its header against the expected magic,
/// format version and record size. Called at comptime only: any mismatch
/// is a compile error.
pub fn open(
    comptime bytes: []const u8,
    comptime magic: *const [4]u8,
    comptime version: u32,
    comptime record_size: usize,
) Table {
    if (bytes.len < HEADER_SIZE) @compileError("embedded table is smaller than its header");
    const header = Header{
        .magic = bytes[0..4].*,
        .version = std.mem.readInt(u32, bytes[4..8], .little),
        .entry_count = std.mem.readInt(u32, bytes[8..12], .little),
        .table_offset = std.mem.readInt(u32, bytes[12..16], .little),
        .strings_offset = std.mem.readInt(u32, bytes[16..20], .little),
        .strings_len = std.mem.readInt(u32, bytes[20..24], .little),
    };
    if (!std.mem.eql(u8, &header.magic, magic)) @compileError("embedded table has magic '" ++ &header.magic ++ "', expected '" ++ magic ++ "'");
    if (header.version != version) @compileError("unsupported embedded table format version");
    const table_end = @as(usize, header.table_offset) + @as(usize, header.entry_count) * record_size;
    if (table_end > bytes.len) @compileError("embedded table records extend beyond file size");
    if (header.strings_offset != table_end) @compileError("embedded table string pool does not start where the records end");
    if (@as(usize, header.strings_offset) + header.strings_len > bytes.len) @compileError("embedded table string pool extends beyond file size");
    return .{
        .entry_count = header.entry_count,
        .record_size = record_size,
        .records = bytes[header.table_offset..table_end],
        .strings = bytes[header.strings_offset .. header.strings_offset + header.strings_len],
    };
}
