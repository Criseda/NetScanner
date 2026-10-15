//! Reading the neighbor (ARP) table through the parent process
//! (`--neighbor-table=parent`).
//!
//! macOS 27 hides the kernel's neighbor table from a child of an app
//! that is not Developer ID signed: `ns` then reads it as empty, losing
//! MAC addresses, manufacturers and the quiet hosts the ARP harvest
//! finds. The app itself can still read it. So with this mode, instead
//! of reading the table, `ns` asks its parent for it over the pipes it
//! already has, and everything else (which entries prove a host, the
//! confirming pings, the OUI lookup) stays here:
//!
//!   ns  -> stdout: {"type":"neighbors_request","id":1}
//!   app -> stdin:  {"type":"neighbors","id":1,"entries":[
//!                    {"ip":"192.168.1.1","mac":"aa:bb:cc:dd:ee:ff","state":"stale"}]}
//!
//! A parent that cannot read the table answers `{"type":"neighbors",
//! "id":1,"error":"..."}`. Either way, and when no answer comes in
//! time, the scan falls back to reading the table itself, exactly as
//! without the flag. The protocol is documented in docs/README.md.

const std = @import("std");
const builtin = @import("builtin");
const utils = @import("utils.zig");
const Neighbor = @import("bindings").Neighbor;

/// How long to wait for each answer before reading the table locally.
/// Reading the table takes the parent a millisecond; this only guards
/// against a parent that never answers.
pub const default_timeout_ms: u32 = 2000;

/// A reply larger than this is not a neighbor table (a few hundred
/// entries are ~30 KiB); stop buffering rather than grow without end.
const max_reply_bytes = 16 * 1024 * 1024;

/// The parent's side of the conversation. One per scan, owned by the
/// caller; the scan only ever asks from one thread at a time.
pub const Parent = struct {
    /// Where replies arrive: stdin, or a pipe in tests.
    input: std.posix.fd_t = if (builtin.os.tag == .windows) undefined else std.posix.STDIN_FILENO,
    timeout_ms: u32 = default_timeout_ms,
    next_id: u32 = 1,
    /// Set once the parent missed a deadline or closed stdin: later
    /// reads go straight to the kernel instead of waiting again.
    gave_up: bool = false,
    /// Bytes read past the last full line.
    pending: std.ArrayList(u8) = .empty,

    pub fn deinit(self: *Parent, allocator: std.mem.Allocator) void {
        self.pending.deinit(allocator);
    }

    /// Ask the parent for the table and wait for its answer. Null when
    /// there is no answer to use (it failed, timed out, or sent
    /// something unreadable); the caller then reads the table itself.
    /// The result is owned by `allocator`.
    pub fn request(self: *Parent, allocator: std.mem.Allocator, io: std.Io, stdout_mutex: *std.Io.Mutex) ?[]Neighbor {
        if (self.gave_up) return null;
        const id = self.next_id;
        self.next_id += 1;
        utils.printStdout(io, stdout_mutex, "{{\"type\":\"neighbors_request\",\"id\":{d}}}\n", .{id});
        return self.awaitReply(allocator, io, id);
    }

    /// The reply to request `id`, skipping replies to earlier requests
    /// that arrived after their deadline.
    pub fn awaitReply(self: *Parent, allocator: std.mem.Allocator, io: std.Io, id: u32) ?[]Neighbor {
        const started = std.Io.Clock.now(.awake, io);
        while (true) {
            const waited_ms = @divTrunc(started.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds, std.time.ns_per_ms);
            const left_ms = @as(i64, self.timeout_ms) - @as(i64, @intCast(waited_ms));
            const line = self.readLine(allocator, @intCast(@max(left_ms, 0))) catch |err| {
                std.debug.print("neighbor table: no answer from the parent ({s}); reading it directly\n", .{@errorName(err)});
                self.gave_up = true;
                return null;
            };
            defer allocator.free(line);
            const reply = parseReply(allocator, line, id) catch {
                std.debug.print("neighbor table: unreadable answer from the parent; reading it directly\n", .{});
                return null;
            };
            switch (reply) {
                .table => |table| return table,
                .failed => return null,
                .earlier => continue,
            }
        }
    }

    /// The next line of input without its newline, owned by
    /// `allocator`. Waits at most `timeout_ms` for it to complete.
    fn readLine(self: *Parent, allocator: std.mem.Allocator, timeout_ms: u32) ![]u8 {
        if (comptime builtin.os.tag == .windows) return error.Unsupported;
        var searched: usize = 0;
        while (true) {
            if (std.mem.indexOfScalarPos(u8, self.pending.items, searched, '\n')) |end| {
                const line = try allocator.dupe(u8, self.pending.items[0..end]);
                self.pending.replaceRangeAssumeCapacity(0, end + 1, &.{});
                return line;
            }
            searched = self.pending.items.len;
            if (searched > max_reply_bytes) return error.ReplyTooLarge;

            var fds = [_]std.posix.pollfd{.{ .fd = self.input, .events = std.posix.POLL.IN, .revents = 0 }};
            if (try std.posix.poll(&fds, @intCast(timeout_ms)) == 0) return error.Timeout;
            var chunk: [64 * 1024]u8 = undefined;
            const n = try std.posix.read(self.input, &chunk);
            if (n == 0) return error.EndOfStream;
            try self.pending.appendSlice(allocator, chunk[0..n]);
        }
    }
};

pub const Reply = union(enum) {
    /// The table, owned by the caller's allocator.
    table: []Neighbor,
    /// The parent could not read the table either.
    failed,
    /// An answer to an earlier request that came after its deadline.
    earlier,
};

/// Decode one reply line for request `id`. Entries the kernel reader
/// would also leave out (multicast, 0.x and broadcast-MAC rows) are
/// dropped here, so a parent may send the table as it read it.
/// Malformed entries are skipped; a malformed reply is an error.
pub fn parseReply(allocator: std.mem.Allocator, line: []const u8, id: u32) error{ InvalidReply, OutOfMemory }!Reply {
    const Entry = struct {
        ip: []const u8,
        mac: ?[]const u8 = null,
        state: ?[]const u8 = null,
    };
    const Message = struct {
        type: []const u8,
        id: u32,
        entries: ?[]const Entry = null,
        @"error": ?[]const u8 = null,
    };
    const parsed = std.json.parseFromSlice(Message, allocator, line, .{ .ignore_unknown_fields = true }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidReply,
    };
    defer parsed.deinit();
    const message = parsed.value;

    if (!std.mem.eql(u8, message.type, "neighbors")) return error.InvalidReply;
    if (message.id < id) return .earlier;
    if (message.id != id) return error.InvalidReply;
    if (message.@"error" != null) return .failed;
    const entries = message.entries orelse return error.InvalidReply;

    var table: std.ArrayList(Neighbor) = try .initCapacity(allocator, entries.len);
    errdefer table.deinit(allocator);
    for (entries) |entry| {
        const ip = utils.ipStringToBytes(entry.ip) catch continue;
        if (ip[0] == 0 or ip[0] >= 224) continue;
        const mac: ?[6]u8 = if (entry.mac) |text| utils.parseMac(text) orelse continue else null;
        if (mac) |m| if (std.mem.eql(u8, &m, &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff })) continue;
        // Only an explicit "reachable" skips the confirming ping.
        const reachable = if (entry.state) |s| std.mem.eql(u8, s, "reachable") else false;
        table.appendAssumeCapacity(.{ .ip = ip, .mac = mac, .state = if (reachable) .reachable else .stale });
    }
    return .{ .table = try table.toOwnedSlice(allocator) };
}
