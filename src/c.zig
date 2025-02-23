pub const c = @cImport({
    @cInclude("ping.h");
});

pub fn pingHost(ip: [*:0]const u8) bool {
    return c.ping_host(ip);
}
