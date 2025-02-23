const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "ns",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.addCSourceFile(.{ .file = b.path("src/ping.c"), .flags = &[_][]const u8{"-Wall"} });
    exe.addIncludePath(b.path("include"));

    // Link required system libraries
    switch (target.result.os.tag) {
        .windows => {
            exe.linkSystemLibrary("iphlpapi");
            exe.linkSystemLibrary("ws2_32");
        },
        else => {},
    }

    exe.linkLibC();
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the network scanner");
    run_step.dependOn(&run_cmd.step);
}
