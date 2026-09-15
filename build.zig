const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = buildExe(b, target, optimize);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the network scanner");
    run_step.dependOn(&run_cmd.step);

    const libs = buildLibraries(b, target, optimize);
    const test_module = b.createModule(.{
        .root_source_file = b.path("tests/main_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "core", .module = libs.core },
            .{ .name = "bindings", .module = libs.bindings },
        },
    });
    linkNativeDeps(b, test_module, target);
    const main_tests = b.addTest(.{ .root_module = test_module });

    const run_tests = b.addRunArtifact(main_tests);
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_tests.step);

    const release_step = b.step("release", "Build releases for all target platforms");
    for (releaseTargets()) |t| {
        const release_exe = buildExe(b, b.resolveTargetQuery(t.query), optimize);
        const install_release = b.addInstallArtifact(release_exe, .{
            .dest_dir = .{ .override = .{ .custom = t.dest_dir } },
        });
        release_step.dependOn(&install_release.step);
    }
}

const Libraries = struct {
    core: *std.Build.Module,
    bindings: *std.Build.Module,
};

/// The Zig half of NetScanner: core logic plus the C ping bindings.
/// Every binary (main, tests, each release) gets its own copy per target.
fn buildLibraries(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) Libraries {
    const core_module = b.createModule(.{
        .root_source_file = b.path("src/core/core.zig"),
        .target = target,
        .optimize = optimize,
    });
    const bindings_module = b.createModule(.{
        .root_source_file = b.path("src/c/c_bindings.zig"),
        .target = target,
        .optimize = optimize,
    });
    bindings_module.addImport("core", core_module);
    return .{ .core = core_module, .bindings = bindings_module };
}

/// Build the `ns` executable for one target.
fn buildExe(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Compile {
    const libs = buildLibraries(b, target, optimize);
    const exe_module = b.createModule(.{
        .root_source_file = b.path("src/core/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "core", .module = libs.core },
            .{ .name = "bindings", .module = libs.bindings },
        },
    });
    linkNativeDeps(b, exe_module, target);
    return b.addExecutable(.{ .name = "ns", .root_module = exe_module });
}

/// Everything compiled here also compiles ping.c and, on Windows, links
/// the system libraries ICMP needs.
fn linkNativeDeps(b: *std.Build, mod: *std.Build.Module, target: std.Build.ResolvedTarget) void {
    mod.addCSourceFile(.{ .file = b.path("src/c/ping.c"), .flags = &[_][]const u8{"-Wall"} });
    mod.addIncludePath(b.path("src/c"));
    mod.addIncludePath(b.path("."));
    if (target.result.os.tag == .windows) {
        mod.linkSystemLibrary("iphlpapi", .{});
        mod.linkSystemLibrary("ws2_32", .{});
    }
}

const ReleaseTarget = struct {
    query: std.Target.Query,
    dest_dir: []const u8,
};

/// The five platforms `zig build release` produces. Abi is left as
/// the default everywhere except Linux, where the docs use explicit
/// gnu; macOS especially must not pin one.
fn releaseTargets() [5]ReleaseTarget {
    return .{
        .{ .query = .{ .cpu_arch = .x86_64, .os_tag = .windows }, .dest_dir = "releases/windows" },
        .{ .query = .{ .cpu_arch = .x86_64, .os_tag = .macos }, .dest_dir = "releases/macos-x86_64" },
        .{ .query = .{ .cpu_arch = .aarch64, .os_tag = .macos }, .dest_dir = "releases/macos-arm64" },
        .{ .query = .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu }, .dest_dir = "releases/linux-x86_64" },
        .{ .query = .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .gnu }, .dest_dir = "releases/linux-arm64" },
    };
}
