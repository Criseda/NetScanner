const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = buildExe(b, target, optimize);
    const install_exe = b.addInstallArtifact(exe, .{});
    b.getInstallStep().dependOn(installAndSign(b, install_exe, .bin, target));

    // Note: on macOS `zig build run` never sees the ARP table (MAC and
    // manufacturer columns stay blank) because `zig` is the parent
    // process; run ./zig-out/bin/ns from a shell instead (see
    // installAndSign).
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
        const release_target = b.resolveTargetQuery(t.query);
        const release_exe = buildExe(b, release_target, optimize);
        const dest_dir: std.Build.InstallDir = .{ .custom = t.dest_dir };
        const install_release = b.addInstallArtifact(release_exe, .{
            .dest_dir = .{ .override = dest_dir },
        });
        release_step.dependOn(installAndSign(b, install_release, dest_dir, release_target));
    }
}

/// Reverse-DNS identifier `ns` is codesigned with on macOS.
const CODESIGN_IDENTIFIER = "io.github.criseda.netscanner";

/// macOS binaries need signing, and only a macOS host has `codesign`.
fn needsCodesign(b: *std.Build, target: std.Build.ResolvedTarget) bool {
    return target.result.os.tag == .macos and b.graph.host.result.os.tag == .macos;
}

/// Install an artifact and, for macOS, ad-hoc codesign the installed
/// copy with a reverse-DNS identifier. Returns the step to depend on.
///
/// Why: macOS 27 hides the kernel neighbour (ARP) table from
/// third-party binaries unless they carry a real code identity. The
/// linker's default signature and plain `codesign -s -` (identifier
/// `ns-<hash>`) both get an empty table, which blanks the MAC and
/// manufacturer columns and the quiet-host ARP harvest. The table is
/// also hidden when a third-party program (rather than a shell) is the
/// parent process, which no signature fixes. An ad-hoc signature needs
/// no Apple developer account. The installed copy is signed, never the
/// cached one, so the build cache stays untouched.
///
/// Cross-building macOS releases on Linux or Windows leaves them
/// unsigned (no `codesign` there); build releases on a Mac.
fn installAndSign(
    b: *std.Build,
    install: *std.Build.Step.InstallArtifact,
    dest_dir: std.Build.InstallDir,
    target: std.Build.ResolvedTarget,
) *std.Build.Step {
    if (!needsCodesign(b, target)) return &install.step;
    const sign = b.addSystemCommand(&.{ "codesign", "--force", "--sign", "-", "--identifier", CODESIGN_IDENTIFIER });
    sign.addArg(b.getInstallPath(dest_dir, install.artifact.out_filename));
    sign.step.dependOn(&install.step);
    return &sign.step;
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
    // scanner.zig calls into the C helpers through the bindings
    // module, so core needs the import edge (bindings itself needs
    // nothing from core).
    core_module.addImport("bindings", bindings_module);
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
    mod.addCSourceFile(.{ .file = b.path("src/c/resolver.c"), .flags = &[_][]const u8{"-Wall"} });
    mod.addIncludePath(b.path("src/c"));
    mod.addIncludePath(b.path("."));
    if (target.result.os.tag == .windows) {
        // Winsock TCP probing with a timeout (see tcp_probe.h).
        mod.addCSourceFile(.{ .file = b.path("src/c/tcp_probe.c"), .flags = &[_][]const u8{"-Wall"} });
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
