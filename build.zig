const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Create a module for the core functionality
    const core_module = b.addModule("core", .{
        .root_source_file = b.path("src/core/core.zig"),
    });

    // Set up include directories
    const include_dirs = &[_][]const u8{
        "src/c",
        ".", // Add project root as well
    };

    // Create module for C bindings
    const bindings_module = b.addModule("bindings", .{
        .root_source_file = b.path("src/c/c_bindings.zig"),
    });

    // Add dependencies after creating the module
    bindings_module.addImport("core", core_module);

    // Main executable
    const exe = b.addExecutable(.{
        .name = "ns",
        .root_source_file = b.path("src/core/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addImport("core", core_module);
    exe.root_module.addImport("bindings", bindings_module);

    exe.addCSourceFile(.{ .file = b.path("src/c/ping.c"), .flags = &[_][]const u8{"-Wall"} });
    // Add ALL include paths
    for (include_dirs) |dir| {
        exe.addIncludePath(b.path(dir));
    }

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

    // Run command
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the network scanner");
    run_step.dependOn(&run_cmd.step);

    // Tests
    const main_tests = b.addTest(.{
        .root_source_file = b.path("tests/main_test.zig"),
        .target = target,
        .optimize = optimize,
    });

    main_tests.root_module.addImport("core", core_module);
    main_tests.root_module.addImport("bindings", bindings_module);
    main_tests.addCSourceFile(.{ .file = b.path("src/c/ping.c"), .flags = &[_][]const u8{"-Wall"} });
    // Add ALL include paths to test
    for (include_dirs) |dir| {
        main_tests.addIncludePath(b.path(dir));
    }

    // Link libraries for tests
    switch (target.result.os.tag) {
        .windows => {
            main_tests.linkSystemLibrary("iphlpapi");
            main_tests.linkSystemLibrary("ws2_32");
        },
        else => {},
    }
    main_tests.linkLibC();

    const run_tests = b.addRunArtifact(main_tests);
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_tests.step);

    // Release step
    const release_step = b.step("release", "Build releases for all target platforms");

    // Define all targets
    // Define all targets with proper ABI settings
    const targets = [_]std.zig.CrossTarget{
        // Windows (x86_64)
        .{
            .cpu_arch = .x86_64,
            .os_tag = .windows,
        },
        // macOS (x86_64)
        .{
            .cpu_arch = .x86_64,
            .os_tag = .macos,
            .abi = .none,
        },
        // macOS (ARM64/M1)
        .{
            .cpu_arch = .aarch64,
            .os_tag = .macos,
            .abi = .none,
        },
        // Linux (x86_64)
        .{
            .cpu_arch = .x86_64,
            .os_tag = .linux,
            .abi = .gnu,
        },
        // Linux (ARM64)
        .{
            .cpu_arch = .aarch64,
            .os_tag = .linux,
            .abi = .gnu,
        },
    };

    // Build for each target
    for (targets) |t| {
        const release_exe = createExecutable(b, t, optimize);

        // Create the destination directory path directly in the switch statement
        const dest_dir = switch (t.os_tag.?) {
            .windows => "releases/windows",
            .macos => switch (t.cpu_arch.?) {
                .x86_64 => "releases/macos-x86_64",
                .aarch64 => "releases/macos-arm64",
                else => unreachable,
            },
            .linux => switch (t.cpu_arch.?) {
                .x86_64 => "releases/linux-x86_64",
                .aarch64 => "releases/linux-arm64",
                .arm => "releases/linux-arm32",
                else => unreachable,
            },
            else => unreachable,
        };

        const install_release = b.addInstallArtifact(release_exe, .{
            .dest_dir = .{ .override = .{ .custom = dest_dir } },
        });

        release_step.dependOn(&install_release.step);
    }
}

fn createExecutable(b: *std.Build, target_cross: std.zig.CrossTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    // Create a module for the core functionality
    const core_module = b.addModule("core", .{
        .root_source_file = b.path("src/core/core.zig"),
    });

    // Set up include directories
    const include_dirs = &[_][]const u8{
        "src/c",
        ".", // Add project root as well
    };

    // Create module for C bindings
    const bindings_module = b.addModule("bindings", .{
        .root_source_file = b.path("src/c/c_bindings.zig"),
    });

    // Add dependencies after creating the module
    bindings_module.addImport("core", core_module);

    // Convert CrossTarget to ResolvedTarget
    const resolved_target = b.resolveTargetQuery(target_cross);

    // Create the executable
    const exe = b.addExecutable(.{
        .name = "ns",
        .root_source_file = b.path("src/core/main.zig"),
        .target = resolved_target,
        .optimize = optimize,
    });

    exe.root_module.addImport("core", core_module);
    exe.root_module.addImport("bindings", bindings_module);

    exe.addCSourceFile(.{ .file = b.path("src/c/ping.c"), .flags = &[_][]const u8{"-Wall"} });

    // Add include paths
    for (include_dirs) |dir| {
        exe.addIncludePath(b.path(dir));
    }

    // Link required system libraries
    switch (target_cross.os_tag.?) {
        .windows => {
            exe.linkSystemLibrary("iphlpapi");
            exe.linkSystemLibrary("ws2_32");
        },
        else => {},
    }

    exe.linkLibC();
    return exe;
}
