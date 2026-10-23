// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// See ../FORK-LICENSE.md for what that identifier covers.
//
//! Build graph for the independent Mbed TLS consumer.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const linkage = b.option(
        std.lang.LinkMode,
        "linkage",
        "Library linkage forwarded to the dependency",
    ) orelse .static;
    const runtime_loaded = b.option(
        bool,
        "runtime",
        "Use explicit runtime loading through the dependency module",
    ) orelse false;

    const dep = b.dependency("mbed-tls", .{
        .target = target,
        .optimize = optimize,
        .linkage = linkage,
        .runtime = runtime_loaded,
    });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("mbedtls", dep.module("mbedtls"));
    exe_mod.addImport("fixtures", addFixtureModule(b, dep));

    const exe = b.addExecutable(.{
        .name = "mbedtls-consumer",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    const run_exe = b.addRunArtifact(exe);
    run_exe.has_side_effects = true;
    run_exe.addPassthruArgs();
    b.step("run", "Build and run the consumer program").dependOn(&run_exe.step);
}

/// Embeds the dependency's published TLS fixtures in a generated module.
fn addFixtureModule(b: *std.Build, dep: *std.Build.Dependency) *std.Build.Module {
    const files = b.addWriteFiles();
    const root = files.add(
        "fixtures.zig",
        \\pub const ca = @embedFile("test-ca.crt");
        \\pub const server_cert = @embedFile("server2.crt");
        \\pub const server_key = @embedFile("server2.key");
        \\
    );
    _ = files.addCopyFile(dep.path("fixtures/test-ca.crt"), "test-ca.crt");
    _ = files.addCopyFile(dep.path("fixtures/server2.crt"), "server2.crt");
    _ = files.addCopyFile(dep.path("fixtures/server2.key"), "server2.key");
    return b.createModule(.{ .root_source_file = root });
}
