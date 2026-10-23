// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// See ../FORK-LICENSE.md for what that identifier covers.
//
//! Build graph for the independent Mbed TLS consumer.
//! It consumes the dependency module and embeds its published TLS fixtures.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Forward linkage and runtime options through local and nested runs.
    const linkage = b.option(
        std.builtin.LinkMode,
        "linkage",
        "Which delivery of libmbedtls, libmbedx509 and libmbedcrypto to check. " ++
            "Forwarded to the dependency; it decides the artifacts, never " ++
            "anything in this package.",
    ) orelse .static;
    const runtime_loaded = b.option(
        bool,
        "runtime",
        "Check the dependency's runtime-loading dispatch instead of a linked " ++
            "one. Forwarded to the dependency. A program built this way has to " ++
            "name a provider with an explicit load() before any native call, " ++
            "which is src/main.zig's business and not this file's.",
    ) orelse false;

    const dep = b.dependency("mbed-tls", .{
        .target = target,
        .optimize = optimize,
        .linkage = linkage,
        .runtime = runtime_loaded,
    });

    // System-integration flags are shared through the graph; no `-D` option is needed.

    // The dependency module carries its C-library requirement.
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("mbedtls", dep.module("mbedtls"));
    exe_mod.addImport("fixtures", addFixtureModule(b));

    const exe = b.addExecutable(.{
        .name = "mbedtls-consumer",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    const run_exe = b.addRunArtifact(exe);
    run_exe.has_side_effects = true;
    // Forward run arguments so `--provider` reaches `src/main.zig`.
    if (b.args) |args| run_exe.addArgs(args);
    const run_step = b.step("run", "Build and run the consumer program");
    run_step.dependOn(&run_exe.step);
}

/// Root source for the generated fixture module.
const fixture_module_source =
    \\//! Upstream's published TLS handshake fixture, embedded verbatim.
    \\//!
    \\//! Provenance: Mbed TLS 3.6.7 framework data files `test-ca.crt`,
    \\//! `server2.crt` and `server2.key`, shipped by this dependency in
    \\//! `fixtures/` and digested in its `UPSTREAM.sha256`. The build copies
    \\//! those three files next to this generated root byte for byte and writes
    \\//! no copy into the source tree.
    \\pub const ca = @embedFile("test-ca.crt");
    \\pub const server_cert = @embedFile("server2.crt");
    \\pub const server_key = @embedFile("server2.key");
    \\
;

/// Builds an in-package root that embeds the dependency's three fixtures.
fn addFixtureModule(b: *std.Build) *std.Build.Module {
    const files = b.addWriteFiles();
    const root = files.add("fixtures.zig", fixture_module_source);
    _ = files.addCopyFile(b.path("../fixtures/test-ca.crt"), "test-ca.crt");
    _ = files.addCopyFile(b.path("../fixtures/server2.crt"), "server2.crt");
    _ = files.addCopyFile(b.path("../fixtures/server2.key"), "server2.key");
    return b.createModule(.{ .root_source_file = root });
}
