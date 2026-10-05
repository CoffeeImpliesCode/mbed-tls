// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// See ../FORK-LICENSE.md for what that identifier covers.
//
//! Build wiring for the separate `consumer/` package.
//!
//! This package exists to prove one thing: that a dependent needs only
//! `dep.module("mbedtls")` and gets a working, correctly linked library. If the
//! facade module stopped carrying the three archives, or the translated
//! headers stopped matching the C source, or the `mbedtls` module stopped
//! resolving by name, this would stop building or stop producing the answers
//! its program checks - and nothing inside the library would notice.
//!
//! `src/main.zig` is the API role's file. This file is only the graph that
//! builds it, and it deliberately repeats almost nothing: the library decides
//! which artifacts are delivered, which platform macros they were compiled with
//! and which headers describe them, and this package learns all of that through
//! the dependency rather than by restating it.
//!
//! `zig build run` runs it. The parent package's `zig build consumer` runs or
//! installs this package as a nested build for the selected target, linkage and
//! dispatch mode -- it installs when this host cannot execute that target -- so
//! `zig build consumer -Dlinkage=dynamic` really does check the shared objects
//! and not the default archives.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The delivery and dispatch options are declared here rather than ignored,
    // so `zig build run -Dlinkage=dynamic` checks the shared objects instead of
    // silently checking the default archives, and so the parent package's
    // `zig build consumer` can pass a configuration through to the dependency
    // instead of dropping it on the floor.
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

    // The system mode is deliberately *not* a `-D` option here, and that is not
    // an omission. The dependency resolves it through
    // `b.systemIntegrationOption`, which is fed by the build runner's
    // `-fsys=`/`-fno-sys=` flags and is never an entry in the `-D` map, so a
    // `b.option` declared here would have to be threaded down as a dependency
    // option to reach the same answer. It does not need to be: a dependency
    // shares its parent's `Graph` (`lib/std/Build.zig:352`) and
    // `system_library_options` is a field of it (`:116`, read at `:2731`), so
    // the flag the runner was given reaches the dependency's own
    // `systemIntegrationOption` call unchanged.
    //
    // That is what the parent package's `zig build consumer` forwards, as the
    // mode it resolved, and it is also why `zig build run -fsys=mbed-tls` in this
    // directory is the same check stated directly. Both spellings reach the one
    // switch; neither is a second code path.

    // No `link_libc` here on purpose. The C requirement belongs to the library
    // module, which carries it; a dependent states its own, and this program
    // needs nothing beyond what the library already brings. Adding it here would
    // hide a library that forgot to declare it.
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
    // Forwarded so `zig build run -Druntime=true -- --provider <path>` reaches
    // `src/main.zig`, which reads exactly that and otherwise falls through to
    // `MBED_TLS_TEST_PROVIDER`. With no arguments this is inert, so a linked run
    // is unchanged.
    if (b.args) |args| run_exe.addArgs(args);
    const run_step = b.step("run", "Build and run the consumer program");
    run_step.dependOn(&run_exe.step);
}

/// The generated root of the `fixtures` module.
///
/// The three files are upstream's own published handshake data, shipped by the
/// parent package in `fixtures/`. They are declared here by name only; the
/// bytes are the build's verbatim copy of those files, never a second copy
/// written into this source tree.
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

/// Builds the `fixtures` module `src/main.zig` imports as `fixtures`.
///
/// A module root may not read outside its own package: the compiler answers
/// `embed of file outside package path` for an `@embedFile("../../fixtures/...")`
/// from `src/main.zig`, because the package that owns that file is this
/// directory and the data lives one level above it. Writing a three-declaration
/// root into a generated directory and copying the upstream files beside it
/// puts the embeds back inside the module, and the bytes stay the ones
/// `UPSTREAM.sha256` covers.
///
/// The copy is read out of the dependency's own tree by path, so nothing here
/// reaches into the library for anything but these three data files, and no
/// dependency edge is invented: the files are already part of the resolved
/// package.
fn addFixtureModule(b: *std.Build) *std.Build.Module {
    const files = b.addWriteFiles();
    const root = files.add("fixtures.zig", fixture_module_source);
    _ = files.addCopyFile(b.path("../fixtures/test-ca.crt"), "test-ca.crt");
    _ = files.addCopyFile(b.path("../fixtures/server2.crt"), "server2.crt");
    _ = files.addCopyFile(b.path("../fixtures/server2.key"), "server2.key");
    return b.createModule(.{ .root_source_file = root });
}