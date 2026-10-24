// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// See FORK-LICENSE.md for what that identifier covers.
//
//! Build graph for Mbed TLS runtime loading.
//! Do not link the native archive into the dispatch module.

const std = @import("std");

/// Must match the prefixes in `runtime/sync.c` and `runtime/library.zig`.
/// Change all three to support another instance in one process.
const sync_prefix = "mbedtls_rt";

/// Route Mbed TLS entry points under the `mbedtls_` and `psa_` prefixes.
const provider_prefix = "mbedtls_,psa_";

/// No libc symbols are routed; the positive prefix rule selects Mbed TLS only.
const libc_noise = "";

/// Upstream declares these APIs even though their implementations are disabled.
/// `config_gen.zig` preserves the three disabled upstream options on every target.
const provider_optional =
    // MBEDTLS_MEMORY_BUFFER_ALLOC_C: src/library/memory_buffer_alloc.c:10.
    "mbedtls_memory_buffer_alloc_init,mbedtls_memory_buffer_alloc_free," ++
    "mbedtls_memory_buffer_set_verify,mbedtls_memory_buffer_alloc_verify," ++
    "mbedtls_memory_buffer_alloc_self_test," ++
    // MBEDTLS_PSA_CRYPTO_SE_C: src/library/psa_crypto_se.c:11.
    "psa_register_se_driver," ++
    // MBEDTLS_PSA_INJECT_ENTROPY: src/library/psa_crypto.c:8115.
    "mbedtls_psa_inject_entropy," ++
    // Declared at src/include/psa/crypto.h:4013 and :4078 (verify_bytes/verify_key); no implementation in 3.6.7.
    "psa_key_derivation_verify_bytes,psa_key_derivation_verify_key";

const provider_excluded = "";

/// Builds the shared loader core used by linked and runtime-loaded facades.
pub fn createCoreModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("runtime/loader.zig"),
        .target = target,
        .optimize = optimize,
        // The Unix loader uses libc's `dlopen`.
        .link_libc = true,
    });
}

/// Builds the runtime `c` module from this target's translation.
pub fn createModule(
    b: *std.Build,
    translate: *std.Build.Step.TranslateC,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
) *std.Build.Module {
    const core = createCoreModule(b, target, optimize);

    const library = b.createModule(.{
        .root_source_file = b.path("runtime/library.zig"),
        .target = target,
        .optimize = optimize,
    });
    library.addImport("rt", core);

    return createDispatchModule(b, translate, target, optimize, core, library);
}

const GeneratedSources = struct {
    native: std.Build.LazyPath,
    dispatch: std.Build.LazyPath,
};

fn createDispatchModule(
    b: *std.Build,
    translate: *std.Build.Step.TranslateC,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    core: *std.Build.Module,
    library: *std.Build.Module,
) *std.Build.Module {
    const sources = generateDispatch(b, translate, target);

    const dispatch = b.createModule(.{
        .root_source_file = sources.dispatch,
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    dispatch.addImport("rt", core);
    dispatch.addImport("library", library);
    // Use the patched translation so nested declarations resolve routed wrappers.
    const native = b.createModule(.{
        .root_source_file = sources.native,
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    native.addImport("c_routed", dispatch);
    dispatch.addImport("c_native", native);
    dispatch.addCSourceFiles(.{
        .files = &.{"runtime/sync.c"},
        .flags = &.{b.fmt("-DRT_SYNC_PREFIX={s}", .{sync_prefix})},
        .language = .c,
    });
    return dispatch;
}

fn generateDispatch(
    b: *std.Build,
    translate: *std.Build.Step.TranslateC,
    target: std.Build.ResolvedTarget,
) GeneratedSources {
    const generator = b.addExecutable(.{
        .name = b.fmt("mbed-tls-runtime-generate-{s}", .{
            target.result.zigTriple(b.allocator) catch @panic("unspellable target"),
        }),
        .root_module = b.createModule(.{
            .root_source_file = b.path("runtime/generate.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });

    const run = b.addRunArtifact(generator);
    run.addArg("--library");
    run.addArg("mbedtls");
    run.addArg("--translate");
    run.addFileArg2(translate.getOutput(), .{});
    if (provider_prefix.len != 0) {
        run.addArg("--prefix");
        run.addArg(provider_prefix);
    }
    if (libc_noise.len != 0) {
        run.addArg("--noise");
        run.addArg(libc_noise);
    }
    if (provider_optional.len != 0) {
        run.addArg("--optional");
        run.addArg(provider_optional);
    }
    if (provider_excluded.len != 0) {
        run.addArg("--exclude");
        run.addArg(provider_excluded);
    }
    run.addArg("--native-output");
    const native_source = run.addOutputFileArg2("native.zig", .{});
    run.addArg("--output");
    const dispatch_source = run.addOutputFileArg2("dispatch.zig", .{});
    return .{ .native = native_source, .dispatch = dispatch_source };
}
