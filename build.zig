//! Build graph for Mbed TLS 3.6.7 from vendored `src/`; no build-time download.
//!
//! Each target builds three upstream archives from explicit source lists,
//! generates target configuration, translates 80 public headers and exposes
//! one `mbedtls` module.
//!
//! `zig/config_gen.zig` runs on the host with target facts. It writes
//! `mbed_tls_target_config.h` via `MBEDTLS_CONFIG_FILE`; the matching
//! configuration installs as `include/mbedtls/mbedtls_config.h`.
//!
//! `-Dsystem` is refused. `-Dlinkage` defaults to `.static`; `.dynamic`
//! requires a dynamic linker. `-Druntime` defaults false and selects dispatch
//! independently of linkage; call `load` before native calls.
//!
//! `zig build` installs libraries, headers, configuration, pkg-config and licences.
//! `test` and `smoke` run; `consumer` builds or runs its package; `check`
//! compiles six targets without running. Root `cross-test.profile.sh` configures them.

const std = @import("std");
const builtin = @import("builtin");

const manifest = @import("build.zig.zon");
const graph_runtime = @import("runtime/graph.zig");
const config_gen = @import("zig/config_gen.zig");

const manifest_version = std.SemanticVersion.parse(manifest.version) catch
    @panic("build.zig.zon .version is not a semantic version");

/// Upstream version from `src/include/mbedtls/build_info.h`; checked against the manifest.
const upstream_version = std.SemanticVersion{
    .major = 3,
    .minor = 6,
    .patch = 7,
};

/// Upstream shared-library ABI numbers from `src/library/Makefile`.
const crypto_abi = std.SemanticVersion{ .major = 16, .minor = 0, .patch = 0 };
const x509_abi = std.SemanticVersion{ .major = 7, .minor = 0, .patch = 0 };
const tls_abi = std.SemanticVersion{ .major = 21, .minor = 0, .patch = 0 };

const source_dir = "src";
const include_dir = "src/include";
const library_dir = "src/library";
const facade_source = "zig/root.zig";
const translate_header = "zig/translate.h";
const config_generator = "zig/config_gen.zig";
const upstream_config = "src/include/mbedtls/mbedtls_config.h";
const test_source = "tests.zig";
const smoke_source = "smoke.zig";

/// Dependency key is `mbed-tls`; module and archive names are upstream's.
const lib_name = "mbedcrypto";
const x509_name = "mbedx509";
const tls_name = "mbedtls";

// Explicit source lists follow upstream's CMake groups and order.

const crypto_sources = [_][]const u8{
    "src/library/aes.c",
    "src/library/aesni.c",
    "src/library/aesce.c",
    "src/library/aria.c",
    "src/library/asn1parse.c",
    "src/library/asn1write.c",
    "src/library/base64.c",
    "src/library/bignum.c",
    "src/library/bignum_core.c",
    "src/library/bignum_mod.c",
    "src/library/bignum_mod_raw.c",
    "src/library/block_cipher.c",
    "src/library/camellia.c",
    "src/library/ccm.c",
    "src/library/chacha20.c",
    "src/library/chachapoly.c",
    "src/library/cipher.c",
    "src/library/cipher_wrap.c",
    "src/library/constant_time.c",
    "src/library/cmac.c",
    "src/library/ctr_drbg.c",
    "src/library/des.c",
    "src/library/dhm.c",
    "src/library/ecdh.c",
    "src/library/ecdsa.c",
    "src/library/ecjpake.c",
    "src/library/ecp.c",
    "src/library/ecp_curves.c",
    "src/library/entropy.c",
    "src/library/entropy_poll.c",
    "src/library/error.c",
    "src/library/gcm.c",
    "src/library/hkdf.c",
    "src/library/hmac_drbg.c",
    "src/library/lmots.c",
    "src/library/lms.c",
    "src/library/md.c",
    "src/library/md5.c",
    "src/library/memory_buffer_alloc.c",
    "src/library/nist_kw.c",
    "src/library/oid.c",
    "src/library/padlock.c",
    "src/library/pem.c",
    "src/library/pk.c",
    "src/library/pk_ecc.c",
    "src/library/pk_wrap.c",
    "src/library/pkcs12.c",
    "src/library/pkcs5.c",
    "src/library/pkparse.c",
    // Present upstream but excluded from its CMake source lists.
    "src/library/pkwrite.c",
    "src/library/platform.c",
    "src/library/platform_util.c",
    "src/library/poly1305.c",
    "src/library/psa_crypto.c",
    "src/library/psa_crypto_aead.c",
    "src/library/psa_crypto_cipher.c",
    "src/library/psa_crypto_client.c",
    "src/library/psa_crypto_driver_wrappers_no_static.c",
    "src/library/psa_crypto_ecp.c",
    "src/library/psa_crypto_ffdh.c",
    "src/library/psa_crypto_hash.c",
    "src/library/psa_crypto_mac.c",
    "src/library/psa_crypto_pake.c",
    "src/library/psa_crypto_rsa.c",
    "src/library/psa_crypto_random.c",
    "src/library/psa_crypto_se.c",
    "src/library/psa_crypto_slot_management.c",
    "src/library/psa_crypto_storage.c",
    "src/library/psa_its_file.c",
    "src/library/psa_util.c",
    "src/library/ripemd160.c",
    "src/library/rsa.c",
    "src/library/rsa_alt_helpers.c",
    "src/library/sha1.c",
    "src/library/sha256.c",
    "src/library/sha512.c",
    "src/library/sha3.c",
    "src/library/threading.c",
    "src/library/timing.c",
    "src/library/version.c",
    "src/library/version_features.c",
};

/// Third-party units from upstream's Makefiles, linked into `libmbedcrypto`.
const thirdparty_sources = [_][]const u8{
    "src/3rdparty/everest/library/everest.c",
    "src/3rdparty/everest/library/x25519.c",
    "src/3rdparty/everest/library/Hacl_Curve25519_joined.c",
    "src/3rdparty/p256-m/p256-m_driver_entrypoints.c",
    "src/3rdparty/p256-m/p256-m/p256-m.c",
};

const thirdparty_includes = [_][]const u8{
    "src/3rdparty/everest/include",
    "src/3rdparty/everest/include/everest",
    "src/3rdparty/everest/include/everest/kremlib",
    "src/3rdparty/p256-m/p256-m",
    "src/library",
};

const x509_sources = [_][]const u8{
    "src/library/pkcs7.c",
    "src/library/x509.c",
    "src/library/x509_create.c",
    "src/library/x509_crl.c",
    "src/library/x509_crt.c",
    "src/library/x509_csr.c",
    "src/library/x509write.c",
    "src/library/x509write_crt.c",
    "src/library/x509write_csr.c",
};

const tls_sources = [_][]const u8{
    "src/library/debug.c",
    "src/library/mps_reader.c",
    "src/library/mps_trace.c",
    "src/library/net_sockets.c",
    "src/library/ssl_cache.c",
    "src/library/ssl_ciphersuites.c",
    "src/library/ssl_client.c",
    "src/library/ssl_cookie.c",
    "src/library/ssl_debug_helpers_generated.c",
    "src/library/ssl_msg.c",
    "src/library/ssl_ticket.c",
    "src/library/ssl_tls.c",
    "src/library/ssl_tls12_client.c",
    "src/library/ssl_tls12_server.c",
    "src/library/ssl_tls13_keys.c",
    "src/library/ssl_tls13_server.c",
    "src/library/ssl_tls13_client.c",
    "src/library/ssl_tls13_generic.c",
};

/// FreeBSD needs `__BSD_VISIBLE=1` for `explicit_bzero` under upstream's `_POSIX_C_SOURCE` (`src/library/platform_util.c:43-45`).
const freebsd_visibility_flag = "-D__BSD_VISIBLE=1";

/// Flags for targets other than FreeBSD.
const c_flags = [_][]const u8{
    "-std=c11",
    "-D_GNU_SOURCE",
};

/// Adds FreeBSD's visibility define.
const freebsd_c_flags = [_][]const u8{
    "-std=c11",
    "-D_GNU_SOURCE",
    freebsd_visibility_flag,
};

/// C11 with GNU extensions; FreeBSD also needs its visibility define.
fn cFlags(platform: Platform) []const []const u8 {
    return switch (platform.freebsd) {
        false => &c_flags,
        true => &freebsd_c_flags,
    };
}

/// Public headers installed by the build.
const public_headers = [_][]const u8{
    "src/include/mbedtls/aes.h",
    "src/include/mbedtls/aria.h",
    "src/include/mbedtls/asn1.h",
    "src/include/mbedtls/asn1write.h",
    "src/include/mbedtls/base64.h",
    "src/include/mbedtls/bignum.h",
    "src/include/mbedtls/block_cipher.h",
    "src/include/mbedtls/build_info.h",
    "src/include/mbedtls/camellia.h",
    "src/include/mbedtls/ccm.h",
    "src/include/mbedtls/chacha20.h",
    "src/include/mbedtls/chachapoly.h",
    "src/include/mbedtls/cipher.h",
    // Required by upstream's `build_info.h` in every configuration.
    "src/include/mbedtls/check_config.h",
    "src/include/mbedtls/cmac.h",
    "src/include/mbedtls/compat-2.x.h",
    "src/include/mbedtls/config_adjust_legacy_crypto.h",
    "src/include/mbedtls/config_adjust_legacy_from_psa.h",
    "src/include/mbedtls/config_adjust_psa_from_legacy.h",
    "src/include/mbedtls/config_adjust_psa_superset_legacy.h",
    "src/include/mbedtls/config_adjust_ssl.h",
    "src/include/mbedtls/config_adjust_x509.h",
    "src/include/mbedtls/config_psa.h",
    "src/include/mbedtls/constant_time.h",
    "src/include/mbedtls/ctr_drbg.h",
    "src/include/mbedtls/debug.h",
    "src/include/mbedtls/des.h",
    "src/include/mbedtls/dhm.h",
    "src/include/mbedtls/ecdh.h",
    "src/include/mbedtls/ecdsa.h",
    "src/include/mbedtls/ecjpake.h",
    "src/include/mbedtls/ecp.h",
    "src/include/mbedtls/entropy.h",
    "src/include/mbedtls/error.h",
    "src/include/mbedtls/gcm.h",
    "src/include/mbedtls/hkdf.h",
    "src/include/mbedtls/hmac_drbg.h",
    "src/include/mbedtls/lms.h",
    "src/include/mbedtls/md.h",
    "src/include/mbedtls/md5.h",
    "src/include/mbedtls/memory_buffer_alloc.h",
    "src/include/mbedtls/net_sockets.h",
    "src/include/mbedtls/nist_kw.h",
    "src/include/mbedtls/oid.h",
    "src/include/mbedtls/pem.h",
    "src/include/mbedtls/pk.h",
    "src/include/mbedtls/pkcs12.h",
    "src/include/mbedtls/pkcs5.h",
    "src/include/mbedtls/pkcs7.h",
    "src/include/mbedtls/platform.h",
    "src/include/mbedtls/platform_time.h",
    "src/include/mbedtls/platform_util.h",
    "src/include/mbedtls/poly1305.h",
    "src/include/mbedtls/psa_util.h",
    // Included by public headers; install it with them.
    "src/include/mbedtls/private_access.h",
    "src/include/mbedtls/ripemd160.h",
    "src/include/mbedtls/rsa.h",
    "src/include/mbedtls/sha1.h",
    "src/include/mbedtls/sha256.h",
    "src/include/mbedtls/sha3.h",
    "src/include/mbedtls/sha512.h",
    "src/include/mbedtls/ssl.h",
    "src/include/mbedtls/ssl_cache.h",
    "src/include/mbedtls/ssl_ciphersuites.h",
    "src/include/mbedtls/ssl_cookie.h",
    "src/include/mbedtls/ssl_ticket.h",
    "src/include/mbedtls/threading.h",
    "src/include/mbedtls/timing.h",
    "src/include/mbedtls/version.h",
    "src/include/mbedtls/x509.h",
    "src/include/mbedtls/x509_crl.h",
    "src/include/mbedtls/x509_crt.h",
    "src/include/mbedtls/x509_csr.h",
    "src/include/psa/build_info.h",
    // Included by installed PSA headers.
    "src/include/psa/crypto_config.h",
    "src/include/psa/crypto_adjust_auto_enabled.h",
    "src/include/psa/crypto_adjust_config_dependencies.h",
    "src/include/psa/crypto_adjust_config_key_pair_types.h",
    "src/include/psa/crypto_adjust_config_synonyms.h",
    "src/include/psa/crypto.h",
    "src/include/psa/crypto_builtin_composites.h",
    "src/include/psa/crypto_builtin_key_derivation.h",
    "src/include/psa/crypto_builtin_primitives.h",
    "src/include/psa/crypto_compat.h",
    "src/include/psa/crypto_driver_common.h",
    "src/include/psa/crypto_driver_contexts_composites.h",
    "src/include/psa/crypto_driver_contexts_key_derivation.h",
    "src/include/psa/crypto_driver_contexts_primitives.h",
    "src/include/psa/crypto_extra.h",
    "src/include/psa/crypto_legacy.h",
    "src/include/psa/crypto_platform.h",
    "src/include/psa/crypto_se_driver.h",
    "src/include/psa/crypto_sizes.h",
    "src/include/psa/crypto_struct.h",
    "src/include/psa/crypto_types.h",
    "src/include/psa/crypto_values.h",
};

/// Licence and provenance records installed with the package.
const licence_records = [_][]const u8{
    "src/LICENSE",
    "NOTICE.md",
    "FORK-LICENSE.md",
    "UPSTREAM.md",
    "README.upstream.md",
};

/// Compile targets. The generator disables `MBEDTLS_NET_C` for WASI.
/// `check` compiles only; `test` runs where an executor is available.
const check_targets = [_]std.Target.Query{
    .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu },
    .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .gnu },
    .{ .cpu_arch = .aarch64, .os_tag = .macos, .abi = .none },
    .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .gnu },
    .{ .cpu_arch = .riscv64, .os_tag = .linux, .abi = .gnu },
    .{ .cpu_arch = .wasm32, .os_tag = .wasi },
};

/// Targets refused by this build; currently none.
const refused_check_targets = [_]std.Target.Query{};

fn refusalFor(os_tag: std.Target.Os.Tag) ?[]const u8 {
    _ = os_tag;
    return null;
}

fn refuseTarget(b: *std.Build, target: std.Target.Os.Tag) noreturn {
    const reason = refusalFor(target) orelse @panic("refuseTarget called for a target this build accepts");
    std.debug.panic("{s}", .{b.fmt(
        "mbed-tls: refusing {s}: this package has no buildable configuration for it ({s})",
        .{ @tagName(target), reason },
    )});
}

fn checkMatrixPartition(b: *std.Build) void {
    for (check_targets) |query| {
        const resolved = b.resolveTargetQuery(query);
        if (refusalFor(resolved.result.os.tag) != null) {
            @panic(b.fmt(
                "build.zig: {s} is in check_targets but this build refuses its operating system",
                .{resolved.result.zigTriple(b.allocator) catch @panic("unspellable check target")},
            ));
        }
    }
    for (refused_check_targets) |query| {
        const resolved = b.resolveTargetQuery(query);
        if (refusalFor(resolved.result.os.tag) == null) {
            @panic(b.fmt(
                "build.zig: {s} is in refused_check_targets but refusalFor no longer refuses it; move it to check_targets and prove it builds",
                .{resolved.result.zigTriple(b.allocator) catch @panic("unspellable check target")},
            ));
        }
    }
}

/// Target facts that affect C flags, linkage, or archive naming.
const Platform = struct {
    /// Target has a dynamic linker.
    dynamic_linker: bool,
    /// Target is Windows.
    windows: bool,
    /// Target uses a separate `libm`.
    separate_m: bool,
    /// Target uses a separate `libdl`.
    separate_dl: bool,
    /// Target uses Mach-O load paths.
    macho: bool,
    /// FreeBSD needs visibility for upstream's `explicit_bzero`.
    freebsd: bool,

    fn forTarget(target: std.Target) Platform {
        return .{
            .dynamic_linker = std.Target.DynamicLinker.kind(target.os.tag) != .none,
            .windows = target.os.tag == .windows,
            .freebsd = target.os.tag == .freebsd,
            // Record target-specific libm and libdl dependencies for consumers.
            .separate_m = switch (target.os.tag) {
                .linux, .freebsd, .netbsd, .openbsd, .dragonfly, .illumos => true,
                else => false,
            },
            .separate_dl = switch (target.os.tag) {
                .linux, .freebsd, .illumos => true,
                else => false,
            },
            .macho = switch (target.ofmt) {
                .macho => true,
                else => false,
            },
        };
    }

    fn describe(self: Platform, target: std.Target) []const u8 {
        _ = target;
        if (self.windows) return "windows: a module definition file states the export list";
        if (self.macho) return "macOS: @loader_path, no version script";
        if (self.freebsd) return "FreeBSD: __BSD_VISIBLE restated for explicit_bzero";
        if (self.separate_m and self.separate_dl) return "unix with separate libm and libdl";
        return "unix";
    }
};

/// Target configuration produced by `generateTargetConfig`.
const GeneratedConfig = struct {
    /// Include directory containing the generated header.
    directory: std.Build.LazyPath,
    /// Generated header used by compile, translation and install.
    header: std.Build.LazyPath,
};

/// Run the host generator with resolved target facts and return its output paths.
/// Consumers of the header must depend on the generator step.
fn generateTargetConfig(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) GeneratedConfig {
    const generator = b.addExecutable(.{
        .name = b.fmt("mbed-tls-config-gen-{s}", .{
            target.result.zigTriple(b.allocator) catch @panic("unspellable target"),
        }),
        .root_module = b.createModule(.{
            .root_source_file = b.path(config_generator),
            // The host runs it; it writes about the target.
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });

    const run = b.addRunArtifact(generator);
    run.setName(b.fmt("generate the configuration for {s}", .{
        target.result.zigTriple(b.allocator) catch @panic("unspellable target"),
    }));

    run.addArg("--upstream");
    run.addFileArg(b.path(upstream_config));
    run.addArg("--output");
    const header = run.addOutputFileArg(config_gen.output_basename);

    // Pass resolved target, CPU, ABI, endianness and pointer width to the generator.
    run.addArg("--triple");
    run.addArg(target.result.zigTriple(b.allocator) catch @panic("unspellable target"));
    run.addArg("--arch");
    run.addArg(@tagName(target.result.cpu.arch));
    run.addArg("--os");
    run.addArg(@tagName(target.result.os.tag));
    run.addArg("--abi");
    run.addArg(@tagName(target.result.abi));
    run.addArg("--endian");
    run.addArg(if (target.result.cpu.arch.endian() == .big) "big" else "little");
    run.addArg("--ptr-bits");
    run.addArg(if (std.Target.ptrBitWidth(&target.result) == 64) "64" else "32");

    _ = optimize;

    return .{
        .directory = header.dirname(),
        .header = header,
    };
}

fn add_library(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    platform: Platform,
    generated: GeneratedConfig,
    name: []const u8,
    sources: []const []const u8,
    abi: ?std.SemanticVersion,
    /// Earlier archive dependencies, in link order.
    below: []const ?*std.Build.Step.Compile,
    public: bool,
    /// Requested archive linkage after target compatibility checks.
    requested: std.builtin.LinkMode,
) *std.Build.Step.Compile {
    const linkage = deliveredLinkage(target, requested);
    const lib = b.addLibrary(.{
        .name = if (public) name else b.fmt("{s}-{s}", .{
            name,
            target.result.zigTriple(b.allocator) catch @panic("unspellable target"),
        }),
        .linkage = linkage,
        .version = if (linkage == .dynamic) abi else null,
        // Export upstream's public symbol prefixes in Windows DLLs.
        .win32_module_definition = if (linkage == .dynamic and platform.windows)
            b.addWriteFiles().add(b.fmt("{s}.def", .{name}),
                \\EXPORTS
                \\    mbedtls_*
                \\    psa_*
                \\    PSA_*
                \\    MBEDTLS_*
                \\
            )
        else
            null,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            // The source closure requires libc.
            .link_libc = true,
            .pic = if (linkage == .dynamic) true else null,
        }),
    });
    const m = lib.root_module;

    // Resolve upstream's `MBEDTLS_CONFIG_FILE` against this target's generated config.
    m.addIncludePath(generated.directory);
    m.addCMacro("MBEDTLS_CONFIG_FILE", b.fmt("\"{s}\"", .{config_gen.output_basename}));

    // Add upstream source and public include directories.
    m.addIncludePath(b.path(library_dir));
    m.addIncludePath(b.path(include_dir));
    for (thirdparty_includes) |dir| {
        m.addIncludePath(b.path(dir));
    }

    // FreeBSD gets its target-specific visibility define.
    const flags = cFlags(platform);
    for (sources) |source| {
        m.addCSourceFile(.{ .file = b.path(source), .flags = flags });
    }

    // Link dependent archives in upstream order.
    for (below) |dependency| {
        if (dependency) |other| m.linkLibrary(other);
    }

    if (platform.separate_m) m.linkSystemLibrary("m", .{});
    if (linkage == .dynamic and platform.separate_dl) m.linkSystemLibrary("dl", .{});

    // Upstream requires `ws2_32` and `bcrypt` imports on Windows (`src/library/CMakeLists.txt`).
    if (platform.windows) {
        m.linkSystemLibrary("ws2_32", .{});
        m.linkSystemLibrary("bcrypt", .{});
    }

    if (linkage == .dynamic and target.result.ofmt == .elf) setVersionScript(b, lib, name);

    // Ensure this compile waits for its generated configuration header.
    generated.header.addStepDependencies(&lib.step);

    return lib;
}

fn setVersionScript(b: *std.Build, lib: *std.Build.Step.Compile, name: []const u8) void {
    const files = b.addWriteFiles();
    lib.setVersionScript(files.add(b.fmt("{s}.map", .{name}), b.fmt(
        \\MBEDTLS_{s} {{
        \\  global:
        \\    mbedtls_*;
        \\    psa_*;
        \\    PSA_*;
        \\    MBEDTLS_*;
        \\  local:
        \\    *;
        \\}};
        \\
    , .{name})));
}

const TargetGraph = struct {
    crypto: *std.Build.Step.Compile,
    x509: *std.Build.Step.Compile,
    tls: *std.Build.Step.Compile,
    /// Public facade module.
    module: *std.Build.Module,
    /// Target config shared by compile, translation and install.
    generated: GeneratedConfig,
};

fn addGraph(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    linkage: std.builtin.LinkMode,
    runtime_loaded: bool,
    public: bool,
) TargetGraph {
    const platform = Platform.forTarget(target.result);
    const generated = generateTargetConfig(b, target, optimize);

    const crypto = add_library(
        b,
        target,
        optimize,
        platform,
        generated,
        lib_name,
        crypto_sources[0..] ++ thirdparty_sources[0..],
        crypto_abi,
        &.{ null, null, null },
        public,
        linkage,
    );
    const x509 = add_library(
        b,
        target,
        optimize,
        platform,
        generated,
        x509_name,
        x509_sources[0..],
        x509_abi,
        &.{ crypto, null, null },
        public,
        linkage,
    );
    const tls = add_library(
        b,
        target,
        optimize,
        platform,
        generated,
        tls_name,
        tls_sources[0..],
        tls_abi,
        &.{ crypto, x509, null },
        public,
        linkage,
    );

    // Translate the same target-configured public headers used by C compilation.
    const translate = b.addTranslateC(.{
        .root_source_file = b.path(translate_header),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    translate.addIncludePath(generated.directory);
    translate.defineCMacro("MBEDTLS_CONFIG_FILE", b.fmt("\"{s}\"", .{config_gen.output_basename}));
    translate.addIncludePath(b.path(include_dir));
    generated.header.addStepDependencies(&translate.step);

    const translated = translate.createModule();

    // Register one public module; check graphs use private modules to avoid duplicate names.
    const module = if (public)
        b.addModule(tls_name, .{
            .root_source_file = b.path(facade_source),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        })
    else
        b.createModule(.{
            .root_source_file = b.path(facade_source),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });

    // Runtime mode imports generated dispatch and does not link archives.
    // Linked mode imports translated C and core types, then links all three archives.
    if (runtime_loaded) {
        module.addImport("c", graph_runtime.createModule(b, translate, target, optimize));
    } else {
        module.addImport("c", translated);
        module.addImport("rt", graph_runtime.createCoreModule(b, target, optimize));
        module.linkLibrary(crypto);
        module.linkLibrary(x509);
        module.linkLibrary(tls);
    }
    // Expose public headers to dependents' C compilation.
    module.addIncludePath(b.path(include_dir));

    // Build and install archives in both linked and runtime-dispatch modes.
    for ([_]*std.Build.Step.Compile{ crypto, x509, tls }) |lib| {
        generated.header.addStepDependencies(&lib.step);
    }

    return .{
        .crypto = crypto,
        .x509 = x509,
        .tls = tls,
        .module = module,
        .generated = generated,
    };
}

fn targetHasDynamicLinker(target: std.Build.ResolvedTarget) bool {
    return std.Target.DynamicLinker.kind(target.result.os.tag) != .none;
}

fn deliveredLinkage(
    target: std.Build.ResolvedTarget,
    requested: std.builtin.LinkMode,
) std.builtin.LinkMode {
    if (requested == .dynamic and !targetHasDynamicLinker(target)) {
        std.debug.panic(
            "mbed-tls: -Dlinkage=dynamic was asked for {s}, which has no dynamic " ++
                "loader; handing back an archive under that name would be a result " ++
                "the caller did not ask for and cannot tell from support.",
            .{@tagName(target.result.os.tag)},
        );
    }
    return requested;
}

fn add_install(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    platform: Platform,
    generated: GeneratedConfig,
    graph: TargetGraph,
    linkage: std.builtin.LinkMode,
) void {
    b.installArtifact(graph.crypto);
    b.installArtifact(graph.x509);
    b.installArtifact(graph.tls);

    for (public_headers) |header| {
        // Preserve `mbedtls/` and `psa/` include paths in the install tree.
        const sub = if (std.mem.indexOf(u8, header, "/psa/") != null)
            "psa"
        else
            "mbedtls";
        const base = std.fs.path.basename(header);
        // Attach each generated install step to the default install step.
        const installed = b.addInstallFileWithDir(
            b.path(header),
            .header,
            b.fmt("{s}/{s}", .{ sub, base }),
        );
        b.getInstallStep().dependOn(&installed.step);
    }

    // Install upstream's generated config as `mbedtls_config.h` for consumers.
    // This keeps the installed headers aligned with the linked archives.
    const installed_config = b.addInstallFileWithDir(
        generated.header,
        .header,
        b.fmt("mbedtls/{s}", .{std.fs.path.basename(upstream_config)}),
    );
    b.getInstallStep().dependOn(&installed_config.step);

    add_pkg_config(b, target, platform, linkage);

    for (licence_records) |record| {
        const installed_record = b.addInstallFileWithDir(
            b.path(record),
            .prefix,
            b.fmt("share/licenses/mbed-tls/{s}", .{std.fs.path.basename(record)}),
        );
        b.getInstallStep().dependOn(&installed_record.step);
    }
}

fn add_pkg_config(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    platform: Platform,
    linkage: std.builtin.LinkMode,
) void {
    const files = b.addWriteFiles();
    // Attach generated pkg-config metadata to the install graph.
    const requires = b.fmt("{s}", .{
        if (linkage == .dynamic) "libmbedtls.so.21 libmbedx509.so.7 libmbedcrypto.so.16 " else "",
    });
    const libs = b.fmt("{s}{s}{s}", .{
        "-lmbedtls -lmbedx509 -lmbedcrypto",
        if (platform.separate_m) " -lm" else "",
        if (linkage == .dynamic and platform.separate_dl) " -ldl" else "",
    });
    const pc = files.add("mbedtls.pc", b.fmt(
        \\prefix=${{pcfiledir}}/../..
        \\exec_prefix=${{prefix}}
        \\libdir=${{exec_prefix}}/lib
        \\includedir=${{prefix}}/include
        \\
        \\Name: mbed-tls
        \\Description: Mbed TLS, the TLS and X.509 stack and its PSA Crypto core
        \\URL: https://github.com/Mbed-TLS/mbedtls
        \\Version: {f}
        \\Requires.private: {s}
        \\Libs: -L"${{libdir}}" {s}
        \\Cflags: -I"${{includedir}}"
        \\
    , .{ upstream_version, requires, libs }));
    b.getInstallStep().dependOn(&b.addInstallFileWithDir(pc, .lib, "pkgconfig/mbedtls.pc").step);
    _ = target;
}

fn add_target_check(
    b: *std.Build,
    step: *std.Build.Step,
    query: std.Target.Query,
    optimize: std.builtin.OptimizeMode,
    linkage: std.builtin.LinkMode,
    runtime_loaded: bool,
) void {
    const cross_target = b.resolveTargetQuery(query);
    // Refuse unsupported targets before choosing the library linkage.
    if (refusalFor(cross_target.result.os.tag) != null) {
        refuseTarget(b, cross_target.result.os.tag);
    }

    const triple = cross_target.result.zigTriple(b.allocator) catch @panic("unspellable target");
    const cross = addGraph(b, cross_target, optimize, linkage, runtime_loaded, false);

    // Call the facade so Zig analyzes its bodies for each check target.
    const test_mod = b.createModule(.{
        .root_source_file = b.path(test_source),
        .target = cross_target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_mod.addImport(tls_name, cross.module);
    // The test root embeds fixtures relative to the package root.
    test_mod.addAnonymousImport("mbed_tls_root", .{
        .root_source_file = b.path("tests.zig"),
    });
    step.dependOn(&b.addTest(.{
        .name = b.fmt("mbed-tls-tests-{s}", .{triple}),
        .root_module = test_mod,
    }).step);

    const example_mod = b.createModule(.{
        .root_source_file = b.path(smoke_source),
        .target = cross_target,
        .optimize = optimize,
        .link_libc = true,
    });
    example_mod.addImport(tls_name, cross.module);
    step.dependOn(&b.addExecutable(.{
        .name = b.fmt("mbed-tls-smoke-{s}", .{triple}),
        .root_module = example_mod,
    }).step);

    // Checks compile targets; they do not run tests or examples.
}

fn runConsumer(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    linkage: std.builtin.LinkMode,
    runtime_loaded: bool,
) *std.Build.Step.Run {
    // Use a nested build to avoid a cyclic manifest dependency.
    const run = b.addSystemCommand(&.{ b.graph.zig_exe, "build" });
    run.setName("consumer package");
    run.setCwd(b.path("consumer"));
    run.addArg(if (hostCanExecute(b, target)) "run" else "install");

    const triple = target.result.zigTriple(b.allocator) catch @panic("unspellable target");
    run.addArg(b.fmt("-Dtarget={s}", .{triple}));
    // The target triple does not encode the CPU model.
    const cpu = target.query.serializeCpuAlloc(b.allocator) catch
        @panic("the CPU model could not be serialized");
    run.addArg(b.fmt("-Dcpu={s}", .{cpu}));
    run.addArg(b.fmt("-Doptimize={s}", .{@tagName(optimize)}));
    run.addArg(b.fmt("-Dlinkage={s}", .{@tagName(linkage)}));
    run.addArg(b.fmt("-Druntime={s}", .{if (runtime_loaded) "true" else "false"}));

    if (b.enable_darling) run.addArg("-fdarling");
    if (b.enable_qemu) run.addArg("-fqemu");
    if (b.enable_rosetta) run.addArg("-frosetta");
    if (b.enable_wasmtime) run.addArg("-fwasmtime");
    if (b.enable_wine) run.addArg("-fwine");
    if (b.libc_runtimes_dir) |runtimes| run.addArgs(&.{ "--libc-runtimes", runtimes });

    run.addArg("-j8");
    run.addArg("--summary");
    run.addArg("all");
    if (b.cache_root.path) |cache| {
        run.addArg("--cache-dir");
        run.addArg(b.fmt("{s}/consumer", .{cache}));
    }
    if (b.graph.global_cache_root.path) |global_cache| {
        run.addArg("--global-cache-dir");
        run.addArg(global_cache);
    }
    if (!std.mem.eql(u8, b.install_prefix, b.pathFromRoot("zig-out"))) {
        run.addArg("--prefix");
        run.addArg(b.install_prefix);
    }
    if (b.args) |args| {
        run.addArg("--");
        run.addArgs(args);
    }
    run.has_side_effects = true;
    return run;
}

fn hostCanExecute(b: *std.Build, target: std.Build.ResolvedTarget) bool {
    // Run only native targets here; cross-test handles foreign executors.
    _ = b;
    return target.query.isNative();
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const system_default = b.option(
        bool,
        "system",
        "Link an installed Mbed TLS instead of compiling src/, and translate the " ++
            "installed headers instead of the bundled ones. Supplies the default " ++
            "of systemIntegrationOption(\"mbedtls\"); a build runner that decides " ++
            "the mode itself (-fsys=mbedtls) overrides it.",
    ) orelse false;
    const use_system = b.systemIntegrationOption(tls_name, .{ .default = system_default });

    const linkage_option = b.option(
        std.builtin.LinkMode,
        "linkage",
        "Which delivery of the three archives to build. The default is .static " ++
            "for a bundled graph, which is what upstream's own Makefile produces; " ++
            "a target with no dynamic linker refuses .dynamic rather than handing " ++
            "back an archive under that name.",
    );
    const linkage: std.builtin.LinkMode = linkage_option orelse .static;

    const runtime_loaded = b.option(
        bool,
        "runtime",
        "Resolve the native entry points at run time instead of linking them. " ++
            "This selects the dispatch, not the linkage: the archives are still " ++
            "built and installed, they are just not on the facade's link line, so " ++
            "a program built this way has to name a provider with an explicit " ++
            "load() before any native call.",
    ) orelse false;

    // Validate configuration before building the graph.
    if (manifest_version.order(upstream_version) != .eq) {
        @panic("build.zig.zon .version no longer matches the version read out " ++
            "of src/include/mbedtls/build_info.h; see UPSTREAM.md");
    }
    if (use_system) {
        @panic(
            "mbed-tls: this package has no system-library mode. -fsys=mbedtls / " ++
                "-Dsystem=true selects an installed libmbedcrypto whose headers " ++
                "and struct layouts are not the ones this package's graph builds, " ++
                "and a dependent would then be compiling bundled headers against a " ++
                "different library. See FORK-NOTES.md section 3.",
        );
    }
    checkMatrixPartition(b);

    const delivered = deliveredLinkage(target, linkage);
    const platform = Platform.forTarget(target.result);

    const graph = addGraph(b, target, optimize, delivered, runtime_loaded, true);
    add_install(b, target, platform, graph.generated, graph, delivered);

    // Report the resolved build configuration.
    std.debug.print(
        "mbed-tls {f} for {s}: {d} + {d} + {d} + {d} translation units, " ++
            "{s} linkage, {s} platform\n",
        .{
            upstream_version,
            target.result.zigTriple(b.allocator) catch @panic("unspellable target"),
            crypto_sources.len,
            thirdparty_sources.len,
            x509_sources.len,
            tls_sources.len,
            @tagName(delivered),
            platform.describe(target.result),
        },
    );
    if (delivered == .dynamic) {
        std.debug.print(
            "  shared objects carry upstream's own ABI numbers: " ++
                "libmbedcrypto.so.16, libmbedx509.so.7, libmbedtls.so.21\n",
            .{},
        );
    }
    if (runtime_loaded) {
        std.debug.print(
            "  -Druntime: the facade resolves its symbols through one " ++
                "process-lifetime table after an explicit load(); the archives " ++
                "are built and installed but are not on its link line.\n",
            .{},
        );
    } else {
        std.debug.print(
            "  linked: the facade's c import is the translation of " ++
                "zig/translate.h and the three archives are on its link line.\n",
            .{},
        );
    }

    const test_mod = b.createModule(.{
        .root_source_file = b.path(test_source),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_mod.addImport(tls_name, graph.module);
    const unit_tests = b.addTest(.{
        .name = "mbed-tls-tests",
        .root_module = test_mod,
    });
    const run_tests = b.addRunArtifact(unit_tests);
    run_tests.has_side_effects = true;
    b.step("test", "Run the behavioural tests for the selected target").dependOn(&run_tests.step);

    const example_mod = b.createModule(.{
        .root_source_file = b.path(smoke_source),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    example_mod.addImport(tls_name, graph.module);
    const example = b.addExecutable(.{
        .name = "mbed-tls-smoke",
        .root_module = example_mod,
    });
    // Build but do not install the example; run it via `smoke`.
    b.getInstallStep().dependOn(&example.step);

    const run_example = b.addRunArtifact(example);
    run_example.has_side_effects = true;
    if (b.args) |args| run_example.addArgs(args);
    b.step("smoke", "Run the deterministic example program").dependOn(&run_example.step);

    b.step("consumer", "Build or run the consumer/ package for the selected target").dependOn(
        &runConsumer(b, target, optimize, delivered, runtime_loaded).step,
    );

    const check_step = b.step(
        "check",
        "Compile the libraries, the facade, the tests and the example for each " ++
            "of the six cross targets without running any of them",
    );
    if (!target.query.isNative()) {
        add_target_check(b, check_step, target.query, optimize, delivered, runtime_loaded);
    } else {
        for (check_targets[0..]) |query| {
            add_target_check(b, check_step, query, optimize, delivered, runtime_loaded);
        }
    }
}
