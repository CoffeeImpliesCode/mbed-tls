//! The build graph for the Mbed TLS SDK.
//!
//! Mbed TLS 3.6.7, compiled from the vendored release tarball in `src/`. There
//! is no CMake, no autotools, no Make and no build-time download anywhere in
//! this graph: `zig build` is the only entry point, and every byte it compiles
//! is in this repository.
//!
//! ## What one target graph produces
//!
//!   * Three archives, named the way upstream names them and in upstream's
//!     layering order: `libmbedcrypto`, `libmbedx509`, `libmbedtls`. Each is a
//!     complete `addLibrary` over its own explicit list of translation units,
//!     taken from `src/library/CMakeLists.txt`'s `src_crypto`, `src_x509` and
//!     `src_tls` lists rather than from a glob.
//!   * One **generated configuration header for that target**, written by
//!     `zig/config_gen.zig` in a dependent step. See "The generated
//!     configuration" below.
//!   * One translate-c step over `zig/translate.h`, which reaches eighty public
//!     headers.
//!   * One facade module, `mbedtls`, carrying the translation and linking all
//!     three archives. `zig/root.zig` is one source over one translation of
//!     all eighty public headers, so there is no per-layer surface to publish:
//!     a module called `mbedcrypto` would still declare the TLS API, and would
//!     still have to link `libmbedtls` for the wrappers that reach it. A
//!     dependent writes `dep.module("mbedtls")`, which is what `consumer/`
//!     is built to prove.
//!
//! ## The generated configuration
//!
//! Mbed TLS's configuration is the feature set *and* several struct layouts and
//! buffer sizes, and parts of it genuinely depend on which target is being
//! built. Upstream's own answer to that is its `Configure` script, which this
//! package does not run: it is Perl, it needs the host's answers, and it writes
//! into the source tree.
//!
//! Instead, `zig/config_gen.zig` is a host program that takes the *target's*
//! facts as command-line arguments - architecture, operating system, ABI,
//! endianness, pointer width - reads this package's own copy of upstream's
//! `src/include/mbedtls/mbedtls_config.h`, and writes one complete
//! `mbed_tls_target_config.h` for that target. It is reached through
//! `-DMBEDTLS_CONFIG_FILE='"mbed_tls_target_config.h"'`, which upstream documents
//! for exactly this purpose at `src/include/mbedtls/build_info.h:112-116`, with
//! the generated directory on the include path.
//!
//! **The name is deliberately not `mbedtls_config.h`.** `build_info.h` reaches
//! that name with a *quoted* include, which resolves beside `build_info.h`
//! before any `-I` directory is consulted, so a file of that name on the include
//! path would never be found. The generated file is therefore reached by name
//! through `MBEDTLS_CONFIG_FILE` and cannot shadow anything, and the four
//! target-derived decisions it applies are each anchored to an upstream line in
//! the generated file's own banner.
//!
//! The generated header is a build output and lands in the build cache like any
//! other. A separate copy of it *is* installed, as
//! `include/mbedtls/mbedtls_config.h`, because the configuration a dependent
//! compiles against has to be the configuration this library was built with;
//! `addInstallGeneratedConfig` below says how, and why that one is an install
//! while the build-internal name is not.
//!
//! ## Options
//!
//!   * `-Dsystem` - default false. Supplies the default of
//!     `systemIntegrationOption("mbedtls")`; a build runner that decides the mode
//!     itself (`-fsys=mbedtls`) overrides it. There is **no** system mode in this
//!     package yet: see FORK-NOTES.md. A `system` build is therefore refused at
//!     configure time rather than silently producing a bundled library under a
//!     system-mode spelling.
//!   * `-Dlinkage` - default `.static` for a bundled graph. `.dynamic` delivers
//!     shared objects. A target with no dynamic linker refuses `.dynamic` rather
//!     than handing back an archive under a name the caller did not ask for.
//!   * `-Druntime` - default false. Selects the *dispatch*, not the linkage: with
//!     it, the facade's `c` import is the generated runtime dispatch and the
//!     archive is **not** linked, so the symbols arrive through the platform
//!     loader after an explicit `load`. Linking the archive as well would let the
//!     linker resolve them statically and the runtime route would quietly become
//!     a linked one.
//!
//! ## Steps
//!
//!   * `zig build` - the default install step: the three archives, the public
//!     headers, the generated configuration, a pkg-config file and the licence
//!     records.
//!   * `zig build smoke` - run the deterministic example program.
//!   * `zig build test` - run the behavioural tests for whatever `-Dtarget`
//!     names, through an `addRunArtifact`, so a foreign target is left to
//!     whichever executor the cross-test harness detects and this build does not
//!     decide that.
//!   * `zig build consumer` - build or run the separate `consumer/` package.
//!   * `zig build check` - compile the libraries, the facade, the tests and the
//!     example for each of the six cross targets without running any of them.
//!
//! Nothing in this file reads `cross-test.profile.sh`; the harness discovers that
//! file by name from the package root.

const std = @import("std");
const builtin = @import("builtin");

const manifest = @import("build.zig.zon");
const graph_runtime = @import("runtime/graph.zig");
const config_gen = @import("zig/config_gen.zig");

const manifest_version = std.SemanticVersion.parse(manifest.version) catch
    @panic("build.zig.zon .version is not a semantic version");

/// The upstream version, as `src/include/mbedtls/build_info.h:27-29` states it
/// (and `:36-38` for the packed number and the two strings).
///
/// Kept as a value rather than parsed from the header because a build function
/// cannot read a source file, and compared against the manifest above so the two
/// cannot drift apart unnoticed.
const upstream_version = std.SemanticVersion{
    .major = 3,
    .minor = 6,
    .patch = 7,
};

/// The ABI numbers of the three shared objects, which upstream fixes in
/// `src/library/Makefile`: `SOEXT_TLS=so.21`, `SOEXT_X509=so.7`,
/// `SOEXT_CRYPTO=so.16`.
const crypto_abi = std.SemanticVersion{ .major = 16, .minor = 0, .patch = 0 };
const x509_abi = std.SemanticVersion{ .major = 7, .minor = 0, .patch = 0 };
const tls_abi = std.SemanticVersion{ .major = 21, .minor = 0, .patch = 0 };

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const source_dir = "src";
const include_dir = "src/include";
const library_dir = "src/library";
const facade_source = "zig/root.zig";
const translate_header = "zig/translate.h";
const config_generator = "zig/config_gen.zig";
const upstream_config = "src/include/mbedtls/mbedtls_config.h";
const test_source = "tests.zig";
const smoke_source = "smoke.zig";

/// The dependency-map key and the base of every module and artifact name.
///
/// A dependent writes `b.dependency("mbed-tls", ...)` - the hyphen, because the
/// directory has one - and then `dep.module("mbedtls")`, `dep.artifact("mbedtls")`
/// and so on. The three library names are upstream's own.
const lib_name = "mbedcrypto";
const x509_name = "mbedx509";
const tls_name = "mbedtls";

// ---------------------------------------------------------------------------
// The closure, as upstream lists it
//
// Explicit per-file lists, never globs: a glob would change what this package
// compiles the next time a file appears, and it would do so in a commit whose
// diff is one line. These are `src/library/CMakeLists.txt`'s `src_crypto`,
// `src_x509` and `src_tls`, in upstream's order.
// ---------------------------------------------------------------------------

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
    // `src/library/ecp_curves_new.c` is on disk and in no list, and that is
    // upstream's own decision: `src/library/CMakeLists.txt` says it is "kept
    // only for compatibility with custom build systems in LTS branches". It is
    // vendored because it is upstream's tree, and not compiled because no
    // supported build includes it. Saying so here is the difference between a
    // recorded decision and an omission a reader has to guess about.
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

/// The two `3rdparty` archives' units, from `3rdparty/Makefile.inc`,
/// `3rdparty/everest/Makefile.inc` and `3rdparty/p256-m/Makefile.inc`.
///
/// Compiled into `libmbedcrypto` because that is where upstream's
/// `src/library/Makefile` puts them (`OBJS_CRYPTO += $(THIRDPARTY_CRYPTO_OBJECTS)`),
/// not because this package needs them for its own surface.
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

/// The one FreeBSD-only define this build has to add, and why.
///
/// `src/library/platform_util.c:14-16` opens by defining `_POSIX_C_SOURCE
/// 200112L` on every platform except OpenBSD, so that `gmtime_r` survives
/// `-std=c11`. FreeBSD reads that same define in the opposite direction from
/// glibc: its `sys/_visible.h` (Zig's copy of FreeBSD 14's `sys/cdefs.h`
/// visibility block) takes the `_POSIX_C_SOURCE` branch at
/// `generic-freebsd/sys/_visible.h:123` and, on that branch, never defines
/// `__BSD_VISIBLE` at all - `generic-freebsd/strings.h:53-54` gates
/// `explicit_bzero` on exactly that macro. So `platform_util.c:43-45`, which
/// turns `MBEDTLS_PLATFORM_HAS_EXPLICIT_BZERO` on for FreeBSD >= 11.0.3,
/// then reaches a function its own header will not declare, and
/// `platform_util.c:98` fails with `call to undeclared function
/// 'explicit_bzero'`.
///
/// FreeBSD's own escape hatch is the macro, not a flag: `_visible.h:207`
/// defines `__BSD_VISIBLE 1` in the "default environment: show everything"
/// branch, and `_DEFAULT_SOURCE` does not reach that branch on this target -
/// verified against the pinned compiler, where `-D_DEFAULT_SOURCE` still
/// leaves `__BSD_VISIBLE` undefined while `-D__BSD_VISIBLE=1` compiles
/// `platform_util.c:98` cleanly. Restating the macro on the command line is
/// what upstream's own `Hacl_Curve25519_joined.c:21-28` does for the same
/// problem with `_BSD_SOURCE`/`_DEFAULT_SOURCE`, and it is the narrowest
/// statement: it re-opens the one declaration the closure calls, without
/// redefining `_POSIX_C_SOURCE` under upstream's feet or editing `src/`.
///
/// OpenBSD needs none of this: `platform_util.c:14` already excludes it from
/// the `_POSIX_C_SOURCE` define, and `generic-openbsd/sys/cdefs.h:430-431`
/// defaults `__BSD_VISIBLE` to 1. So the define is scoped to FreeBSD.
const freebsd_visibility_flag = "-D__BSD_VISIBLE=1";

/// The flags every target gets.
const c_flags = [_][]const u8{
    "-std=c11",
    "-D_GNU_SOURCE",
};

/// The same two, plus the one FreeBSD-only define.
const freebsd_c_flags = [_][]const u8{
    "-std=c11",
    "-D_GNU_SOURCE",
    freebsd_visibility_flag,
};

/// The C flags for one target.
///
/// C11, with the GNU extensions upstream's own flags ask for.
///
/// Upstream builds with the compiler's default standard plus warnings; there is
/// no `-std=` anywhere in `src/library/Makefile`. This pins one so it is a fact
/// of this build rather than a fact about whichever clang happens to be
/// installed, and `-D_GNU_SOURCE` because `net_sockets.c:33-68` reaches
/// `<netdb.h>`, `<sys/select.h>` and friends that glibc hides without it.
/// FreeBSD additionally needs `freebsd_visibility_flag`; every other target
/// gets the same two flags it always did.
fn cFlags(platform: Platform) []const []const u8 {
    return switch (platform.freebsd) {
        false => &c_flags,
        true => &freebsd_c_flags,
    };
}

/// The public headers, installed flat into `include/`.
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
    // `build_info.h:192` includes this one unconditionally, at the end of the
    // header and outside every `#if`, so no installed header is usable without
    // it. It was the next failure after `private_access.h` was added.
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
    // `private_access.h` is not optional: 40 of the headers installed below
    // reach it by quoted include (`src/include/mbedtls/sha256.h:15` is the
    // shortest), so without it a plain `#include <mbedtls/sha256.h>` against
    // the installed prefix alone fails on a missing file rather than on
    // anything the consumer did.
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
    // Reached from `build_info.h:138` and from `mbedtls/config_psa.h`, which
    // is itself installed. The four `crypto_adjust_*` headers are reached from
    // `config_psa.h` the same way. All five are in the installed closure
    // whether or not a consumer names them.
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

/// The licence and provenance records installed beside the libraries.
const licence_records = [_][]const u8{
    "src/LICENSE",
    "NOTICE.md",
    "FORK-LICENSE.md",
    "UPSTREAM.md",
    "README.upstream.md",
};

// ---------------------------------------------------------------------------
// The check matrix
// ---------------------------------------------------------------------------

/// The six cross targets `check` compiles for.
///
/// `wasm32-wasi` is in this list, not in `refused_check_targets`: Mbed TLS 3.6
/// compiles there, and the one boundary the platform imposes is expressed where
/// it belongs - `zig/config_gen.zig` turns `MBEDTLS_NET_C` off for it, so the
/// `mbedtls_net_*` transport has no symbols, and the tests that drive a loopback
/// socket are *compiled* by `check` and *run* only by `test`, which the
/// cross-test harness runs under wasmtime or reports as build-only.
const check_targets = [_]std.Target.Query{
    .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu },
    .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .gnu },
    .{ .cpu_arch = .aarch64, .os_tag = .macos, .abi = .none },
    .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .gnu },
    .{ .cpu_arch = .riscv64, .os_tag = .linux, .abi = .gnu },
    .{ .cpu_arch = .wasm32, .os_tag = .wasi },
};

/// Targets this build refuses outright.
///
/// None. The refusal mechanism is kept because it is how a target gets dropped
/// *deliberately* and recorded, rather than quietly: `checkMatrixPartition`
/// below panics if either list and `refusalFor` disagree, so moving a row out of
/// `check_targets` is a change with a name in it.
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

// ---------------------------------------------------------------------------
// Platform
// ---------------------------------------------------------------------------

/// Everything about a target that changes the C compile line or the way the
/// archives are named.
///
/// One function, consulted by the library, the translation, the install and the
/// configure-time print, so the six cross cells cannot drift from the published
/// one.
const Platform = struct {
    /// True where the target has a dynamic linker at all.
    dynamic_linker: bool,
    /// True on Windows, where the module definition file is how an export list
    /// is stated.
    windows: bool,
    /// True where `libm` is a separate library rather than part of libc.
    separate_m: bool,
    /// True where `libdl` is a separate library.
    separate_dl: bool,
    /// True on macOS, where an executable records its dependencies with
    /// `@loader_path` rather than `$ORIGIN`.
    macho: bool,
    /// True on FreeBSD, where this build has to restate the declaration
    /// environment FreeBSD's own headers otherwise narrow. See
    /// `freebsd_visibility_flag`.
    freebsd: bool,

    fn forTarget(target: std.Target) Platform {
        return .{
            .dynamic_linker = std.Target.DynamicLinker.kind(target.os.tag) != .none,
            .windows = target.os.tag == .windows,
            .freebsd = target.os.tag == .freebsd,
            // Upstream's own `library/Makefile` does not link either of these:
            // nothing in the closure calls into libm or dlopen. They are recorded
            // here because a shared object on glibc needs libm's symbols
            // resolved from somewhere, and a consumer linking the archive
            // statically inherits the dependency.
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

// ---------------------------------------------------------------------------
// The generated configuration
// ---------------------------------------------------------------------------

/// What `generateTargetConfig` produced for one target.
const GeneratedConfig = struct {
    /// The directory the generated header is in.
    ///
    /// `Step.Run.addOutputFileArg` creates a cache directory per run and returns
    /// a path inside it; that directory is what goes on the include path, because
    /// the header is reached by a bare name through `MBEDTLS_CONFIG_FILE`.
    directory: std.Build.LazyPath,
    /// The header itself, for the dependency edge and for the install copy.
    header: std.Build.LazyPath,
};

/// Runs `zig/config_gen.zig` for one target and returns what it wrote.
///
/// The generator is a host program, so it *runs* on the machine doing the build
/// while writing a header that describes the *target*: every fact it uses is an
/// argument, and `b.graph.host` appears in this function only as the generator's
/// own execution target. That is the distinction this whole mechanism rests on -
/// the host may compute, the target decides.
///
/// The returned `Run` step is not resolved here. It is attached as a dependency
/// of every step that reads the header, below and in `addGraph`, so the header
/// is written before the compile that includes it. A `LazyPath` created while
/// `build()` runs is a name resolved in a dependent make step, not a file read
/// now.
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

    // Every fact the generator is allowed to use. `-Dtarget` supplies the triple;
    // `-Dcpu` supplies a CPU model the triple does not carry
    // (`lib/std/Target/Query.zig` serialises the model separately), and the
    // arch/os/abi tags come out of the resolved target rather than out of the
    // query string, so a `-Dtarget=` with an ABI suffix is read correctly.
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

    // `_ = optimize` is not needed: the generator's decisions are the target's
    // and nothing here changes with the optimize mode. It is in the signature
    // anyway so that a future per-mode decision has a home rather than a new
    // parameter bolted on later.
    _ = optimize;

    return .{
        // `LazyPath.dirname` is not optional: it panics rather than returning
        // null when a path has no dirname, and a generated output file always has
        // one, so the panic is unreachable here and is not a check this function
        // needs to spell.
        .directory = header.dirname(),
        .header = header,
    };
}

// ---------------------------------------------------------------------------
// The three libraries
// ---------------------------------------------------------------------------

fn add_library(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    platform: Platform,
    generated: GeneratedConfig,
    name: []const u8,
    sources: []const []const u8,
    abi: ?std.SemanticVersion,
    /// Archives this one depends on, in link order. Recorded as compile
    /// dependencies through `Module.linkLibrary`, so a change to
    /// `libmbedcrypto` re-links the two above it rather than serving a stale
    /// `libmbedtls.a` from the cache.
    below: []const ?*std.Build.Step.Compile,
    public: bool,
    /// The linkage this archive is delivered in, already checked against the
    /// target by `deliveredLinkage`.
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
        // A module definition file is how a COFF export list is stated, and
        // upstream's `mbedtls_*` / `psa_*` naming is the whole API. It is a
        // pattern rather than a list of 1500 names: write the rules out here and
        // a header that adds a symbol needs no change.
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
            // `link_libc` because the closure reaches <string.h>, <stdlib.h>,
            // <time.h>, <stdio.h> and, on every unix-like target, <unistd.h>,
            // <sys/socket.h>, <netdb.h> and <poll.h>.
            .link_libc = true,
            .pic = if (linkage == .dynamic) true else null,
        }),
    });
    const m = lib.root_module;

    // The generated configuration, for *this* target, first on the include path
    // and named through upstream's own `MBEDTLS_CONFIG_FILE` hook. Both steps are
    // needed and neither is enough alone: the macro names the header, and the
    // directory is what lets a bare name be resolved. See the module doc for why
    // the generated file is not called `mbedtls_config.h`.
    m.addIncludePath(generated.directory);
    m.addCMacro("MBEDTLS_CONFIG_FILE", b.fmt("\"{s}\"", .{config_gen.output_basename}));

    // For the sources' own quoted includes: every file in `library/` includes its
    // neighbours by bare name, and `net_sockets.c:18` opens `"common.h"`.
    m.addIncludePath(b.path(library_dir));
    // For the public headers, by the names the sources spell them with.
    m.addIncludePath(b.path(include_dir));
    for (thirdparty_includes) |dir| {
        m.addIncludePath(b.path(dir));
    }

    // Per target, not one global list: FreeBSD needs one extra define that no
    // other target wants. See `cFlags` and `freebsd_visibility_flag`.
    const flags = cFlags(platform);
    for (sources) |source| {
        m.addCSourceFile(.{ .file = b.path(source), .flags = flags });
    }

    // The archives below, in upstream's order. `linkLibrary` records each as a
    // compile dependency of this one, which is also what makes a static archive
    // resolve against the other two.
    for (below) |dependency| {
        if (dependency) |other| m.linkLibrary(other);
    }

    if (platform.separate_m) m.linkSystemLibrary("m", .{});
    if (linkage == .dynamic and platform.separate_dl) m.linkSystemLibrary("dl", .{});

    // Upstream's own answer, at `src/library/CMakeLists.txt:225-227`:
    // `if(WIN32) set(libs ${libs} ws2_32 bcrypt)`. Both are import libraries,
    // not archives this build produces: `net_sockets.c` calls the whole
    // Winsock2 set (`socket`, `bind`, `listen`, `accept`, `connect`, `send`,
    // `recv`, `select`, `setsockopt`, `getaddrinfo`, `WSAStartup`,
    // `WSAGetLastError`) and `entropy_poll.c:98-146` calls
    // `BCryptGenRandom`. Without them `lld-link` reports every one of them as
    // `undefined symbol`, which is what the two Windows cells did.
    //
    // Recorded on the archive's module, as `separate_m` above is, so that every
    // consumer of the archive inherits them rather than each executable having
    // to remember.
    if (platform.windows) {
        m.linkSystemLibrary("ws2_32", .{});
        m.linkSystemLibrary("bcrypt", .{});
    }

    if (linkage == .dynamic and target.result.ofmt == .elf) setVersionScript(b, lib, name);

    // The generated header is an *input* to this compile, so the step that
    // writes it has to be a dependency of it. `addIncludePath` contributes only
    // a path to the command line; without this edge the archive could be served
    // from the build cache from a run in which a different target had written
    // that directory.
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

// ---------------------------------------------------------------------------
// The graph for one target
// ---------------------------------------------------------------------------

const TargetGraph = struct {
    crypto: *std.Build.Step.Compile,
    x509: *std.Build.Step.Compile,
    tls: *std.Build.Step.Compile,
    /// The facade module for `name`, carrying the translation and the archives.
    module: *std.Build.Module,
    /// The configuration header this target's compile and translation both read.
    /// `add_install` needs it, and the install step lives outside `addGraph`, so
    /// it travels back out rather than being regenerated: a second generator run
    /// would write a second cache directory, and the installed header would not
    /// be the one this graph compiled against.
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

    // The translation. One step, rooted at `zig/translate.h`, which reaches the
    // eighty public headers; the same include path and the same
    // `MBEDTLS_CONFIG_FILE` macro as the libraries above, so the translation
    // describes the headers this build compiled against rather than another
    // configuration's.
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

    // The facade module. One module, registered by name under `tls_name` when
    // this graph is the public one: `zig/root.zig` is a single source over a
    // single translation of all eighty public headers, so a second published
    // name would be the same module twice, not a layer. The private graphs a
    // `check` cell builds use `createModule`, because a second `addModule`
    // under a name the map already holds trips `HashMap.put`'s duplicate-key
    // assertion, and with assertions off it would overwrite the entry and leave
    // only the last cell's module reachable.
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

    // The runtime route. Under `-Druntime=true` the facade's `c` import is the
    // generated dispatch and *nothing* links the archives, because a linker that
    // could resolve those symbols would resolve them statically and the runtime
    // route would quietly become a linked one. `rt` is imported only in the
    // linked configuration, for the two public types; a second core module would
    // be a second nominal `LoadSource`, and `load` would hand the facade's type to
    // something expecting the dispatch's.
    if (runtime_loaded) {
        module.addImport("c", graph_runtime.createModule(b, translate, target, optimize));
    } else {
        module.addImport("c", translated);
        module.addImport("rt", graph_runtime.createCoreModule(b, target, optimize));
        module.linkLibrary(crypto);
        module.linkLibrary(x509);
        module.linkLibrary(tls);
    }
    // So that a dependent compiling a C file of its own finds the same headers.
    module.addIncludePath(b.path(include_dir));

    // The three archives are built and installed whatever the dispatch is:
    // delivery and dispatch are different questions, and `-Druntime=true` does
    // not mean "do not build the library".
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

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

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
        // `mbedtls/foo.h` and `psa/foo.h` install into their own subdirectory,
        // because the headers include each other by those exact names and a flat
        // layout would make `#include "mbedtls/build_info.h"` unresolvable for a
        // consumer.
        const sub = if (std.mem.indexOf(u8, header, "/psa/") != null)
            "psa"
        else
            "mbedtls";
        const base = std.fs.path.basename(header);
        // `addInstallFileWithDir` *creates* a step and nothing more. Dropping the
        // return value builds nothing and installs nothing, and the omission is
        // silent: the step exists, it is simply never in the graph.
        const installed = b.addInstallFileWithDir(
            b.path(header),
            .header,
            b.fmt("{s}/{s}", .{ sub, base }),
        );
        b.getInstallStep().dependOn(&installed.step);
    }

    // The generated configuration, installed under the name the headers reach it
    // by, so that a dependent's own `mbedtls/build_info.h` finds the
    // configuration this library was actually built with.
    //
    // This is the *only* generated file that is installed, and the reason is
    // narrow: upstream's own install rule puts `mbedtls_config.h` in exactly this
    // place, so a consumer that includes any Mbed TLS header needs *some* file
    // there, and the one that describes a different configuration than the linked
    // library is the failure mode this workspace rules out by name. The
    // build-internal name `mbedtls_target_config.h` is not installed under that
    // name, so nothing in the tree can shadow it.
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
    // `b.fmt` is inside `add`, so the file is both formatted and written at build
    // time. `addInstallFileWithDir` *creates* a step and nothing more: dropping
    // the return value builds nothing and installs nothing, silently.
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

// ---------------------------------------------------------------------------
// The check step
// ---------------------------------------------------------------------------

fn add_target_check(
    b: *std.Build,
    step: *std.Build.Step,
    query: std.Target.Query,
    optimize: std.builtin.OptimizeMode,
    linkage: std.builtin.LinkMode,
    runtime_loaded: bool,
) void {
    const cross_target = b.resolveTargetQuery(query);
    // The refusal comes *before* any delivery decision, so a target this build
    // will not configure never reaches the point where a linkage is chosen.
    if (refusalFor(cross_target.result.os.tag) != null) {
        refuseTarget(b, cross_target.result.os.tag);
    }

    const triple = cross_target.result.zigTriple(b.allocator) catch @panic("unspellable target");
    const cross = addGraph(b, cross_target, optimize, linkage, runtime_loaded, false);

    // Zig analyses a function body only when something calls it, so the check has
    // to *call* the facade rather than merely name it. The test root and the
    // example root both do, which is what makes this a compile exercise instead
    // of a translation.
    const test_mod = b.createModule(.{
        .root_source_file = b.path(test_source),
        .target = cross_target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_mod.addImport(tls_name, cross.module);
    // The fixtures are embedded with `@embedFile` from the test root, so the
    // test module needs the package root on its path for `fixtures/`.
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

    // Nothing in `check` runs. A cell that fails is a fact to diagnose, not a
    // reason to drop the cell, sample the tests, or remap Debug to an optimized
    // mode to make it pass.
}

// ---------------------------------------------------------------------------
// The consumer
// ---------------------------------------------------------------------------

fn runConsumer(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    linkage: std.builtin.LinkMode,
    runtime_loaded: bool,
) *std.Build.Step.Run {
    // A nested build rather than a manifest dependency: a manifest dependency from
    // this package to `consumer/`, which depends back on this package, closes a
    // cycle.
    const run = b.addSystemCommand(&.{ b.graph.zig_exe, "build" });
    run.setName("consumer package");
    run.setCwd(b.path("consumer"));
    run.addArg(if (hostCanExecute(b, target)) "run" else "install");

    const triple = target.result.zigTriple(b.allocator) catch @panic("unspellable target");
    run.addArg(b.fmt("-Dtarget={s}", .{triple}));
    // The CPU model is serialised separately because the triple does not carry
    // it (`lib/std/Target/Query.zig`).
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
    // The question is whether the selected target is the host, not whether an
    // executor for it exists. Whether a *foreign* target runs is the cross-test
    // harness's decision; this build answers "run" for the host and "install"
    // for everything else, which is the conservative half of that answer.
    _ = b;
    return target.query.isNative();
}

// ---------------------------------------------------------------------------
// build
// ---------------------------------------------------------------------------

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

    // Configure-time validation, before any graph is built.
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

    // Configure-time reporting, so `zig build` says what it is about to do
    // without anyone having to read the graph.
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
    // Built, not installed: the example exists to be run by `smoke` and compiled
    // by `check`, and installing a demo binary into a consumer's prefix would be
    // a surprise.
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
        // `[0..]`, not `.*`: `.*` is for dereferencing a single optional or
        // error-union payload, so the pointer-to-array has to become a slice
        // before it can be iterated.
        for (check_targets[0..]) |query| {
            add_target_check(b, check_step, query, optimize, delivered, runtime_loaded);
        }
    }
}
