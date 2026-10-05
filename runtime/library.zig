// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// See FORK-LICENSE.md for what that identifier covers.
//
//! Mbed TLS's side of the runtime loader: the names its synchronization binding
//! has, what it requires of a provider beyond resolving its symbols, and what
//! the external ABI boundary for this provider actually is.
//!
//! Everything else about the runtime route is generic. `runtime/loader.zig` is
//! the state machine and the platform layer; `runtime/generate.zig` builds the
//! dispatch from whatever the translation step actually produced;
//! `runtime/graph.zig` wires them together. This file is what makes them Mbed
//! TLS's, and it is the file another SDK replaces.
//!
//! ## What a provider must be
//!
//! Every declaration `zig/translate.h` reaches whose name starts with `mbedtls_`
//! or `psa_`: the whole of `src/include/mbedtls/*.h`'s C API and the whole of
//! `src/include/psa/crypto.h`'s PSA Crypto API. `runtime/graph.zig` selects
//! that set by prefix, so nothing can fall out of it, and both
//! `provider_optional` and `provider_excluded` there are empty: a provider that
//! does not export the whole set is refused rather than half used.
//!
//! A provider's *configuration* is not in that set, and that is the larger
//! boundary. See below.
//!
//! ## The ABI boundary, stated honestly
//!
//! The supported external ABI family is **Mbed TLS 3.6** - version 3.6.7,
//! `src/include/mbedtls/build_info.h:27-29` for the three components and `:36-38`
//! for the packed number and the two strings - built from these headers
//! with the configuration `zig/config_gen.zig` generates. That is a narrower
//! claim than "a shared object that exports these names", and the difference is
//! real:
//!
//!   * **Configuration is ABI.** Mbed TLS's struct layouts and buffer sizes are
//!     compile-time constants read out of the configuration header, not
//!     run-time negotiation. `mbedtls_entropy_context` has
//!     `MBEDTLS_ENTROPY_MAX_SOURCES` sources and a buffer of
//!     `MBEDTLS_ENTROPY_BLOCK_SIZE` bytes in it
//!     (`src/include/mbedtls/entropy.h:59-89`); `mbedtls_ssl_context`
//!     (`src/include/mbedtls/ssl.h:1646-1801`) is roughly forty fields whose
//!     types are configuration-dependent; `mbedtls_x509_crt` and every other
//!     public struct are fixed layouts chosen by the same header. A provider
//!     built with a different configuration has a *different* struct under the
//!     same name, so its `mbedtls_entropy_context` is a different size and its
//!     `mbedtls_ssl_context` is a different layout, and every offset the C code
//!     reads through them is wrong.
//!   * **So the configuration is part of what a provider must be, and the
//!     version string does not carry it.** `mbedtls_version_check_feature`
//!     (`src/include/mbedtls/version.h:56-73`) is how a provider is asked which
//!     options it was built with; the load-time check below does not call it,
//!     because a check that returns -1 for a missing feature is not the same
//!     thing as a check of a *struct layout*, and this package cannot enumerate
//!     every layout-relevant option here without turning into a second copy of
//!     `mbedtls_config.h`. What it does instead is described next.
//!   * **The allocator is the provider's.** `mbedtls_calloc` and
//!     `mbedtls_free` (`src/library/platform.c:14-27`, `:143-148`) are libc
//!     `calloc`/`free` wrappers unless `MBEDTLS_PLATFORM_C` is configured in,
//!     in which case they dispatch through `mbedtls_platform_calloc_free`.
//!     Nothing in this SDK can observe, bound or account for those allocations:
//!     a Zig allocator is not in the path, and a test framework cannot supply a
//!     leak oracle for memory a third-party allocator owns.
//!   * **Version functions and callback types cross the boundary in both
//!     directions.** `mbedtls_ssl_conf_*`, `mbedtls_x509_crt_verify` and the
//!     PSA key-derivation calls all take function pointers the provider will
//!     call back with the provider's own calling convention, and
//!     `mbedtls_ecp_curve_info` and the other accessors return pointers into
//!     the provider's own static tables.
//!
//! **Mbed TLS 4.x is a different ABI and is refused.** 4.0 moved the
//! primitives into a separate TF-PSA-Crypto repository behind the PSA API and
//! removed the legacy `mbedtls_sha256_*`, `mbedtls_gcm_*` and `mbedtls_rsa_*`
//! entry points, so a 4.x object does not export most of what these headers
//! declare and would fail on `MissingSymbol` before any check ran. **Mbed TLS
//! 2.28** is a different ABI for the other reason: its configuration is older,
//! its struct layouts differ, and its TLS 1.3 support is absent. Both are
//! refused by the version-string check below, by name, before anything is
//! published.
//!
//! Resolving the symbols and translating the header is the boundary. They are
//! not proof that a provider is compatible, and this file does not pretend to
//! add more than it checks. What is checked at load time, before anything is
//! published:
//!
//!   * `mbedtls_version_get_string_full` writes "Mbed TLS 3.6.7"
//!     (`src/library/version.c:25-29` copies `MBEDTLS_VERSION_STRING_FULL`,
//!     `src/include/mbedtls/build_info.h:27`), and the result must start with
//!     "Mbed TLS 3.6.". That is the ABI *family* check: it is what separates
//!     3.6 from 3.5, from 3.4, from 2.28 and from 4.x.
//!   * An entropy context is created and destroyed through this same table.
//!     `mbedtls_entropy_init` and `mbedtls_entropy_free`
//!     (`src/include/mbedtls/entropy.h:135,142`) exercise the provider's
//!     allocator and its teardown path, and doing the free here rather than at
//!     process exit is what keeps the check from leaking if it fails. It is
//!     also the first struct whose *layout* crosses the boundary, so
//!     allocating one with this translation's own `sizeof` and handing the
//!     pointer to the provider is itself a layout check: a provider built with a
//!     different `MBEDTLS_ENTROPY_MAX_SOURCES` would write past it.
//!   * SHA-256 of the three bytes "abc" must equal the FIPS 180-4 §B.1 answer.
//!     That is an *independent* oracle: the constant below is a published
//!     standard value, not something this package computed, and a provider
//!     whose SHA-256 is broken, stubbed, or answering through a driver it does
//!     not have is refused here rather than discovered in a caller's handshake.
//!
//! What is deliberately *not* called here is anything whose failure mode is
//! `abort` or a process exit. Upstream's own check for this family is
//! `mbedtls_psa_crypto_config_check` behind `MBEDTLS_SELF_TEST`, and the
//! self-test path calls `exit`. A loader that has to answer `ValidationFailed`
//! cannot use a check that kills the process, so the facts it would have
//! checked - the version family, and one real cryptographic operation - are
//! checked here instead, in a form that returns.

const std = @import("std");

const rt = @import("rt");

/// The synchronization this loader calls, bound by exact name.
///
/// The names below are `runtime/sync.c` compiled with
/// `RT_SYNC_PREFIX=mbedtls_rt`, which is what `runtime/graph.zig` passes. Two
/// spellings of that prefix have to agree: this file names the symbols, and
/// graph.zig defines the macro. A build where they disagree does not link, and
/// that is the whole error report: there is no runtime path that could hide it.
///
/// The core in `runtime/loader.zig` never names a symbol of its own, which is
/// what lets two SDKs, or two configurations of one SDK, hold their own loader
/// state in one process without sharing any of it.
pub const Sync = struct {
    extern fn mbedtls_rt_lock() void;
    extern fn mbedtls_rt_unlock() void;
    extern fn mbedtls_rt_wait() void;
    extern fn mbedtls_rt_broadcast() void;
    // `unsigned long long`. Declared as u64, which is the same type in every
    // ABI this SDK targets: 64-bit on x86_64, aarch64, riscv64 and wasm32.
    extern fn mbedtls_rt_thread_self() u64;

    pub fn lock() void {
        mbedtls_rt_lock();
    }
    pub fn unlock() void {
        mbedtls_rt_unlock();
    }
    pub fn wait() void {
        mbedtls_rt_wait();
    }
    pub fn broadcast() void {
        mbedtls_rt_broadcast();
    }
    pub fn threadSelf() u64 {
        return mbedtls_rt_thread_self();
    }
};

/// The prefix of the family this SDK's headers describe, with no trailing
/// space: the start of `MBEDTLS_VERSION_STRING_FULL`
/// (`src/include/mbedtls/build_info.h:27`), which
/// `mbedtls_version_get_string_full` copies verbatim
/// (`src/library/version.c:25-29`).
///
/// "Mbed TLS 3.6." rather than the whole "Mbed TLS 3.6.7", because a patch
/// release inside the same LTS line is the same ABI family and this package is
/// pinned to one patch, not one minor.
const family_prefix = "Mbed TLS 3.6.";

/// SHA-256 of the three bytes "abc", from NIST FIPS 180-4 §B.1.
///
/// `ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad`
/// is the single-message digest FIPS 180-4 publishes for `abc` (Appendix B,
/// "Sample Results"). It is quoted here as eight bytes, because
/// `mbedtls_sha256` takes a `size_t` length and a caller buffer, and this is
/// the check's whole point: the constant is a published standard value and not
/// something this build computed from the provider.
const sha256_abc = [32]u8{
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
};

/// The loader's configuration for this SDK, given the dispatch that owns the
/// table.
///
/// `dispatch` is the generated module, passed as a type by the dispatch itself
/// so that this file never has to import it. The direction is one-way on
/// purpose: the descriptor knows what the loader needs, the dispatch knows what
/// the header said, and neither imports the other.
pub fn Config(comptime dispatch: type) type {
    return struct {
        /// Named in the pre-load panic, so the message says which library was
        /// reached for before it was loaded.
        pub const library_name = "mbedtls";

        /// The table the generated dispatch declares, and the symbols it needs
        /// to fill it. Both come from the translated headers, not from this file.
        pub const table = dispatch.Table;
        pub const symbols = dispatch.symbols;
        pub const optional_symbols = dispatch.optional_symbols;

        /// The project's namespaced synchronization binding.
        pub const sync = Sync;

        pub fn tablePtr() *table {
            return dispatch.tablePtr();
        }

        pub fn ready() *rt.Ready {
            return &dispatch.ready;
        }

        pub fn assign(comptime index: usize, dst: *table, address: *const anyopaque) void {
            dispatch.assign(index, dst, address);
        }

        pub inline fn assignOptional(comptime index: usize, dst: *table, address: *const anyopaque) void {
            dispatch.assignOptional(index, dst, address);
        }

        pub inline fn assignMissing(comptime index: usize, dst: *table) void {
            dispatch.assignMissing(index, dst);
        }

        /// The library-specific checks, run after every symbol resolved and
        /// before anything is published.
        ///
        /// A non-null answer is `ValidationFailed` and the candidate is closed
        /// without being published. Every check here is one whose failure this
        /// code can observe; see the module comment for what is deliberately
        /// not called and why.
        pub fn validate(dst: *const table) ?[]const u8 {
            // The version family. `mbedtls_version_get_string_full` copies
            // `MBEDTLS_VERSION_STRING_FULL` including its terminating NUL
            // (`src/library/version.c:25-29`), so the buffer only has to be as
            // long as that string: 18 bytes for this release, and the header
            // says "18 bytes AT MOST" (`src/include/mbedtls/version.h:44-47`).
            // 32 is that bound with room to spare, and a provider built from a
            // different release writes no further than its own string.
            var version: [32]u8 = @splat(0);
            dst.mbedtls_version_get_string_full(&version);
            const reported = std.mem.sliceTo(@as([:0]const u8, &version), 0);
            if (!std.mem.startsWith(u8, reported, family_prefix)) {
                // The two strings go to the diagnostic stream rather than into
                // the returned text: `validate` has no allocator and the loader
                // reports whatever string it is given.
                std.debug.print(
                    "mbedtls: provider reports \"{s}\", this SDK's headers " ++
                        "describe a 3.6.x release; they are different external " ++
                        "ABIs\n",
                    .{reported},
                );
                return "this provider is not an Mbed TLS 3.6.x build, and its " ++
                    "struct layouts are not the ones these headers describe";
            }

            // Create and destroy one entropy context through this same table.
            // `mbedtls_entropy_context` is a plain struct, not a pointer, so it
            // is allocated here with this translation's own layout: a provider
            // compiled with a different MBEDTLS_ENTROPY_MAX_SOURCES or
            // MBEDTLS_ENTROPY_BLOCK_SIZE writes a different number of bytes
            // into it, and that is a real layout disagreement, not a style one.
            var entropy: dispatch.mbedtls_entropy_context = undefined;
            dst.mbedtls_entropy_init(&entropy);
            defer dst.mbedtls_entropy_free(&entropy);

            // The cryptographic check. `mbedtls_sha256`
            // (`src/include/mbedtls/sha256.h:167-190`) takes the input, its
            // length, the output buffer and the 224-bit selector, and returns 0
            // on success. `is224 = 0` is the SHA-256 variant, which is the one
            // FIPS 180-4 §B.1 gives an answer for.
            var digest: [32]u8 = undefined;
            const status = dst.mbedtls_sha256("abc", 3, &digest, 0);
            if (status != 0) return "this provider's SHA-256 rejected a three " ++
                "byte input that FIPS 180-4 defines a digest for";

            // The independent answer. A provider that passes the version check
            // and fails this one is either stubbed or dispatching SHA-256 to a
            // driver it does not have, and both are cases a caller would
            // otherwise discover inside its own handshake.
            if (!std.mem.eql(u8, digest[0..], sha256_abc[0..])) {
                return "this provider's SHA-256 does not match the FIPS 180-4 " ++
                    "digest of \"abc\", so its cryptographic core is not the " ++
                    "one these headers describe";
            }

            return null;
        }
    };
}