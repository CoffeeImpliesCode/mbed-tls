// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// See FORK-LICENSE.md for what that identifier covers.
//
//! Mbed TLS 3.6.x providers only; 2.28 and 4.x are refused.
//! Provider layouts, callbacks, and allocator must match translated headers and configuration.
//! Validation checks version, entropy init/free, and SHA-256 of "abc".

const std = @import("std");

const rt = @import("rt");

/// Namespaced synchronization bindings for this loader instance.
/// The prefix must match `runtime/graph.zig` and `runtime/sync.c`.
pub const Sync = struct {
    extern fn mbedtls_rt_lock() void;
    extern fn mbedtls_rt_unlock() void;
    extern fn mbedtls_rt_wait() void;
    extern fn mbedtls_rt_broadcast() void;
    // C's `unsigned long long` is represented as `u64` here.
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

/// Version prefix accepted by the provider check; 3.6 patch releases are allowed.
const family_prefix = "Mbed TLS 3.6.";

/// FIPS 180-4 SHA-256 digest of "abc", used to validate the provider.
const sha256_abc = [32]u8{
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
};

/// Binds the generic loader to this generated dispatch.
pub fn Config(comptime dispatch: type) type {
    return struct {
        /// Name used in pre-load diagnostics.
        pub const library_name = "mbedtls";

        /// Dispatch table and symbol lists from translated headers.
        pub const table = dispatch.Table;
        pub const symbols = dispatch.symbols;
        pub const optional_symbols = dispatch.optional_symbols;

        /// Namespaced synchronization bindings.
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

        /// Checks the version family, entropy lifecycle, and SHA-256 result.
        /// Returns a diagnostic string when validation fails.
        pub fn validate(dst: *const table) ?[]const u8 {
            // The 32-byte buffer exceeds the header's 18-byte maximum for this release.
            var version: [32]u8 = @splat(0);
            dst.mbedtls_version_get_string_full(&version);
            const reported = std.mem.sliceTo(version[0..], 0);
            if (!std.mem.startsWith(u8, reported, family_prefix)) {
                // Include the observed version; `validate` has no allocator.
                std.debug.print(
                    "mbedtls: provider reports \"{s}\", this SDK's headers " ++
                        "describe a 3.6.x release; they are different external " ++
                        "ABIs\n",
                    .{reported},
                );
                return "this provider is not an Mbed TLS 3.6.x build, and its " ++
                    "struct layouts are not the ones these headers describe";
            }

            // The context uses this translation's layout; a mismatch can overrun it.
            // Exercise provider init and free before publishing the table.
            var entropy: dispatch.mbedtls_entropy_context = undefined;
            dst.mbedtls_entropy_init(&entropy);
            defer dst.mbedtls_entropy_free(&entropy);

            // `is224 = 0` selects SHA-256, which has the published FIPS vector below.
            var digest: [32]u8 = undefined;
            const status = dst.mbedtls_sha256("abc", 3, &digest, 0);
            if (status != 0) return "this provider's SHA-256 rejected a three " ++
                "byte input that FIPS 180-4 defines a digest for";

            // Compare with the published FIPS vector, independent of the provider.
            if (!std.mem.eql(u8, digest[0..], sha256_abc[0..])) {
                return "this provider's SHA-256 does not match the FIPS 180-4 " ++
                    "digest of \"abc\", so its cryptographic core is not the " ++
                    "one these headers describe";
            }

            return null;
        }
    };
}
