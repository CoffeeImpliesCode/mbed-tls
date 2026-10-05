// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// See FORK-LICENSE.md for what that identifier covers.
//

//! The example program, and what it is for.
//!
//! `zig build smoke` runs this; `zig build check` compiles it for every cross
//! target without running it. It exists to answer one question on a machine
//! where nobody has read the source: *does this build actually do TLS?*
//!
//! ## What makes it a check and not a demonstration
//!
//! Every expected value below is a **literal** - a published standard vector or a
//! field read out of upstream's own published test certificate. Nothing is
//! compared against a value this program computed for the purpose. A program
//! that asked Mbed TLS whether it agreed with itself would print whatever the
//! library said and pass on a build with a broken cipher; this one cannot,
//! because the answers come from NIST, from the GCM specification, from RFC 8439
//! and from OpenSSL's reading of a certificate file.
//!
//! ## No `@cImport`
//!
//! There is no `@cImport`, `@cInclude` or `@cDefine` in this file. C is reached
//! only through the facade, which is what makes this program a check of the
//! *published module* rather than of a private translation a dependent could
//! not use.
//!
//! ## The version line
//!
//! The first two lines name the configuration (`linked` or `loaded`) and the
//! version the *library* reports. The version is printed and never compared: a
//! version string is provenance, not behaviour. The gate for the pin is
//! `tools/check-provenance.sh`, which reads `UPSTREAM.md` and `UPSTREAM.sha256`
//! and never looks at this program.

const std = @import("std");
const builtin = @import("builtin");
const mbedtls = @import("mbedtls");

const test_ca_pem = @embedFile("fixtures/test-ca.crt");
const server_cert_pem = @embedFile("fixtures/server2.crt");
const server_key_pem = @embedFile("fixtures/server2.key");

/// The verification profile this vendored chain needs.
///
/// Both fixture certificates are `sha1WithRSAEncryption`, and Mbed TLS 3.6.7's
/// default profile allows SHA-256 and above
/// (`src/library/x509_crt.c:89-97`), so the library refuses this chain by
/// default. `certificateChecks` prints that refusal and its exact reason
/// before it uses this profile, so the line below never hides the default.
///
/// A function and not a `const`: upstream's profiles are link-time `const`
/// globals (`src/include/mbedtls/x509_crt.h:324`), which cannot be read while
/// a container-level initialiser is evaluated, and the caller has to keep the
/// value alive anyway because `mbedtls_ssl_conf_cert_profile` stores the
/// pointer (`src/library/ssl_tls.c:1832-1835`).
fn legacySha1() mbedtls.CertificateProfile {
    return mbedtls.CertificateProfile.default().allowingMd(.sha1);
}

/// `MBEDTLS_X509_BADCERT_BAD_MD` (`src/include/mbedtls/x509.h:105`): the
/// certificate is signed with a hash the profile does not accept.
const badcert_bad_md: u32 = 0x4000;

/// What a mismatch costs: a named error from `main`, which is Zig's own non-zero
/// exit. There is no `exit()` anywhere in this file.
const CheckFailed = error{CheckFailed};

/// What a check can fail with: the mismatch it exists to report, and the
/// writer's own failure while it is reporting it. A helper that prints the
/// answer it then compares cannot claim to fail only on the mismatch.
const CheckError = CheckFailed || std.Io.Writer.Error;

/// FIPS 180-4 Appendix B, `SHA-256("abc")`.
const sha256_abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

/// RFC 4231 §4.2 test case 1.
const hmac_tag = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

/// NIST SP 800-38A §F.2.1, CBC-AES128.Encrypt, first block. Also measured
/// independently with OpenSSL 3.5.0.
const cbc_ciphertext = "7649abac8119b246cee98e9b12e9197d";

/// The GCM specification's Test Case 2 tag, for that case's published 64-byte
/// plaintext. Also measured independently with Python's `cryptography`.
const gcm_tag = "59e5dfc37cb87a2afc73c4d0d58d23a8";

/// RFC 8439 §2.8.2 tag, for that section's published plaintext. Also measured
/// independently with Python's `cryptography`.
const chacha_tag = "1ae10b594f09e26a7e902ecbd0600691";

/// RFC 8439 §2.8.2's plaintext: the AEAD check below is that section's example,
/// so it encrypts that section's message and nothing of this program's own.
const rfc8439_plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

/// The test request and answer, so a wrong answer cannot be both ends agreeing
/// about a byte that never travelled.
const request = "ping";
const response = "pong-from-server";

/// A fixed high port. `Socket.bindAll` takes a port and nothing else, so nothing
/// in the library chooses or reports one; a collision is `error.System` and a
/// non-zero exit, with no retry, so "which port did this run use" stays
/// answerable from the source.
const port = "39501";

/// Whether this target has the BSD-socket transport `Socket` needs.
///
/// The same condition `zig/config_gen.zig` decides `MBEDTLS_NET_C` from, read
/// out of the resolved target. It is not a capability probe: nothing is called
/// to find out.
const has_socket_transport = switch (builtin.os.tag) {
    .windows => true,
    .linux, .macos, .ios, .tvos, .watchos, .visionos, .freebsd, .netbsd, .openbsd,
    .dragonfly, .illumos, .hurd, .fuchsia, .haiku,
    => true,
    else => false,
};

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buffer);
    const w = &stdout.interface;

    try w.print("mbed-tls smoke\n", .{});
    // The configuration first, then the version the library reports. Both are
    // printed rather than compared: they are provenance.
    var version: [32]u8 = undefined;
    const reported = mbedtls.versionString(&version) catch "3.6.7 (buffer too small)";
    try w.print("{s: <44}{s}\n", .{ "configuration", if (mbedtls.runtime_loaded) "loaded" else "linked" });
    try w.print("{s: <44}{s}\n", .{ "the library reports version", reported });

    if (comptime mbedtls.runtime_loaded) {
        try mbedtls.load(.{ .path = try providerRequest(init) });
        // `load` returned, so there is a source; naming the unreachable case
        // beats printing a provider this process does not have.
        const provider = mbedtls.loadedSource() orelse return error.ProviderNotLoaded;
        try w.print("{s: <44}{s}: {s}\n", .{
            "provider",
            @tagName(provider),
            switch (provider) {
                .path => provider.path,
                .system => provider.system,
            },
        });
    }

    try cryptoChecks(w);
    try certificateChecks(w);
    try handshake(w);

    try w.print("every answer matched the published value\n", .{});
    try w.flush();
}

/// The cryptographic answers, all from published standards.
fn cryptoChecks(w: *std.Io.Writer) !void {
    var digest: [32]u8 = undefined;
    try mbedtls.hash(.sha256, "abc", &digest);
    try checkBytes(w, "SHA-256 of abc (FIPS 180-4 B)", &digest, sha256_abc);

    var tag: [32]u8 = undefined;
    try mbedtls.hmac(.sha256, &([_]u8{0x0b} ** 20), "Hi There", &tag);
    try checkBytes(w, "HMAC-SHA-256 (RFC 4231 case 1)", &tag, hmac_tag);

    var cipher = try mbedtls.Aes128Cbc.initEncrypt(&[_]u8{
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    });
    defer cipher.deinit();
    var iv = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    var block_out: [16]u8 = undefined;
    try cipher.crypt(true, &iv, &[_]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    }, &block_out);
    try checkBytes(w, "AES-128-CBC (SP 800-38A F.2.1)", &block_out, cbc_ciphertext);

    var gcm = try mbedtls.Aes128Gcm.init(&[_]u8{0} ** 16);
    defer gcm.deinit();
    var gcm_out: [64]u8 = undefined;
    var gcm_tag_out: [16]u8 = undefined;
    try gcm.seal(
        &[_]u8{ 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 },
        "",
        &[_]u8{
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5,
            0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
            0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95,
            0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
            0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
            0x1a, 0xaf, 0xd2, 0x55,
        },
        &gcm_out,
        &gcm_tag_out,
    );
    try checkBytes(w, "AES-128-GCM tag (GCM spec case 2)", &gcm_tag_out, gcm_tag);

    var aead = try mbedtls.ChaCha20Poly1305.init(&[_]u8{
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    });
    defer aead.deinit();
    var aead_out: [114]u8 = undefined;
    var aead_tag: [16]u8 = undefined;
    try aead.seal(
        &[_]u8{ 0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 },
        &[_]u8{ 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 },
        rfc8439_plaintext,
        &aead_out,
        &aead_tag,
    );
    try checkBytes(w, "ChaCha20-Poly1305 tag (RFC 8439 2.8.2)", &aead_tag, chacha_tag);
}

/// The X.509 answers, read out of upstream's published test certificates.
fn certificateChecks(w: *std.Io.Writer) !void {
    var ca = mbedtls.Certificate.init();
    defer ca.deinit();
    try ca.parse(test_ca_pem);

    var text: [128]u8 = undefined;
    try checkString(w, "test CA subject", try ca.subject(&text), "C=NL, O=PolarSSL, CN=PolarSSL Test CA");
    try checkString(w, "test CA serial", try ca.serial(&text), "03");
    try check(w, "test CA says it is a CA", ca.isCa(), true);
    try checkCount(w, "test CA DER length", ca.der().len, 840);

    var server = mbedtls.Certificate.init();
    defer server.deinit();
    try server.parse(server_cert_pem);
    try checkString(w, "server subject", try server.subject(&text), "C=NL, O=PolarSSL, CN=localhost");
    try checkString(w, "server issuer", try server.issuer(&text), "C=NL, O=PolarSSL, CN=PolarSSL Test CA");
    try check(w, "server says it is not a CA", server.isCa(), false);
    try checkCount(w, "server RSA modulus bits", server.rsaBitLength() orelse 0, 2048);

    // What this build does with the vendored chain under the library's own
    // default policy: it refuses it, and the only reason it reports is the
    // unacceptable hash. Both fixture certificates are `sha1WithRSAEncryption`
    // and `mbedtls_x509_crt_profile_default` is "hashes from SHA-256 and above"
    // (`src/library/x509_crt.c:89-97`).
    var default_flags: u32 = 0;
    if (server.verifyInto(&ca, &default_flags)) |_| {
        std.debug.print("smoke: the SHA-1 chain verified under the default profile\n", .{});
        return error.CheckFailed;
    } else |_| {}
    try checkCount(w, "default-profile flags for the SHA-1 chain", default_flags, badcert_bad_md);

    // The same chain, same CA, and the profile a caller must name to accept a
    // peer that still signs with SHA-1. What OpenSSL independently reported as
    // `server2.crt: OK`.
    var profile = legacySha1();
    var flags: u32 = 0;
    server.verifyIntoWithProfile(&ca, &profile, &flags) catch |err| {
        std.debug.print("smoke: the fixture chain did not verify under legacy_sha1: {s} flags=0x{x}\n", .{ @errorName(err), flags });
        return error.CheckFailed;
    };
    try checkCount(w, "verify flags for the chain under legacy_sha1", flags, 0);

    // And the negative: a leaf is not its own anchor.
    var self_flags: u32 = 0;
    if (server.verifyIntoWithProfile(&server, &profile, &self_flags)) |_| {
        std.debug.print("smoke: the server certificate verified against itself\n", .{});
        return error.CheckFailed;
    } else |_| {}
    try check(w, "a self-anchored chain reports a reason", self_flags != 0, true);

    var entropy = mbedtls.Entropy.init();
    defer entropy.deinit();
    if (entropy.gather()) |_| {
        try w.print("{s: <44}{s}\n", .{ "entropy gather", "ok" });
    } else |_| {
        // A platform where upstream found no strong source cannot gather. That
        // is a fact about the host, printed rather than asserted, because this
        // program's job is to report what this build does.
        try w.print("{s: <44}{s}\n", .{ "entropy gather", "no strong source on this host" });
    }
}

/// A real handshake over a loopback socket, against the fixture and nothing else.
///
/// Skipped, not faked, where the platform has no BSD sockets: the line says so
/// rather than printing a value nobody checked.
fn handshake(w: *std.Io.Writer) !void {
    if (!has_socket_transport) {
        try w.print("{s: <44}{s}\n", .{
            "TLS handshake",
            "skipped: no socket transport on this target",
        });
        return;
    }

    var entropy = mbedtls.Entropy.init();
    defer entropy.deinit();

    var ca = mbedtls.Certificate.init();
    defer ca.deinit();
    try ca.parse(test_ca_pem);

    var cert = mbedtls.Certificate.init();
    defer cert.deinit();
    try cert.parse(server_cert_pem);

    var key = mbedtls.PrivateKey.init();
    defer key.deinit();
    key.parsePem(server_key_pem, &entropy) catch |err| {
        std.debug.print("smoke: the fixture key did not parse: {s}\n", .{@errorName(err)});
        return error.CheckFailed;
    };

    var listener = mbedtls.Socket.bindAll(port) catch |err| {
        std.debug.print("smoke: could not bind port {s}: {s}\n", .{ port, @errorName(err) });
        return error.CheckFailed;
    };
    defer listener.deinit();

    const Exchange = struct {
        var served: ?[]const u8 = null;

        fn run(
            bind_socket: *mbedtls.Socket,
            chain: *mbedtls.Certificate,
            private: *mbedtls.PrivateKey,
            alloc: std.mem.Allocator,
        ) void {
            // The server owns its entropy context and its own generator rather
            // than borrowing the client's. This build compiles
            // `MBEDTLS_THREADING_C` off, so the context has no mutex and
            // upstream documents every entry point as "thread-safe if
            // MBEDTLS_THREADING_C is enabled"
            // (`src/include/mbedtls/entropy.h:146,167,178,190`); two threads
            // drawing from one context is a race this program does not enter.
            var server_entropy = mbedtls.Entropy.init();
            defer server_entropy.deinit();
            var server_drbg = mbedtls.Drbg.init();
            defer server_drbg.deinit();
            server_drbg.seed(&server_entropy) catch {
                // The thread cannot return an error, and a server that never
                // got a generator would fail the handshake with the client
                // reporting a closed connection - so the reason is printed.
                std.debug.print("smoke: the server's generator did not seed\n", .{});
                return;
            };

            var config = mbedtls.TlsConfig.init(.server);
            defer config.deinit();
            config.authMode(.none);
            config.rng(&server_drbg);
            // Both ends pinned to one version, so the negotiated answer is a
            // literal rather than "whichever the preference order chose".
            config.minVersion(.tls1_2);
            config.maxVersion(.tls1_2);
            config.ownCertificate(chain, private);
            // The server verifies no peer, so this profile changes nothing
            // here; it is named on both ends so the policy of the exchange is
            // stated once, where a reader sees the client copy below.
            var profile = legacySha1();
            config.certProfile(&profile);

            var connection = mbedtls.Socket.accept(bind_socket) catch |err| {
                std.debug.print("smoke: the server could not accept: {s}\n", .{@errorName(err)});
                return;
            };
            defer connection.deinit();
            var endpoint = mbedtls.Endpoint.init();
            defer endpoint.deinit();
            endpoint.setup(&config) catch |err| {
                std.debug.print("smoke: the server configuration was refused: {s}\n", .{@errorName(err)});
                return;
            };
            endpoint.setSocket(&connection);
            // The reason is printed, not swallowed: a server thread that
            // returns silently leaves the client reporting a closed connection,
            // which names the symptom and not the cause.
            endpoint.handshake() catch |err| {
                std.debug.print("smoke: the server handshake failed: {s}\n", .{@errorName(err)});
                return;
            };

            var buffer: [64]u8 = undefined;
            const got = endpoint.read(&buffer) catch |e| {
                std.debug.print("smoke: the server read failed: {s}\n", .{@errorName(e)});
                return;
            };
            if (got == 0) return;
            _ = endpoint.write(response) catch |e| {
                std.debug.print("smoke: the server write failed: {s}\n", .{@errorName(e)});
                return;
            };
            endpoint.closeNotify();
            served = alloc.dupe(u8, buffer[0..got]) catch null;
        }
    };
    defer if (Exchange.served) |text| std.heap.page_allocator.free(text);

    const thread = std.Thread.spawn(.{}, Exchange.run, .{
        &listener, &cert, &key, std.heap.page_allocator,
    }) catch |err| {
        std.debug.print("smoke: could not start the server thread: {s}\n", .{@errorName(err)});
        return error.CheckFailed;
    };
    defer thread.join();

    var drbg = mbedtls.Drbg.init();
    defer drbg.deinit();
    drbg.seed(&entropy) catch |err| {
        std.debug.print("smoke: the client's generator did not seed: {s}\n", .{@errorName(err)});
        return error.CheckFailed;
    };

    var client_config = mbedtls.TlsConfig.init(.client);
    defer client_config.deinit();
    client_config.authMode(.required);
    client_config.rng(&drbg);
    client_config.caChain(&ca);
    client_config.minVersion(.tls1_2);
    client_config.maxVersion(.tls1_2);
    // The vendored chain is SHA-1 signed, so the client's verification profile
    // has to name that, and `certificateChecks` above prints what the default
    // profile does with the same two files.
    var profile = legacySha1();
    client_config.certProfile(&profile);

    var client_socket = mbedtls.Socket.connect("127.0.0.1", port) catch |err| {
        std.debug.print("smoke: could not connect to port {s}: {s}\n", .{ port, @errorName(err) });
        return error.CheckFailed;
    };
    defer client_socket.deinit();

    var client = mbedtls.Endpoint.init();
    defer client.deinit();
    client.setup(&client_config) catch |err| {
        std.debug.print("smoke: the client configuration was refused: {s}\n", .{@errorName(err)});
        return error.CheckFailed;
    };
    client.setHostname("localhost") catch |err| {
        std.debug.print("smoke: setHostname was refused: {s}\n", .{@errorName(err)});
        return error.CheckFailed;
    };
    client.setSocket(&client_socket);

    client.handshake() catch |err| {
        std.debug.print("smoke: the handshake failed: {s}\n", .{@errorName(err)});
        return error.CheckFailed;
    };
    try checkString(w, "negotiated version", client.negotiatedVersion() orelse "none", "TLSv1.2");
    try checkCount(w, "verify flags after the handshake", client.verifyFlags(), 0);

    _ = client.write(request) catch |err| {
        std.debug.print("smoke: the request could not be written: {s}\n", .{@errorName(err)});
        return error.CheckFailed;
    };
    var answer: [64]u8 = undefined;
    const length = client.read(&answer) catch |err| {
        std.debug.print("smoke: the answer could not be read: {s}\n", .{@errorName(err)});
        return error.CheckFailed;
    };
    try checkString(w, "the server answered", answer[0..length], response);
    client.closeNotify();
}

/// The provider a runtime-loading build was pointed at.
///
/// `--provider <path>` or `MBED_TLS_TEST_PROVIDER`, both explicit. Nothing is
/// looked for in a default location and no other file is tried: a
/// runtime-loading build that was not told where its provider is stops with a
/// message saying so, rather than resolving a library it was not asked for.
fn providerRequest(init: std.process.Init) ![]const u8 {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        if (std.mem.eql(u8, args[index], "--provider")) {
            if (index + 1 < args.len) return args[index + 1];
            break;
        }
    }
    if (init.environ_map.get("MBED_TLS_TEST_PROVIDER")) |from_environment| return from_environment;
    std.debug.print(
        "smoke: this is a runtime-loading build. Pass --provider <path>, or " ++
            "export MBED_TLS_TEST_PROVIDER with a shared object exporting the " ++
            "mbedtls_* and psa_* declarations of zig/translate.h. Nothing is " ++
            "loaded by default and no other file is tried.\n",
        .{},
    );
    return error.NoProviderConfigured;
}

// ---------------------------------------------------------------------------
// The check helpers
//
// Print, then compare, then fail through the return type. Nothing here calls
// `exit`, and nothing here allocates.
// ---------------------------------------------------------------------------

fn check(w: *std.Io.Writer, what: []const u8, got: bool, expected: bool) CheckError!void {
    try w.print("{s: <44}{s}\n", .{ what, if (got) "yes" else "no" });
    if (got != expected) {
        std.debug.print(
            "smoke: {s}: expected {s}, computed {s}\n",
            .{ what, if (expected) "yes" else "no", if (got) "yes" else "no" },
        );
        return error.CheckFailed;
    }
}

fn checkCount(w: *std.Io.Writer, what: []const u8, got: anytype, expected: anytype) CheckError!void {
    try w.print("{s: <44}{d}\n", .{ what, got });
    if (got != expected) {
        std.debug.print("smoke: {s}: expected {d}, computed {d}\n", .{ what, expected, got });
        return error.CheckFailed;
    }
}

fn checkString(
    w: *std.Io.Writer,
    what: []const u8,
    got: []const u8,
    expected: []const u8,
) CheckError!void {
    try w.print("{s: <44}{s}\n", .{ what, got });
    if (!std.mem.eql(u8, got, expected)) {
        std.debug.print(
            "smoke: {s}: expected \"{s}\", computed \"{s}\"\n",
            .{ what, expected, got },
        );
        return error.CheckFailed;
    }
}

/// Compares bytes by printing them as hex straight to the writer.
///
/// `{x}` formats one byte as two hex digits through `std/Io/Writer`'s
/// `printHex`, so no formatting buffer is needed and no allocation happens.
fn checkBytes(
    w: *std.Io.Writer,
    what: []const u8,
    got: []const u8,
    expected_hex: []const u8,
) CheckError!void {
    try w.writeAll(what);
    var padding = what.len;
    while (padding < 44) : (padding += 1) try w.writeByte(' ');
    try w.writeByte('{');
    try w.print("{x}", .{got});
    try w.writeAll("}\n");

    var decoded: [128]u8 = undefined;
    const wanted = decodeHex(expected_hex, &decoded) orelse {
        std.debug.print("smoke: {s}: the expected value is not hex\n", .{what});
        return error.CheckFailed;
    };
    if (wanted.len != got.len) {
        std.debug.print(
            "smoke: {s}: expected {d} bytes, computed {d}\n",
            .{ what, wanted.len, got.len },
        );
        return error.CheckFailed;
    }
    if (!std.mem.eql(u8, wanted, got)) {
        std.debug.print("smoke: {s}: expected {s}\n", .{ what, expected_hex });
        return error.CheckFailed;
    }
}

/// Decodes a lower-case hex string into `out`, or null when `text` is not one
/// or does not fit.
///
/// The literals are kept as hex rather than as byte arrays because that is how
/// the standards print them, so a reader comparing this file against FIPS 180-4
/// can see that the two are the same string. The decoder is total: any
/// character that is not a hex digit, or an odd length, is a bug in this file
/// and is reported rather than tolerated.
fn decodeHex(text: []const u8, out: []u8) ?[]const u8 {
    if (text.len % 2 != 0 or text.len / 2 > out.len) return null;
    var index: usize = 0;
    while (index < text.len) : (index += 2) {
        const high = hexDigit(text[index]) orelse return null;
        const low = hexDigit(text[index + 1]) orelse return null;
        out[index / 2] = (high << 4) | low;
    }
    return out[0 .. text.len / 2];
}

fn hexDigit(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        else => null,
    };
}