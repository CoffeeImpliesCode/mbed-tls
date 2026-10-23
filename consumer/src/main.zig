// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// See ../FORK-LICENSE.md for what that identifier covers.

//! Host consumer for linked and runtime-loaded Mbed TLS.
//! Exercises a TLS handshake with upstream's published certificates.
//! The fixed-port `bindAll` listener opens on every host interface.

const std = @import("std");
const mbedtls = @import("mbedtls");
const fixtures = @import("fixtures");

const CheckError = std.Io.Writer.Error || error{ConsumerCheckFailed};

const Port = "49171";

/// Numeric loopback address; the certificate name is set separately.
const ClientAddress = "127.0.0.1";

/// SNI and certificate hostname used with the fixture.
const ServerName = "localhost";

const Request = "GET /consumer HTTP/1.1\r\nHost: localhost\r\n\r\n";
const Response = "loopback TLS handshake completed\r\n";

/// TLS 1.2 ECDHE-RSA suites with forward secrecy and AEAD.
/// The list matches suites enabled by this configuration.
const Tls12EcdheRsaSuites = [_][]const u8{
    "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256",
    "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384",
    "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256",
};

/// Result written by the server thread and read after `join`.
const ServerOutcome = struct {
    accepted: bool = false,
    /// Bounded buffer; oversized input fails comparison instead of truncating.
    request: [128]u8 = undefined,
    request_len: usize = 0,
    response_sent: usize = 0,
    version: [16]u8 = undefined,
    version_len: usize = 0,
    cipher: [64]u8 = undefined,
    cipher_len: usize = 0,
    verify_flags: u32 = 0,
    /// Failure step recorded for the joining thread.
    stage: []const u8 = "none",
    failure: ?anyerror = null,

    fn fail(self: *ServerOutcome, stage: []const u8, err: anyerror) void {
        if (self.failure != null) return;
        self.stage = stage;
        self.failure = err;
    }
};

/// Read the explicit provider path from argv or environment; no default search.
fn providerRequest(init: std.process.Init) []const u8 {
    const args = init.minimal.args.toSlice(init.arena.allocator()) catch
        std.debug.panic("consumer: the argument list could not be read\n", .{});
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        if (!std.mem.eql(u8, args[index], "--provider")) continue;
        if (index + 1 >= args.len) noProvider();
        return args[index + 1];
    }
    return init.environ_map.get("MBED_TLS_TEST_PROVIDER") orelse noProvider();
}

/// Stop when a runtime-loaded build has no explicit provider.
fn noProvider() []const u8 {
    std.debug.panic(
        "consumer: this is a runtime-loading build. Pass --provider <path>, or " ++
            "export MBED_TLS_TEST_PROVIDER with a shared object exporting the " ++
            "declarations of zig/translate.h. Nothing is loaded by default and " ++
            "no other file is tried.",
        .{},
    );
}

/// Runs the server side of the handshake.
/// The caller keeps its listener, configuration, certificate, and key alive through `join`.
fn serve(listener: *mbedtls.Socket, conf: *mbedtls.TlsConfig, outcome: *ServerOutcome) void {
    var socket = mbedtls.Socket.accept(listener) catch |err| {
        outcome.fail("accept", err);
        return;
    };
    defer socket.deinit();
    outcome.accepted = true;

    var endpoint = mbedtls.Endpoint.init();
    defer endpoint.deinit();

    endpoint.setup(conf) catch |err| {
        outcome.fail("setup", err);
        return;
    };
    endpoint.setSocket(&socket);

    endpoint.handshake() catch |err| {
        outcome.fail("handshake", err);
        return;
    };

    // Copy endpoint-owned strings before the endpoint is freed.
    outcome.version_len = copyText(endpoint.negotiatedVersion(), outcome.version[0..]);
    outcome.cipher_len = copyText(endpoint.negotiatedCipher(), outcome.cipher[0..]);
    outcome.verify_flags = endpoint.verifyFlags();

    outcome.request_len = endpoint.read(&outcome.request) catch |err| {
        outcome.fail("read", err);
        return;
    };
    outcome.response_sent = endpoint.write(Response) catch |err| {
        outcome.fail("write", err);
        return;
    };

    // Send a clean TLS close so the client can check EOF.
    endpoint.closeNotify();
}

/// Copy an optional borrowed string into a fixed buffer and return its length.
/// Zero-fill missing and unused bytes.
fn copyText(borrowed: ?[]const u8, into: []u8) usize {
    const text = borrowed orelse {
        @memset(into, 0);
        return 0;
    };
    const n = @min(text.len, into.len);
    @memcpy(into[0..n], text[0..n]);
    @memset(into[n..], 0);
    return n;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buffer);
    const w = &stdout.interface;

    // Runtime mode loads the provider before native calls; linked mode skips this.
    if (comptime mbedtls.runtime_loaded) {
        try mbedtls.load(.{ .path = providerRequest(init) });
    }

    try w.print("mbed-tls consumer\n", .{});
    var version: [32]u8 = undefined;
    try w.print("{s: <44}{s}\n", .{
        "library version, provenance only",
        try mbedtls.versionString(&version),
    });

    // Check whether the configured entropy sources can produce random bytes.
    var entropy = mbedtls.Entropy.init();
    defer entropy.deinit();
    const gathered: []const u8 = if (entropy.gather()) |_| "ok" else |err| @errorName(err);
    try checkString(w, "mbedtls_entropy_gather on this host", gathered, "ok");

    var ca = mbedtls.Certificate.init();
    defer ca.deinit();
    try ca.parse(fixtures.ca);

    var server_cert = mbedtls.Certificate.init();
    defer server_cert.deinit();
    try server_cert.parse(fixtures.server_cert);

    var server_key = mbedtls.PrivateKey.init();
    defer server_key.deinit();
    try server_key.parsePem(fixtures.server_key, &entropy);

    // Check parsed certificate fields against the fixture's DER values.
    var dn: [256]u8 = undefined;
    var short: [64]u8 = undefined;

    try checkString(
        w,
        "test-ca.crt subject",
        try ca.subject(&dn),
        "C=NL, O=PolarSSL, CN=PolarSSL Test CA",
    );
    try checkString(w, "test-ca.crt is a CA", yesNo(ca.isCa()), "yes");
    try checkString(
        w,
        "server2.crt subject",
        try server_cert.subject(&dn),
        "C=NL, O=PolarSSL, CN=localhost",
    );
    try checkString(
        w,
        "server2.crt issuer",
        try server_cert.issuer(&dn),
        "C=NL, O=PolarSSL, CN=PolarSSL Test CA",
    );
    try checkString(w, "server2.crt serial", try server_cert.serial(&short), "02");
    try checkString(w, "server2.crt is a CA", yesNo(server_cert.isCa()), "no");
    try checkInt(w, "server2.crt X.509 version", server_cert.version(), 3);

    const server_bits = server_cert.rsaBitLength() orelse return error.NoRsaKey;
    try checkInt(w, "server2.crt RSA modulus bits", server_bits, 2048);

    try checkTime(w, "server2.crt validFrom", server_cert.validFrom(), .{
        .year = 2019,
        .mon = 2,
        .day = 10,
        .hour = 14,
        .min = 44,
        .sec = 6,
    });
    try checkTime(w, "server2.crt validTo", server_cert.validTo(), .{
        .year = 2029,
        .mon = 2,
        .day = 10,
        .hour = 14,
        .min = 44,
        .sec = 6,
    });

    // The fixture's SHA-1 signatures fail the default profile with `BAD_MD` (0x4000).
    // The handshake uses a SHA-1-accepting profile; both trust results are checked.
    var default_flags: u32 = 0xFFFF_FFFF;
    if (server_cert.verifyInto(&ca, &default_flags)) |_| {
        try w.print("server2.crt verified under the default profile\n", .{});
        return error.UnexpectedTrust;
    } else |_| {}
    try checkInt(w, "default-profile bad-cert bits", default_flags, 0x4000);

    var profile = mbedtls.CertificateProfile.default().allowingMd(.sha1);
    var flags: u32 = 0xFFFF_FFFF;
    try server_cert.verifyIntoWithProfile(&ca, &profile, &flags);
    try checkInt(w, "server2.crt against test-ca.crt, bad-cert bits", flags, 0);

    // Pin both endpoints to TLS 1.2 for literal version assertions.
    var server_conf = mbedtls.TlsConfig.init(.server);
    // Seed one DRBG per endpoint; entropy's output cap is too small for RSA blinding.
    var server_drbg = mbedtls.Drbg.init();
    defer server_drbg.deinit();
    try server_drbg.seed(&entropy);
    var client_drbg = mbedtls.Drbg.init();
    defer client_drbg.deinit();
    try client_drbg.seed(&entropy);

    defer server_conf.deinit();
    server_conf.rng(&server_drbg);
    server_conf.ownCertificate(&server_cert, &server_key);
    // The server requests no client certificate; the client identity is tested.
    server_conf.authMode(.none);
    server_conf.minVersion(.tls1_2);
    server_conf.maxVersion(.tls1_2);
    server_conf.certProfile(&profile);

    var client_conf = mbedtls.TlsConfig.init(.client);
    defer client_conf.deinit();
    client_conf.rng(&client_drbg);
    client_conf.caChain(&ca);
    client_conf.authMode(.required);
    client_conf.minVersion(.tls1_2);
    client_conf.maxVersion(.tls1_2);
    // Use the SHA-1-accepting profile for this fixture's handshake.
    client_conf.certProfile(&profile);

    // Socket timeouts bound the server's accept and handshake waits.
    var listener = try mbedtls.Socket.bindAll(Port);
    defer listener.deinit();

    var outcome = ServerOutcome{};
    var server_thread: ?std.Thread = try std.Thread.spawn(.{}, serve, .{
        &listener,
        &server_conf,
        &outcome,
    });
    // Join after later-declared sockets/endpoints close, unblocking the server on errors.
    defer if (server_thread) |thread| thread.join();

    var socket = try mbedtls.Socket.connect(ClientAddress, Port);
    defer socket.deinit();

    var endpoint = mbedtls.Endpoint.init();
    defer endpoint.deinit();
    try endpoint.setup(&client_conf);
    // Set both SNI and the certificate hostname.
    try endpoint.setHostname(ServerName);
    endpoint.setSocket(&socket);

    try endpoint.handshake();

    const client_version = endpoint.negotiatedVersion() orelse return error.NoNegotiatedVersion;
    try checkString(w, "client negotiated version", client_version, "TLSv1.2");
    const client_cipher = endpoint.negotiatedCipher() orelse return error.NoNegotiatedCipher;
    try checkOneOf(w, "client negotiated cipher", client_cipher, &Tls12EcdheRsaSuites);
    try checkInt(w, "client verify result, bad-cert bits", endpoint.verifyFlags(), 0);

    const sent = try endpoint.write(Request);
    try checkInt(w, "client wrote every request byte", sent, Request.len);

    var received: [128]u8 = undefined;
    const got = try endpoint.read(&received);
    try checkString(w, "client read the server's answer", received[0..got], Response);

    // The facade reports peer `close_notify` as EOF.
    var scratch: [1]u8 = undefined;
    const after_close = try endpoint.read(&scratch);
    try checkInt(w, "client read the server's close_notify", after_close, 0);

    endpoint.closeNotify();

    if (server_thread) |thread| {
        thread.join();
        server_thread = null;
    }

    try checkString(w, "server accepted one connection", yesNo(outcome.accepted), "yes");
    try checkString(
        w,
        "server read the request",
        outcome.request[0..outcome.request_len],
        Request,
    );
    try checkInt(w, "server wrote every response byte", outcome.response_sent, Response.len);
    // Use recorded lengths; fixed buffers may not contain a terminator.
    try checkString(w, "server negotiated version", outcome.version[0..outcome.version_len], "TLSv1.2");
    try checkOneOf(w, "server negotiated cipher", outcome.cipher[0..outcome.cipher_len], &Tls12EcdheRsaSuites);
    // `0x80` means verification was skipped because the server requested no client certificate.
    // `0x40` would mean a requested client certificate was missing.
    try checkInt(w, "server verify result, bad-cert bits", outcome.verify_flags, 0x80);

    if (outcome.failure) |err| {
        std.debug.print(
            "consumer: the server stopped at '{s}': {s}\n",
            .{ outcome.stage, @errorName(err) },
        );
        return error.ServerExchangeFailed;
    }

    try w.print("every answer matched its expected literal\n", .{});
    try w.flush();
}

fn yesNo(value: bool) []const u8 {
    return if (value) "yes" else "no";
}

fn checkString(
    w: *std.Io.Writer,
    what: []const u8,
    got: []const u8,
    expected: []const u8,
) CheckError!void {
    try w.print("{s: <44}{s}\n", .{ what, got });
    if (std.mem.eql(u8, got, expected)) return;
    std.debug.print("consumer: {s}: expected \"{s}\", got \"{s}\"\n", .{
        what,
        expected,
        got,
    });
    return error.ConsumerCheckFailed;
}

fn checkInt(
    w: *std.Io.Writer,
    what: []const u8,
    got: anytype,
    expected: anytype,
) CheckError!void {
    try w.print("{s: <44}{d}\n", .{ what, got });
    if (got == expected) return;
    std.debug.print("consumer: {s}: expected {d}, got {d}\n", .{ what, expected, got });
    return error.ConsumerCheckFailed;
}

fn checkOneOf(
    w: *std.Io.Writer,
    what: []const u8,
    got: []const u8,
    allowed: []const []const u8,
) CheckError!void {
    try w.print("{s: <44}{s}\n", .{ what, got });
    for (allowed) |name| {
        if (std.mem.eql(u8, got, name)) return;
    }
    std.debug.print("consumer: {s}: \"{s}\" is not one of", .{ what, got });
    for (allowed) |name| std.debug.print(" \"{s}\"", .{name});
    std.debug.print("\n", .{});
    return error.ConsumerCheckFailed;
}

fn checkTime(
    w: *std.Io.Writer,
    what: []const u8,
    got: mbedtls.c.mbedtls_x509_time,
    expected: mbedtls.c.mbedtls_x509_time,
) CheckError!void {
    try w.print("{s: <44}{d: >5}-{d: >2}-{d: >2}T{d: >2}:{d: >2}:{d: >2}\n", .{
        what,
        got.year,
        got.mon,
        got.day,
        got.hour,
        got.min,
        got.sec,
    });
    if (std.meta.eql(got, expected)) return;
    std.debug.print(
        "consumer: {s}: expected {d: >5}-{d: >2}-{d: >2}, got {d: >5}-{d: >2}-{d: >2}\n",
        .{ what, expected.year, expected.mon, expected.day, got.year, got.mon, got.day },
    );
    return error.ConsumerCheckFailed;
}
