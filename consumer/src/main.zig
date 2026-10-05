// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// See ../FORK-LICENSE.md for what that identifier covers.

//! Consumes the `mbed-tls` package the way an outside project would.
//!
//! Everything here goes through the published surface only: `dep.module` in
//! `build.zig`, and `@import("mbedtls")` here. The only thing that arrives from
//! elsewhere is the `fixtures` module `build.zig` generates, which carries
//! byte-for-byte copies of three files upstream publishes itself. No path
//! reaches into the library's source tree. If this builds and produces the
//! answers below, the module contract is real: the typed facade, the translated
//! headers it re-exports as `c`, and the three archives the module carries all
//! arrived through one dependency line.
//!
//! ## What it actually does
//!
//! One real TLS handshake over a real TCP socket, between a client and a server
//! in this one process, using upstream's own published `test-ca.crt`,
//! `server2.crt` and `server2.key`. The client verifies the server's chain
//! against the embedded CA, checks the name `localhost`, sends one request, reads
//! one answer, and then sees the server's `close_notify` arrive.
//!
//! Nothing is compared against a value this program computed: every answer is
//! checked against a literal, either a field read out of the fixture's own DER
//! or a name the protocol itself defines. A mismatch exits non-zero.
//!
//! ## The listener cannot be a loopback socket
//!
//! `mbedtls_net_bind` takes a null address or an address, and upstream offers no
//! way to ask for a loopback-only listener, so `Socket.bindAll` passes null and
//! binds every interface. The listener therefore exists on every interface of
//! this host for the lifetime of this run. Nothing in this facade can change
//! that, and inventing a loopback default would hide it. A caller that must not
//! expose a listener has to place it behind whatever its platform provides.
//!
//! The port is fixed for the same kind of reason: `Socket.bindAll` takes a port
//! string and nothing else, so no part of this library chooses one and there is
//! no way to ask which port was taken. A collision with something already bound
//! is reported as `error.System` and exits non-zero rather than retrying another
//! port, because a silent retry would make "which port did this run use"
//! unanswerable.
//!
//! ## Where this runs
//!
//! `Socket` needs `MBEDTLS_NET_C`, which `zig/config_gen.zig` turns off exactly
//! where `src/library/net_sockets.c:22-24` refuses the file - `wasm32-wasi`. So
//! this is a host program, and it is not one of the six cross targets the
//! library package itself is checked against.
//!
//! ## One source, two configurations
//!
//! `mbedtls.runtime_loaded` is a comptime constant, so the same source compiles
//! against a linked package and a runtime-loaded one. In the runtime-loaded
//! build the provider is named on the command line (`--provider <path>`) or in
//! `MBED_TLS_TEST_PROVIDER`, loaded once, and the same answers follow. In a
//! linked build `mbedtls.load` stops the program if it is called at all, which
//! is why the call below is inside a `comptime` branch that a linked build
//! never analyzes.

const std = @import("std");
const mbedtls = @import("mbedtls");
const fixtures = @import("fixtures");

/// Every way a printed answer can be wrong.
///
/// The writer's own failure is in here because a line that did not reach the
/// terminal is a line that checked nothing, and reporting a mismatch after a
/// failed write would be a check nobody saw. The mismatch tag is what makes
/// `main` exit non-zero.
const CheckError = std.Io.Writer.Error || error{ConsumerCheckFailed};

/// The port the listener binds. See the note above: fixed, not chosen.
const Port = "49171";

/// The address the client connects to.
///
/// A numeric address, so nothing here depends on a name resolver. The name the
/// certificate must carry is a separate question and is asked separately, through
/// `Endpoint.setHostname`.
const ClientAddress = "127.0.0.1";

/// The name sent in SNI and checked against the certificate.
///
/// `server2.crt` has `CN=localhost`, so this both exercises the check and
/// matches the fixture. Using `ClientAddress` here would fail the handshake on a
/// fixture that is correct, which would test the wrong thing.
const ServerName = "localhost";

/// The bytes the client sends and the server answers.
///
/// Two literals, so the exchange is checked against a stated expectation rather
/// than against whatever happened to arrive.
const Request = "GET /consumer HTTP/1.1\r\nHost: localhost\r\n\r\n";
const Response = "loopback TLS handshake completed\r\n";

/// The TLS 1.2 suites this configuration can select with an RSA certificate.
///
/// Three literals, in the order `src/library/ssl_ciphersuites.c` lists them:
/// `MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` at line 52,
/// `MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` at line 58 and
/// `MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` at line 90, spelled as the
/// library spells them at lines 328, 530 and 516.
///
/// Each is an ephemeral key exchange with an AEAD, and each needs
/// `MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED`
/// (`src/include/mbedtls/mbedtls_config.h:1033`) plus its cipher, so a suite
/// without forward secrecy or without authenticated encryption is not on this
/// list: it would fail the check rather than pass it.
const Tls12EcdheRsaSuites = [_][]const u8{
    "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256",
    "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384",
    "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256",
};

/// What the server thread observed, read by the main thread after `join`.
///
/// The server thread writes here and prints nothing: there is one writer in this
/// program, so no lock is needed and no line can interleave.
const ServerOutcome = struct {
    accepted: bool = false,
    /// Larger than `Request` and bounded, so a peer that sends more than the
    /// literal fails the comparison instead of passing a truncated one.
    request: [128]u8 = undefined,
    request_len: usize = 0,
    response_sent: usize = 0,
    version: [16]u8 = undefined,
    version_len: usize = 0,
    cipher: [64]u8 = undefined,
    cipher_len: usize = 0,
    verify_flags: u32 = 0,
    /// Where the server stopped, if it stopped. A thread cannot return an error
    /// to its joiner, so it names the step here instead.
    stage: []const u8 = "none",
    failure: ?anyerror = null,

    fn fail(self: *ServerOutcome, stage: []const u8, err: anyerror) void {
        if (self.failure != null) return;
        self.stage = stage;
        self.failure = err;
    }
};

/// The provider this run should load, from `--provider <path>` or from
/// `MBED_TLS_TEST_PROVIDER`.
///
/// Both are explicit. Nothing here looks in a default location, and a build that
/// was not told which file to load stops rather than loading something else.
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

/// Stop, naming both ways a provider can be named.
///
/// A runtime-loading build has no library at all until one is named, so there is
/// nothing to fall back on and no honest way to continue. An error name on its
/// own would also send the next person into the loader instead of to the command
/// line.
fn noProvider() []const u8 {
    std.debug.panic(
        "consumer: this is a runtime-loading build. Pass --provider <path>, or " ++
            "export MBED_TLS_TEST_PROVIDER with a shared object exporting the " ++
            "declarations of zig/translate.h. Nothing is loaded by default and " ++
            "no other file is tried.",
        .{},
    );
}

/// The server half of the exchange: accept, handshake, read, answer, close.
///
/// Everything it borrows belongs to the main thread and outlives the join: the
/// listener stays open until `main` returns, and the configuration, the
/// certificate and the key all outlive it too.
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

    // The library owns these two strings, and this endpoint is freed at the end
    // of this function, so they are copied out rather than borrowed.
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

    // RFC 8446 section 6.1: this is how the client learns the stream ended
    // deliberately rather than being cut. The client reads that notice below.
    endpoint.closeNotify();
}

/// Copy a library-owned string into a caller buffer, bounded, and report how
/// many bytes it wrote.
///
/// The length is returned because the caller's buffer is a fixed-size array
/// with no room for a terminator, so the reader needs the length `copyText`
/// already computed. The tail is zeroed as well, so a field that was never
/// filled prints as empty rather than as whatever was on the stack.
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

    // In a runtime-loading build every native call below goes through one table
    // that this single call fills. In a linked build the branch is never
    // analyzed, and `mbedtls.load` is never named.
    if (comptime mbedtls.runtime_loaded) {
        try mbedtls.load(.{ .path = providerRequest(init) });
    }

    try w.print("mbed-tls consumer\n", .{});
    // Through the library, so this line names what this build reached rather
    // than a constant compiled into this program. Printed, not compared: a
    // version string is provenance, not behaviour.
    var version: [32]u8 = undefined;
    try w.print("{s: <44}{s}\n", .{
        "library version, provenance only",
        try mbedtls.versionString(&version),
    });

    // The entropy source both configurations borrow. `mbedtls_entropy_init` has
    // no failure mode; whether the platform sources this build registered can
    // actually produce random bytes is a question with an answer, and on a host
    // that has one the answer is "ok".
    var entropy = mbedtls.Entropy.init();
    defer entropy.deinit();
    const gathered: []const u8 = if (entropy.gather()) |_| "ok" else |err| @errorName(err);
    try checkString(w, "mbedtls_entropy_gather on this host", gathered, "ok");

    // The three embedded files, through upstream's own parsers.
    var ca = mbedtls.Certificate.init();
    defer ca.deinit();
    try ca.parse(fixtures.ca);

    var server_cert = mbedtls.Certificate.init();
    defer server_cert.deinit();
    try server_cert.parse(fixtures.server_cert);

    var server_key = mbedtls.PrivateKey.init();
    defer server_key.deinit();
    try server_key.parsePem(fixtures.server_key, &entropy);

    // Every answer below is a field of the fixture itself, read out of its own
    // DER: C, then O, then CN in the order the DER encodes the distinguished
    // name, serial `02`, RSA 2048, validity 2019-02-10 14:44:06 through
    // 2029-02-10 14:44:06, X.509 version 3.
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

    // The trust decision, made by the library against the embedded CA and
    // reported as the `MBEDTLS_X509_BADCERT_*` bits.
    //
    // Both fixture certificates are `sha1WithRSAEncryption`, and Mbed TLS
    // 3.6.7's default profile allows SHA-256 and above
    // (`src/library/x509_crt.c:89-97`), so the default refuses this chain and
    // says so with `MBEDTLS_X509_BADCERT_BAD_MD` (0x4000,
    // `src/include/mbedtls/x509.h:105`). What OpenSSL independently reported as
    // `server2.crt: OK` is the same chain under a profile that also accepts
    // SHA-1, and both answers are printed.
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

    // Both ends are pinned to TLS 1.2. This build also compiles TLS 1.3, and
    // leaving the ends unpinned would make the negotiated version a preference
    // order rather than a stated fact, which is not something this program's
    // answers can then compare against a literal.
    var server_conf = mbedtls.TlsConfig.init(.server);
    // Two generators, each seeded on this thread before the server starts and
    // then used by exactly one endpoint. `TlsConfig.rng` wants an `f_rng`, and
    // `mbedtls_entropy_func` is not one: it caps a single request at
    // `MBEDTLS_ENTROPY_BLOCK_SIZE` (64 here) while RSA blinding draws a
    // modulus-sized value.
    var server_drbg = mbedtls.Drbg.init();
    defer server_drbg.deinit();
    try server_drbg.seed(&entropy);
    var client_drbg = mbedtls.Drbg.init();
    defer client_drbg.deinit();
    try client_drbg.seed(&entropy);

    defer server_conf.deinit();
    server_conf.rng(&server_drbg);
    server_conf.ownCertificate(&server_cert, &server_key);
    // No client certificate is sent, so there is nothing for the server to
    // check: this handshake is about the server's identity to the client.
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
    // The same profile the trust decision above used, so the handshake this
    // program drives reaches the end instead of stopping at the SHA-1 policy.
    client_conf.certProfile(&profile);

    // The listener, then the server thread, then the client. The server blocks
    // in accept until this thread connects, and both handshakes block on a
    // socket with a timeout, so neither side waits on the other indefinitely.
    var listener = try mbedtls.Socket.bindAll(Port);
    defer listener.deinit();

    var outcome = ServerOutcome{};
    var server_thread: ?std.Thread = try std.Thread.spawn(.{}, serve, .{
        &listener,
        &server_conf,
        &outcome,
    });
    // If anything below returns early, this still joins. The socket and the
    // endpoint declared after it are released first, because deferred blocks
    // unwind in reverse order, and closing them is what unblocks the server.
    defer if (server_thread) |thread| thread.join();

    var socket = try mbedtls.Socket.connect(ClientAddress, Port);
    defer socket.deinit();

    var endpoint = mbedtls.Endpoint.init();
    defer endpoint.deinit();
    try endpoint.setup(&client_conf);
    // Both effects at once: the name to send in SNI and the name to check the
    // certificate against.
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

    // The server sends close_notify as soon as it has answered, so this read is
    // the clean end of a stream arriving from the peer: zero bytes rather than
    // an error, which is `MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY` inside
    // `src/library/ssl_msg.c:5297` and the facade's decision to report it as
    // an end of stream. RFC 8446 section 6.1.
    var scratch: [1]u8 = undefined;
    const after_close = try endpoint.read(&scratch);
    try checkInt(w, "client read the server's close_notify", after_close, 0);

    // And then this side announces the same thing, which is all
    // `closeNotify` is: it reports nothing and cannot fail.
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
    // The recorded lengths, not `[0..]` and not a sentinel slice: these buffers
    // are fixed-size arrays that `copyText` may have filled completely, so
    // there is no terminator past the end to find.
    try checkString(w, "server negotiated version", outcome.version[0..outcome.version_len], "TLSv1.2");
    try checkOneOf(w, "server negotiated cipher", outcome.cipher[0..outcome.cipher_len], &Tls12EcdheRsaSuites);
    // `MBEDTLS_X509_BADCERT_SKIP_VERIFY` (0x80), not 0. The server runs with
    // `authMode(.none)`, so it asks for no client certificate and verifies
    // nothing; `mbedtls_ssl_get_verify_result` reports that as "verification
    // was skipped" (`src/include/mbedtls/x509.h:98`). A server that verified a
    // client certificate it never received would report `BADCERT_MISSING`
    // (0x40, `:97`) instead, so 0x80 is the positive evidence that the server
    // side asked for nothing and got nothing, as intended.
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

/// "yes" or "no", so a boolean reaches the same aligned label/value line every
/// other answer uses.
fn yesNo(value: bool) []const u8 {
    return if (value) "yes" else "no";
}

/// Print one label and value pair, then require the value to be the literal.
///
/// Every answer in this program goes through one of the four helpers below, so
/// no line can be printed without also being checked.
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

/// Print one label and a number, then require it to be the literal.
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

/// Print one label and a string, then require it to be one of the literals.
///
/// Used for a negotiated suite, where the configuration admits three named
/// answers and asserting any one of them alone would be a claim this program
/// cannot make without knowing the peer's preference order.
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

/// Print one label and an `mbedtls_x509_time`, then require it to equal a
/// literal one.
///
/// The type is named through the published `c` module rather than restated, so
/// reaching the translated headers from a dependent is part of what this line
/// exercises. `mbedtls_x509_time` is six `int`s, the certificate's own numbers
/// and not a Unix timestamp, with a 1-based month.
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