// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// See FORK-LICENSE.md for what that identifier covers.
//
//! The typed facade over Mbed TLS 3.6.
//!
//! `c` is the translated public headers, verbatim: every declaration the headers
//! reached through `zig/translate.h` contain, and nothing of this package's own.
//! The types and functions below are a convenience *over* that, never a
//! replacement for it, and every one of them names the file and line it was
//! read out of. Where a wrapper cannot honestly do what its C counterpart does,
//! it says so in its own documentation rather than hiding the difference.
//!
//! ## Where the answers come from
//!
//! Two sources, and neither is this build's own opinion:
//!
//!   * **Behaviour.** Mbed TLS's own headers, cited by `file:line` in each doc
//!     comment. A wrapper that claims a behaviour the C does not have is a bug,
//!     so every claim here traces to a line.
//!   * **The cryptographic answers** in `tests.zig` are published standard
//!     vectors - NIST FIPS 180-4, NIST SP 800-38A, the GCM specification, RFC
//!     8439 - and the handshake fixture is upstream's own published test
//!     certificate. They are computed in Zig or read out of the fixture, never
//!     run through the library and accepted, so a broken build cannot agree with
//!     itself.
//!
//! ## The allocator
//!
//! `mbedtls_calloc` and `mbedtls_free` are the allocator in this whole module.
//! `MBEDTLS_PLATFORM_C` is enabled by the configuration `zig/config_gen.zig`
//! generates, so `src/library/platform.c:143-148` dispatches them through
//! `mbedtls_platform_calloc_free`, and `src/library/platform.c:14-27` makes that
//! `calloc`/`free` again when no platform hooks are set. Either way no Zig
//! allocator is in the path.
//!
//! So `std.testing.allocator` cannot be a leak oracle for anything Mbed TLS
//! allocates, and nothing here claims it is. Every wrapper below that owns a
//! context has an idempotent `deinit`, and every test that creates one releases
//! it on every path including the failing one. That is the discipline, and it
//! is the strongest claim this package can honestly make about allocation.
//!
//! ## What is not here
//!
//!   * **PSA Crypto's key lifecycle.** `psa_crypto_init`, the key slots, the
//!     secure-element drivers and `psa/crypto_se_driver.h` are in the
//!     translation and reachable through `c`, but there is no typed wrapper. A
//!     PSA key is owned by a slot table inside the library, so a wrapper whose
//!     deinit could be skipped would leak a *slot*, not a pointer. That is a real
//!     hazard and this package does not paper over it with a wrapper whose
//!     failure mode is undocumented.
//!   * **DTLS.** The DTLS configuration and timer entry points are reachable
//!     through `c`. No wrapper claims DTLS, and `Socket` below is a stream
//!     transport only.
//!   * **Anything that would re-derive a value upstream defines.**
//!     `versionString` asks the library rather than restating the manifest, and
//!     `hasFeature` asks `mbedtls_version_check_feature`, which reads the same
//!     `mbedtls_config.h` this build compiled against.
//!
//! ## The two configurations
//!
//! This module is one source compiled two ways. With `-Druntime=true` the `c`
//! import is a generated dispatch that resolves every symbol through one
//! process-lifetime table after an explicit `load`, and a native call before
//! that `load` stops the program with a message naming the symbol. With the
//! default `-Druntime=false` the archive is linked and every call is direct.
//! `runtime_loaded` says which, at comptime.

const std = @import("std");

/// The translated public headers, verbatim.
pub const c = @import("c");

/// The loader core, which is where a linked build's two public types come
/// from.
///
/// It is imported only by the linked configuration. In a runtime-loading build
/// the dispatch carries its own copy of the same declarations, and this module
/// is never referenced, so it is never resolved and never compiled. Either way
/// there is exactly one `LoadSource` and one `LoadError` in a build, which is
/// what keeps them one type for a consumer that names them.
const rt = @import("rt");

/// Whether this module was configured to resolve its native symbols at run
/// time.
///
/// False for the ordinary build, where the C library is linked and `c` is the
/// translation of the public headers. True when the build generated a dispatch
/// that resolves the same symbols through the platform loader, in which case
/// `load` is the call that makes the library usable.
///
/// It is a comptime constant, so a consumer can write two different code paths
/// and have only the one it chose analyzed.
pub const runtime_loaded: bool = if (@hasDecl(c, "rt_runtime_loaded")) c.rt_runtime_loaded else false;

/// Which native library `load` should open.
///
/// `.path` is an explicit file path and `.system` is an explicit name for the
/// platform loader. There is no path-to-system fallback and no implicit
/// fallback of any kind; a request that cannot be honoured is an error, not a
/// different library.
pub const LoadSource = if (runtime_loaded) c.LoadSource else rt.LoadSource;

/// Every way `load` can decline.
///
/// Declared here, in the module a consumer imports, rather than only inside
/// the loader: the caller names the failure it is handling.
pub const LoadError = if (runtime_loaded) c.LoadError else rt.LoadError;

/// Load the native library this module dispatches to.
///
/// In a runtime-loading build this is the whole contract: call it once, then use
/// this module as if it were linked. Calling it again with the same request
/// succeeds and changes nothing; calling it with a different request after a
/// success is `ProviderMismatch`, and the library already in use stays in use. A
/// failed attempt publishes nothing and can be retried explicitly, by calling
/// this again: there is no automatic retry and no implicit second source.
///
/// In a linked build there is no provider, no table and nothing to resolve, so
/// this stops the program with a message saying so instead of quietly
/// succeeding. `runtime_loaded` is false there, so a consumer that supports both
/// configurations can tell the two apart at comptime.
pub fn load(source: LoadSource) LoadError!void {
    // `c.load` exists only in a runtime-loading build. The condition is known
    // at comptime, so the branch this build does not take is never analyzed and
    // never names it.
    if (runtime_loaded) return c.load(source);
    std.debug.panic(
        "mbedtls: load was called on a linked build; this module is not " ++
            "runtime-loaded, so there is no library to load. Build with runtime " ++
            "loading configured, or do not call load.",
        .{},
    );
}

/// The request that succeeded, or null when nothing has loaded yet.
///
/// The answer is the loader's own retained copy and stays valid for the life of
/// the process. Null in a linked build, which has no request.
pub fn loadedSource() ?LoadSource {
    if (runtime_loaded) return c.loadedSource();
    return null;
}

/// Whether the native library is usable right now.
///
/// True in a linked build, without consulting anything: the archive is on the
/// link line. In a runtime-loading build it is the loader's own readiness flag,
/// read with acquire ordering, so a caller that saw `true` also sees every field
/// of the table it was published with.
pub fn ready() bool {
    if (runtime_loaded) return c.rt_is_ready();
    return true;
}

// ---------------------------------------------------------------------------
// Version and diagnostics
// ---------------------------------------------------------------------------

/// The version this library reports, `"3.6.7"` for the pinned release.
///
/// `mbedtls_version_get_string` copies `MBEDTLS_VERSION_STRING` into a caller
/// buffer the header says must be "at least 9 bytes in size"
/// (`src/include/mbedtls/version.h:33-37`); this checks that, asks the library,
/// and hands back the bytes with the terminating NUL removed. The answer is
/// what the library was compiled as, not what this package's manifest says,
/// which is why it is asked for rather than restated.
pub fn versionString(buf: []u8) error{BufferTooSmall}![]const u8 {
    if (buf.len < 9) return error.BufferTooSmall;
    c.mbedtls_version_get_string(buf.ptr);
    // Upstream writes a NUL-terminated string, so the answer ends at the first
    // NUL. The buffer itself is not sentinel-typed, so the terminator is found
    // rather than asserted; a build that somehow wrote no terminator yields the
    // whole buffer rather than reading past it.
    const end = std.mem.indexOfScalar(u8, buf, 0) orelse buf.len;
    return buf[0..end];
}

/// The packed version number this library was compiled as,
/// `MBEDTLS_VERSION_NUMBER` - `0x03060700` for 3.6.7.
///
/// `mbedtls_version_get_number` returns it directly
/// (`src/include/mbedtls/build_info.h:25`). Comparing this against a number read
/// out of `build_info.h` compares the library against itself, which is
/// provenance; what a caller wants is to compare it against a number obtained
/// somewhere else. That is why no test in this package uses it as an oracle.
pub fn versionNumber() u32 {
    return c.mbedtls_version_get_number();
}

/// Whether a named configuration option was compiled in.
///
/// `mbedtls_version_check_feature` (`src/include/mbedtls/version.h:56-73`)
/// returns 0 if the option is present, -1 if it is not, and -2 if feature
/// checking was not compiled in at all. All three are answers, so this returns
/// the optional boolean rather than a `bool` that would have to invent one for
/// the third case.
pub fn hasFeature(name: []const u8) ?bool {
    if (name.len == 0 or std.mem.indexOfScalar(u8, name, 0) != null) return null;
    return switch (c.mbedtls_version_check_feature(name.ptr)) {
        0 => true,
        -1 => false,
        else => null,
    };
}

/// The library's own text for a status code.
///
/// `mbedtls_strerror` (`src/include/mbedtls/error.h:165`) takes an error number
/// and writes as much as fits into the caller's buffer, truncating rather than
/// failing. 3.6 removed the `MBEDTLS_STRERROR_MAX_SIZE` constant that 2.x had,
/// so there is no length this module can require: the caller supplies the buffer
/// and this hands back what was written, with the terminating NUL removed. A
/// code with no table entry leaves the buffer empty, and that is reported as the
/// empty string rather than as a message this module made up.
pub fn errorName(status: c_int, buf: []u8) []const u8 {
    if (buf.len == 0) return "";
    c.mbedtls_strerror(status, buf.ptr, buf.len);
    // `indexOfScalar` rather than `std.mem.sliceTo` on a `[:0]const u8` view of
    // `buf`: casting a non-sentinel slice to a sentinel one is a compile-time
    // error in Zig 0.16, so this function could not be instantiated at all, and
    // nothing in this package's own gates called it. A code whose text fills the
    // buffer exactly leaves no NUL to find, and the whole buffer is then the
    // answer rather than a panic.
    return buf[0..(std.mem.indexOfScalar(u8, buf, 0) orelse buf.len)];
}

// ---------------------------------------------------------------------------
// Errors
//
// Mbed TLS encodes a status as a negative high-level code or a positive
// low-level one, and every wrapper below cuts its taxonomy at the codes its own
// switch names. A code no tag claims becomes `Unknown`, never a tag invented
// for it.
// ---------------------------------------------------------------------------

/// Every way the TLS handshake can end.
///
/// The codes are the ones `src/include/mbedtls/ssl.h:47-204` defines and
/// `src/library/ssl_tls.c` actually returns, grouped by what a caller can do
/// about them rather than by module. `errorName` turns any of them back into
/// text, so a caller that needs the precise code rather than the tag can ask
/// the library rather than this module.
pub const HandshakeError = error{
    /// `MBEDTLS_ERR_SSL_WANT_READ` (-0x6900) or `MBEDTLS_ERR_SSL_WANT_WRITE`
    /// (-0x6880): the transport would block. The blocking route below never
    /// returns this, because `Socket` hands the library a socket with a timeout
    /// rather than a non-blocking one. A caller that supplied its own
    /// non-blocking transport through `Endpoint.setTransport` will see it.
    WantReadOrWrite,
    /// `MBEDTLS_ERR_SSL_TIMEOUT` (-0x6800).
    Timeout,
    /// `MBEDTLS_ERR_SSL_CLIENT_RECONNECT` (-0x6780): a client was asked to
    /// start a fresh handshake rather than resume.
    ClientReconnect,
    /// `MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY` (-0x7880): the peer sent
    /// `close_notify` in the middle of the handshake.
    PeerCloseNotify,
    /// `MBEDTLS_ERR_SSL_CONN_EOF` (-0x7280): the transport reached end of file
    /// with no `close_notify`, which RFC 8446 §6.1 calls an unclean shutdown.
    ConnectionEnded,
    /// `MBEDTLS_ERR_X509_CERT_VERIFY_FAILED` (-0x2700): the peer's chain did
    /// not verify. The reason is in `Endpoint.verifyFlags`, not here.
    CertificateVerifyFailed,
    /// The peer sent something this state machine cannot use:
    /// `MBEDTLS_ERR_SSL_BAD_INPUT_DATA` (-0x7100), `INVALID_RECORD` (-0x7200),
    /// `DECODE_ERROR` (-0x7300), `UNEXPECTED_MESSAGE` (-0x7700),
    /// `UNEXPECTED_RECORD` (-0x6700), `ILLEGAL_PARAMETER` (-0x6600),
    /// `BAD_PROTOCOL_VERSION` (-0x6E80) or `VERSION_MISMATCH` (-0x5F00). One tag,
    /// because none of them leaves the caller a different next move: the
    /// handshake is over and the connection must be dropped.
    ProtocolError,
    /// `MBEDTLS_ERR_SSL_INVALID_MAC` (-0x7180): a record failed
    /// authentication. Truncation-attack territory; drop the connection.
    InvalidMac,
    /// The handshake reached a state neither side could continue from:
    /// `FATAL_ALERT_MESSAGE` (-0x7780), `UNRECOGNIZED_NAME` (-0x7800),
    /// `NO_APPLICATION_PROTOCOL` (-0x7580), `NO_CLIENT_CERTIFICATE` (-0x7480),
    /// `CA_CHAIN_REQUIRED` (-0x7680), `PRIVATE_KEY_REQUIRED` (-0x7600),
    /// `BAD_CERTIFICATE` (-0x7A00), `BAD_CONFIG` (-0x5E80), `NO_RNG` (-0x7400),
    /// `HW_ACCEL_FAILED` (-0x7F80), `FEATURE_UNAVAILABLE` (-0x7080),
    /// `HANDSHAKE_FAILURE` (-0x6E00), `SESSION_TICKET_EXPIRED` (-0x6D80),
    /// `PK_TYPE_MISMATCH` (-0x6D00), `UNKNOWN_IDENTITY` (-0x6C80),
    /// `HELLO_VERIFY_REQUIRED` (-0x6A80) and
    /// `CERTIFICATE_VERIFICATION_WITHOUT_HOSTNAME` (-0x5D80). One tag: each is a
    /// refusal whose remedy is a different configuration, and this module does
    /// not pretend to tell a caller which.
    NegotiationRefused,
    /// `MBEDTLS_ERR_SSL_ALLOC_FAILED` (-0x7F00),
    /// `MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL` (-0x6A00) or
    /// `MBEDTLS_ERR_SSL_INTERNAL_ERROR` (-0x6C00): the library could not do
    /// what this build asked of it, for a reason outside the protocol.
    InternalError,
    /// A code these tags do not name.
    Unknown,
};

/// Every way a record read or write can end.
///
/// `MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY` means the peer closed cleanly and every
/// byte before it arrived, so `read` reports zero bytes rather than an error: a
/// TLS stream ends by reading zero, and a caller that has to tell "closed" from
/// "failed" is asking a byte stream a question it does not answer.
pub const IoError = error{
    WantReadOrWrite,
    Timeout,
    PeerClosed,
    ConnectionEnded,
    ProtocolError,
    InvalidMac,
    InternalError,
    Unknown,
};

/// Why a certificate or key could not be parsed.
///
/// `mbedtls_x509_crt_parse` returns `MBEDTLS_ERR_X509_*`
/// (`src/include/mbedtls/x509_crt.h:529`). The cut is at what a caller can do
/// about it: give the library more memory or a bigger buffer, point it at
/// different bytes, or stop trusting them.
pub const ParseError = error{
    /// `MBEDTLS_ERR_X509_ALLOC_FAILED` (-0x2880), and the key parser's
    /// `MBEDTLS_ERR_PK_ALLOC_FAILED` (-0x3F80).
    MemoryOrBuffer,
    /// `MBEDTLS_ERR_X509_BAD_INPUT_DATA` (-0x2800) and the ASN.1 codes
    /// underneath it. One tag: the library's own diagnostics, which `errorName`
    /// reaches, name which.
    Malformed,
    /// `MBEDTLS_ERR_X509_FILE_IO_ERROR` (-0x2900) and
    /// `MBEDTLS_ERR_PK_FILE_IO_ERROR` (-0x3E00), from the file routes only.
    FileUnavailable,
};

/// Why a chain did not verify.
pub const VerifyError = error{
    /// The chain did not reach a trusted root. `Certificate.verifyInto`'s
    /// `flags` says which check stopped it, from the `MBEDTLS_X509_BADCERT_*`
    /// bits at `src/include/mbedtls/x509.h:91-107`.
    Untrusted,
    /// `MBEDTLS_ERR_X509_CERT_VERIFY_FAILED` for a reason the flag bits do not
    /// separate.
    Failed,
};

/// Every way a socket operation can end.
///
/// The `MBEDTLS_ERR_NET_*` codes at `src/include/mbedtls/net_sockets.h:38-60`.
/// The low-level POSIX codes are folded in rather than mapped, because a caller
/// that needs `errno` can read it: the library leaves `errno` as the platform
/// set it, and inventing tags for it would be a taxonomy with no owner.
pub const NetError = error{
    /// `MBEDTLS_ERR_NET_SOCKET_FAILED` (-0x0042), `CONNECT_FAILED` (-0x0044),
    /// `BIND_FAILED` (-0x0046), `LISTEN_FAILED` (-0x0048),
    /// `ACCEPT_FAILED` (-0x004A), `RECV_FAILED` (-0x004C),
    /// `SEND_FAILED` (-0x004E), `POLL_FAILED` (-0x0047), and the negative
    /// `errno` values those wrap.
    System,
    /// `MBEDTLS_ERR_NET_CONN_RESET` (-0x0050): the peer reset the connection.
    ConnectionReset,
    /// `MBEDTLS_ERR_NET_INVALID_CONTEXT` (-0x0045): the context was already
    /// closed. This wrapper prevents that by making `deinit` idempotent, so it
    /// can only come from upstream.
    InvalidContext,
    /// `MBEDTLS_ERR_NET_UNKNOWN_HOST` (-0x0052) and
    /// `MBEDTLS_ERR_NET_BAD_INPUT_DATA` (-0x0049): the request itself was
    /// refused before any system call.
    Refused,
    /// A buffer the library wanted to write into was too small, which is
    /// `MBEDTLS_ERR_NET_BUFFER_TOO_SMALL` (-0x0043).
    BufferTooSmall,
};

/// Every way an endpoint could not be configured.
pub const ConfigError = error{
    /// `MBEDTLS_ERR_SSL_BAD_INPUT_DATA` (-0x7100) from an `mbedtls_ssl_conf_*`
    /// call that validates its argument.
    BadInputData,
    /// `MBEDTLS_ERR_SSL_ALLOC_FAILED` (-0x7F00).
    AllocFailed,
    /// `MBEDTLS_ERR_SSL_NO_RNG` (-0x7400): the configuration had no entropy
    /// source. `TlsConfig.rng` exists to prevent this.
    NoRandom,
    /// `MBEDTLS_ERR_SSL_BAD_CONFIG` (-0x5E80): the configuration itself is
    /// incomplete, which upstream detects in `mbedtls_ssl_setup`.
    BadConfig,
};

fn handshakeOk(status: c_int) HandshakeError!void {
    return switch (status) {
        0 => {},
        c.MBEDTLS_ERR_SSL_WANT_READ,
        c.MBEDTLS_ERR_SSL_WANT_WRITE,
        => error.WantReadOrWrite,
        c.MBEDTLS_ERR_SSL_TIMEOUT => error.Timeout,
        c.MBEDTLS_ERR_SSL_CLIENT_RECONNECT => error.ClientReconnect,
        c.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY => error.PeerCloseNotify,
        c.MBEDTLS_ERR_SSL_CONN_EOF => error.ConnectionEnded,
        c.MBEDTLS_ERR_X509_CERT_VERIFY_FAILED => error.CertificateVerifyFailed,
        c.MBEDTLS_ERR_SSL_INVALID_MAC => error.InvalidMac,
        c.MBEDTLS_ERR_SSL_BAD_INPUT_DATA,
        c.MBEDTLS_ERR_SSL_INVALID_RECORD,
        c.MBEDTLS_ERR_SSL_DECODE_ERROR,
        c.MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE,
        c.MBEDTLS_ERR_SSL_UNEXPECTED_RECORD,
        c.MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER,
        c.MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION,
        c.MBEDTLS_ERR_SSL_VERSION_MISMATCH,
        => error.ProtocolError,
        c.MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE,
        c.MBEDTLS_ERR_SSL_UNRECOGNIZED_NAME,
        c.MBEDTLS_ERR_SSL_NO_APPLICATION_PROTOCOL,
        c.MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE,
        c.MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED,
        c.MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED,
        c.MBEDTLS_ERR_SSL_BAD_CERTIFICATE,
        c.MBEDTLS_ERR_SSL_BAD_CONFIG,
        c.MBEDTLS_ERR_SSL_NO_RNG,
        c.MBEDTLS_ERR_SSL_HW_ACCEL_FAILED,
        c.MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE,
        c.MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE,
        c.MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED,
        c.MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH,
        c.MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY,
        c.MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED,
        c.MBEDTLS_ERR_SSL_CERTIFICATE_VERIFICATION_WITHOUT_HOSTNAME,
        => error.NegotiationRefused,
        c.MBEDTLS_ERR_SSL_ALLOC_FAILED,
        c.MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL,
        c.MBEDTLS_ERR_SSL_INTERNAL_ERROR,
        => error.InternalError,
        else => error.Unknown,
    };
}

fn ioOk(status: c_int) IoError!void {
    return switch (status) {
        0 => {},
        c.MBEDTLS_ERR_SSL_WANT_READ,
        c.MBEDTLS_ERR_SSL_WANT_WRITE,
        => error.WantReadOrWrite,
        c.MBEDTLS_ERR_SSL_TIMEOUT => error.Timeout,
        c.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY => error.PeerClosed,
        c.MBEDTLS_ERR_SSL_CONN_EOF => error.ConnectionEnded,
        c.MBEDTLS_ERR_SSL_INVALID_MAC => error.InvalidMac,
        c.MBEDTLS_ERR_SSL_BAD_INPUT_DATA,
        c.MBEDTLS_ERR_SSL_INVALID_RECORD,
        c.MBEDTLS_ERR_SSL_DECODE_ERROR,
        c.MBEDTLS_ERR_SSL_UNEXPECTED_RECORD,
        c.MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER,
        c.MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION,
        => error.ProtocolError,
        c.MBEDTLS_ERR_SSL_ALLOC_FAILED,
        c.MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL,
        c.MBEDTLS_ERR_SSL_INTERNAL_ERROR,
        => error.InternalError,
        else => error.Unknown,
    };
}

fn parseOk(status: c_int) ParseError!void {
    return switch (status) {
        0 => {},
        c.MBEDTLS_ERR_X509_ALLOC_FAILED, c.MBEDTLS_ERR_PK_ALLOC_FAILED => error.MemoryOrBuffer,
        c.MBEDTLS_ERR_X509_FILE_IO_ERROR, c.MBEDTLS_ERR_PK_FILE_IO_ERROR => error.FileUnavailable,
        else => error.Malformed,
    };
}

fn netOk(status: c_int) NetError!void {
    return switch (status) {
        0 => {},
        c.MBEDTLS_ERR_NET_CONN_RESET => error.ConnectionReset,
        c.MBEDTLS_ERR_NET_INVALID_CONTEXT => error.InvalidContext,
        c.MBEDTLS_ERR_NET_UNKNOWN_HOST, c.MBEDTLS_ERR_NET_BAD_INPUT_DATA => error.Refused,
        c.MBEDTLS_ERR_NET_BUFFER_TOO_SMALL => error.BufferTooSmall,
        else => error.System,
    };
}

fn confOk(status: c_int) ConfigError!void {
    return switch (status) {
        0 => {},
        c.MBEDTLS_ERR_SSL_BAD_INPUT_DATA => error.BadInputData,
        c.MBEDTLS_ERR_SSL_ALLOC_FAILED => error.AllocFailed,
        c.MBEDTLS_ERR_SSL_NO_RNG => error.NoRandom,
        else => error.BadConfig,
    };
}

// ---------------------------------------------------------------------------
// Hashing and MACs
// ---------------------------------------------------------------------------

/// The SHA-2 family in the shapes NIST FIPS 180-4 defines, plus SHA-1.
///
/// The names are the standards' own. Each is a one-shot call into upstream's
/// `mbedtls_sha1`, `mbedtls_sha256` and `mbedtls_sha512` with the width
/// selector at 0 for SHA-1 and SHA-256 and 1 for the 384-bit truncation of
/// SHA-512, which is how `src/include/mbedtls/sha512.h` spells SHA-384.
pub const Hash = enum {
    sha1,
    sha256,
    sha384,
    sha512,

    /// The digest length in bytes: 20, 32, 48 and 64.
    pub fn len(self: Hash) usize {
        return switch (self) {
            .sha1 => 20,
            .sha256 => 32,
            .sha384 => 48,
            .sha512 => 64,
        };
    }

    /// The `mbedtls_md_type_t` tag for this digest, so a caller moving between
    /// this module and the rest of Mbed TLS 3.6 has one spelling.
    pub fn mdType(self: Hash) c.mbedtls_md_type_t {
        return switch (self) {
            .sha1 => c.MBEDTLS_MD_SHA1,
            .sha256 => c.MBEDTLS_MD_SHA256,
            .sha384 => c.MBEDTLS_MD_SHA384,
            .sha512 => c.MBEDTLS_MD_SHA512,
        };
    }
};

/// Hash `input` with `algorithm` and write the digest into `out`.
///
/// `out.len` must be exactly the algorithm's digest length; any other length is
/// `error.OutputLengthWrong` rather than a short write, because a caller that
/// asked for the wrong length has a bug that a truncated digest would hide.
///
/// Upstream's one-shot entry points are used
/// (`src/include/mbedtls/sha256.h:167`, `src/include/mbedtls/sha512.h`) because
/// the only promise here is one complete digest of one complete buffer. A caller
/// with a stream needs the incremental `starts`/`update`/`finish` trio and
/// should reach it through `c`.
pub fn hash(algorithm: Hash, input: []const u8, out: []u8) error{
    OutputLengthWrong,
    Failed,
}!void {
    if (out.len != algorithm.len()) return error.OutputLengthWrong;
    const status: c_int = switch (algorithm) {
        .sha1 => c.mbedtls_sha1(input.ptr, input.len, out.ptr),
        .sha256 => c.mbedtls_sha256(input.ptr, input.len, out.ptr, 0),
        .sha384 => c.mbedtls_sha512(input.ptr, input.len, out.ptr, 1),
        .sha512 => c.mbedtls_sha512(input.ptr, input.len, out.ptr, 0),
    };
    // Each of the four functions has its own low-level "bad input" code
    // (`MBEDTLS_ERR_SHA1_BAD_INPUT_DATA` -0x0073, `SHA256` -0x0074, `SHA512`
    // -0x0075) and a high-level "feature unavailable" code when its module is
    // not compiled in. This signature cannot produce either - both lengths are
    // already checked - so one tag for all of them is the honest answer, and
    // `errorName` gives the exact code when a caller needs it.
    if (status == 0) return;
    return error.Failed;
}

/// HMAC over `key` and `message`, into `out`.
///
/// `mbedtls_md_hmac` (`src/include/mbedtls/md.h:518`) takes an
/// `mbedtls_md_info_t *`, which comes from `mbedtls_md_info_from_type`
/// (`src/include/mbedtls/md.h:149`). That function returns null when the digest
/// was not compiled in, so a null here is `error.DigestUnavailable` rather than
/// a null dereference: "this build has no SHA-256" is a fact a caller can act
/// on, and the library states it in exactly this way.
pub fn hmac(
    algorithm: Hash,
    key: []const u8,
    message: []const u8,
    out: []u8,
) error{ OutputLengthWrong, DigestUnavailable, Failed }!void {
    if (out.len != algorithm.len()) return error.OutputLengthWrong;
    const info = c.mbedtls_md_info_from_type(algorithm.mdType()) orelse
        return error.DigestUnavailable;
    const status = c.mbedtls_md_hmac(info, key.ptr, key.len, message.ptr, message.len, out.ptr);
    if (status == 0) return;
    return error.Failed;
}

// ---------------------------------------------------------------------------
// Block and AEAD ciphers
// ---------------------------------------------------------------------------

/// AES-128 in CBC mode.
///
/// `mbedtls_aes_setkey_enc`/`mbedtls_aes_setkey_dec` with 128 key bits
/// (`src/include/mbedtls/aes.h:155,175`) and `mbedtls_aes_crypt_cbc`
/// (`src/include/mbedtls/aes.h:295`). CBC threads the initialisation vector
/// through each call - upstream takes it as an in/out `unsigned char iv[16]` -
/// so `iv` is mutated in place and the caller keeps ownership of it.
///
/// `input.len` must be a nonzero multiple of 16: CBC has no partial-block mode
/// and upstream answers `MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH` (-0x0022) for
/// anything else. This checks it first rather than handing over a length it
/// knows is rejected.
pub const Aes128Cbc = struct {
    context: c.mbedtls_aes_context,
    initialized: bool = false,

    /// Set an encryption key.
    pub fn initEncrypt(key: []const u8) (error{BadKeyLength, Failed}!Aes128Cbc) {
        var self: Aes128Cbc = .{ .context = undefined };
        c.mbedtls_aes_init(&self.context);
        self.initialized = true;
        if (key.len != 16) {
            self.deinit();
            return error.BadKeyLength;
        }
        const status = c.mbedtls_aes_setkey_enc(&self.context, key.ptr, 128);
        if (status != 0) {
            self.deinit();
            return error.Failed;
        }
        return self;
    }

    /// Set a decryption key.
    pub fn initDecrypt(key: []const u8) (error{BadKeyLength, Failed}!Aes128Cbc) {
        var self: Aes128Cbc = .{ .context = undefined };
        c.mbedtls_aes_init(&self.context);
        self.initialized = true;
        if (key.len != 16) {
            self.deinit();
            return error.BadKeyLength;
        }
        const status = c.mbedtls_aes_setkey_dec(&self.context, key.ptr, 128);
        if (status != 0) {
            self.deinit();
            return error.Failed;
        }
        return self;
    }

    /// Encrypt or decrypt `input.len` bytes.
    ///
    /// `output` must be at least `input.len` bytes. Upstream allows `output` to
    /// be the same buffer as `input` (`src/include/mbedtls/aes.h:295-310`), so
    /// in-place operation is permitted here too; anything else needs the length
    /// this checks.
    pub fn crypt(
        self: *Aes128Cbc,
        encrypt: bool,
        iv: *[16]u8,
        input: []const u8,
        output: []u8,
    ) error{ InvalidLength, OutputTooSmall, Failed }!void {
        if (input.len == 0 or input.len % 16 != 0) return error.InvalidLength;
        if (output.len < input.len) return error.OutputTooSmall;
        // `MBEDTLS_AES_ENCRYPT` is 1 and `MBEDTLS_AES_DECRYPT` is 0
        // (`src/include/mbedtls/aes.h:52-53`), which is the opposite of the C
        // boolean this signature takes, so the constant is passed through rather
        // than the boolean.
        const mode: c_int = if (encrypt) c.MBEDTLS_AES_ENCRYPT else c.MBEDTLS_AES_DECRYPT;
        const status = c.mbedtls_aes_crypt_cbc(&self.context, mode, input.len, iv, input.ptr, output.ptr);
        if (status == 0) return;
        return error.Failed;
    }

    /// Release the context. Safe to call twice; the second call is a no-op.
    pub fn deinit(self: *Aes128Cbc) void {
        if (!self.initialized) return;
        self.initialized = false;
        c.mbedtls_aes_free(&self.context);
    }
};

/// AES-128-GCM with a 128-bit tag.
///
/// `mbedtls_gcm_setkey` with `MBEDTLS_CIPHER_ID_AES` and 128 key bits
/// (`src/include/mbedtls/gcm.h:110-112`), then `mbedtls_gcm_crypt_and_tag`
/// (`src/include/mbedtls/gcm.h:165`) and `mbedtls_gcm_auth_decrypt`
/// (`src/include/mbedtls/gcm.h:212`). NIST SP 800-38D defines the mode and the
/// specification's own test cases are what `tests.zig` checks against, so this
/// wrapper is measured by a published vector rather than by a round trip.
///
/// The context holds no heap allocation, but upstream still gives it a `free`,
/// and giving it a `deinit` means a caller releasing one cannot forget.
pub const Aes128Gcm = struct {
    context: c.mbedtls_gcm_context,
    initialized: bool = false,

    pub fn init(key: []const u8) (error{BadKeyLength, Failed}!Aes128Gcm) {
        var self: Aes128Gcm = .{ .context = undefined };
        c.mbedtls_gcm_init(&self.context);
        self.initialized = true;
        if (key.len != 16) {
            self.deinit();
            return error.BadKeyLength;
        }
        const status = c.mbedtls_gcm_setkey(&self.context, c.MBEDTLS_CIPHER_ID_AES, key.ptr, 128);
        if (status != 0) {
            self.deinit();
            return error.Failed;
        }
        return self;
    }

    /// Encrypt `plaintext`, writing `ciphertext` and a 16-byte `tag`.
    ///
    /// `iv` must be 12 bytes: SP 800-38D names 96 bits as the preferred nonce
    /// length and every test case in the specification uses it. Another length is
    /// refused here rather than passed on, because GCM's security argument for a
    /// non-96-bit nonce is not one this wrapper can make on the caller's behalf.
    pub fn seal(
        self: *Aes128Gcm,
        iv: []const u8,
        additional: []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: *[16]u8,
    ) error{ OutputTooSmall, InvalidIvLength, Failed }!void {
        if (iv.len != 12) return error.InvalidIvLength;
        if (ciphertext.len < plaintext.len) return error.OutputTooSmall;
        const status = c.mbedtls_gcm_crypt_and_tag(
            &self.context,
            c.MBEDTLS_GCM_ENCRYPT,
            plaintext.len,
            iv.ptr,
            iv.len,
            if (additional.len == 0) null else additional.ptr,
            additional.len,
            if (plaintext.len == 0) null else plaintext.ptr,
            if (plaintext.len == 0) null else ciphertext.ptr,
            tag.len,
            tag,
        );
        if (status == 0) return;
        // `MBEDTLS_ERR_GCM_BUFFER_TOO_SMALL` (-0x0016) is the one low-level GCM
        // code with a remedy this module can see, and the length was already
        // checked above, so it cannot be that.
        return error.Failed;
    }

    /// Decrypt and authenticate, reporting whether the tag matched.
    ///
    /// On `error.AuthenticationFailed` the plaintext buffer holds whatever the
    /// operation wrote before the check: GCM authenticates last, so there is
    /// nothing trustworthy there. **A caller must not read `plaintext` after
    /// this returns that error.** That is upstream's behaviour, and
    /// `src/include/mbedtls/gcm.h:207` says so.
    pub fn open(
        self: *Aes128Gcm,
        iv: []const u8,
        additional: []const u8,
        ciphertext: []const u8,
        tag: []const u8,
        plaintext: []u8,
    ) error{ OutputTooSmall, InvalidIvLength, AuthenticationFailed, Failed }!void {
        if (iv.len != 12) return error.InvalidIvLength;
        if (plaintext.len < ciphertext.len) return error.OutputTooSmall;
        const status = c.mbedtls_gcm_auth_decrypt(
            &self.context,
            ciphertext.len,
            iv.ptr,
            iv.len,
            if (additional.len == 0) null else additional.ptr,
            additional.len,
            tag.ptr,
            tag.len,
            if (ciphertext.len == 0) null else ciphertext.ptr,
            if (ciphertext.len == 0) null else plaintext.ptr,
        );
        return switch (status) {
            0 => {},
            c.MBEDTLS_ERR_GCM_AUTH_FAILED => error.AuthenticationFailed,
            else => error.Failed,
        };
    }

    pub fn deinit(self: *Aes128Gcm) void {
        if (!self.initialized) return;
        self.initialized = false;
        c.mbedtls_gcm_free(&self.context);
    }
};

/// ChaCha20-Poly1305 AEAD, as RFC 8439 defines it.
///
/// `mbedtls_chachapoly_setkey` takes the 32-byte key
/// (`src/include/mbedtls/chachapoly.h:126`),
/// `mbedtls_chachapoly_encrypt_and_tag` the 12-byte nonce
/// (`src/include/mbedtls/chachapoly.h:291`) and
/// `mbedtls_chachapoly_auth_decrypt` the 12-byte nonce with the tag
/// (`src/include/mbedtls/chachapoly.h:328`). Both lengths are fixed by the RFC's
/// constructions, so this wrapper refuses anything else rather than passing it
/// on: another nonce length is not a parameter, it is a different construction.
pub const ChaCha20Poly1305 = struct {
    context: c.mbedtls_chachapoly_context,
    initialized: bool = false,

    pub fn init(key: []const u8) (error{BadKeyLength, Failed}!ChaCha20Poly1305) {
        var self: ChaCha20Poly1305 = .{ .context = undefined };
        c.mbedtls_chachapoly_init(&self.context);
        self.initialized = true;
        if (key.len != 32) {
            self.deinit();
            return error.BadKeyLength;
        }
        const status = c.mbedtls_chachapoly_setkey(&self.context, key.ptr);
        if (status != 0) {
            self.deinit();
            return error.Failed;
        }
        return self;
    }

    pub fn seal(
        self: *ChaCha20Poly1305,
        nonce: []const u8,
        additional: []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: *[16]u8,
    ) error{ OutputTooSmall, InvalidNonceLength, Failed }!void {
        if (nonce.len != 12) return error.InvalidNonceLength;
        if (ciphertext.len < plaintext.len) return error.OutputTooSmall;
        const status = c.mbedtls_chachapoly_encrypt_and_tag(
            &self.context,
            plaintext.len,
            nonce.ptr,
            if (additional.len == 0) null else additional.ptr,
            additional.len,
            if (plaintext.len == 0) null else plaintext.ptr,
            if (plaintext.len == 0) null else ciphertext.ptr,
            tag,
        );
        if (status == 0) return;
        return error.Failed;
    }

    /// Decrypt and authenticate.
    ///
    /// On `error.AuthenticationFailed` the plaintext buffer holds whatever was
    /// written before the tag check and must not be read; RFC 8439 §2.8.2
    /// authenticates last, and `src/include/mbedtls/chachapoly.h:321` documents
    /// `MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED` (-0x0056) as the answer when the tag
    /// does not match.
    pub fn open(
        self: *ChaCha20Poly1305,
        nonce: []const u8,
        additional: []const u8,
        ciphertext: []const u8,
        tag: []const u8,
        plaintext: []u8,
    ) error{ OutputTooSmall, InvalidNonceLength, AuthenticationFailed, Failed }!void {
        if (nonce.len != 12) return error.InvalidNonceLength;
        if (plaintext.len < ciphertext.len) return error.OutputTooSmall;
        const status = c.mbedtls_chachapoly_auth_decrypt(
            &self.context,
            ciphertext.len,
            nonce.ptr,
            if (additional.len == 0) null else additional.ptr,
            additional.len,
            tag.ptr,
            if (ciphertext.len == 0) null else ciphertext.ptr,
            if (ciphertext.len == 0) null else plaintext.ptr,
        );
        return switch (status) {
            0 => {},
            c.MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED => error.AuthenticationFailed,
            else => error.Failed,
        };
    }

    pub fn deinit(self: *ChaCha20Poly1305) void {
        if (!self.initialized) return;
        self.initialized = false;
        c.mbedtls_chachapoly_free(&self.context);
    }
};

// ---------------------------------------------------------------------------
// Entropy
// ---------------------------------------------------------------------------

/// An entropy source, and the only place this facade lets randomness in.
///
/// `mbedtls_entropy_context` (`src/include/mbedtls/entropy.h:59-89`) holds up to
/// `MBEDTLS_ENTROPY_MAX_SOURCES` sources - 20 in this configuration, line 58 -
/// and a `MBEDTLS_ENTROPY_BLOCK_SIZE` accumulator, so its layout is a function of
/// the configuration: a provider built with different values has a *different
/// struct under the same name*. `runtime/library.zig` says the same about the
/// runtime route, because that is the boundary that matters there.
///
/// `gather` is `mbedtls_entropy_gather` (`src/include/mbedtls/entropy.h:173`).
/// With no hardware source registered - and this configuration registers none,
/// because `MBEDTLS_ENTROPY_HARDWARE_ALT` is not defined - the built-in sources
/// are the platform ones, and where upstream found none, `gather` cannot produce
/// a strong answer unless a caller has called `updateManual`. That is upstream's
/// rule; this wrapper does not hide it by adding a source of its own, because
/// choosing an entropy source is the caller's decision and not a default.
pub const Entropy = struct {
    context: c.mbedtls_entropy_context,
    initialized: bool = false,

    /// Create an entropy context with whatever sources the configuration's
    /// defaults install. There is no failure mode: `mbedtls_entropy_init`
    /// (`src/include/mbedtls/entropy.h:135`) is `void`.
    pub fn init() Entropy {
        var self: Entropy = .{ .context = undefined };
        c.mbedtls_entropy_init(&self.context);
        self.initialized = true;
        return self;
    }

    /// Mix `seed` into the context, as `mbedtls_entropy_update_manual`
    /// (`src/include/mbedtls/entropy.h:198`) does.
    ///
    /// There is no length limit to enforce here: `src/library/entropy.c:133-137`
    /// *hashes* input longer than `MBEDTLS_ENTROPY_BLOCK_SIZE` rather than
    /// rejecting it, so a caller may pass anything and gets a distinct result for
    /// each length. That is upstream's behaviour and this wrapper passes it
    /// through rather than imposing a limit the C does not have.
    pub fn updateManual(self: *Entropy, seed: []const u8) error{SourceFailed}!void {
        const status = c.mbedtls_entropy_update_manual(&self.context, seed.ptr, seed.len);
        if (status == 0) return;
        return error.SourceFailed;
    }

    /// Collect entropy from the registered sources now.
    pub fn gather(self: *Entropy) error{SourceFailed}!void {
        const status = c.mbedtls_entropy_gather(&self.context);
        if (status == 0) return;
        return error.SourceFailed;
    }

    /// Fill `out` with `out.len` bytes of entropy, as `mbedtls_entropy_func`
    /// (`src/include/mbedtls/entropy.h:186`) does.
    ///
    /// This is the signature `mbedtls_ssl_conf_rng` wants
    /// (`src/include/mbedtls/ssl.h:2266`), so a caller configuring the TLS stack
    /// hands `&entropy` to `TlsConfig.rng` and the library does the rest.
    pub fn fill(self: *Entropy, out: []u8) error{SourceFailed}!void {
        if (out.len == 0) return;
        const status = c.mbedtls_entropy_func(&self.context, out.ptr, out.len);
        if (status == 0) return;
        return error.SourceFailed;
    }

    pub fn deinit(self: *Entropy) void {
        if (!self.initialized) return;
        self.initialized = false;
        c.mbedtls_entropy_free(&self.context);
    }
};

/// A seeded random generator: what the TLS stack wants as its `f_rng`.
///
/// `Entropy` is not one, and pointing `mbedtls_ssl_conf_rng` at it is a defect
/// that only shows up on the first private-key operation. `mbedtls_entropy_func`
/// refuses any single request larger than `MBEDTLS_ENTROPY_BLOCK_SIZE`
/// (`src/library/entropy.c:277-279`), which this build sets to 64 because its
/// accumulator is SHA-512 (`src/include/mbedtls/entropy.h:20-25`), while RSA
/// blinding draws a modulus-sized value - 128 bytes for one 2048-bit prime
/// (`src/library/rsa.c:1361`, through `mbedtls_mpi_fill_random`). The result
/// is `MBEDTLS_ERR_ENTROPY_SOURCE_FAILED` inside `mbedtls_rsa_private`, which
/// the handshake reports as a peer that went away.
///
/// Upstream's own `programs/ssl/ssl_server2.c` passes
/// `mbedtls_ctr_drbg_random`, and this is that, seeded from an `Entropy`.
pub const Drbg = struct {
    context: c.mbedtls_ctr_drbg_context,
    initialized: bool = false,

    /// Create a generator. It cannot produce anything until `seed` has run, and
    /// `mbedtls_ctr_drbg_init` (`src/include/mbedtls/ctr_drbg.h:245`) is
    /// `void`, so there is no failure to report here.
    pub fn init() Drbg {
        var self: Drbg = .{ .context = undefined };
        c.mbedtls_ctr_drbg_init(&self.context);
        self.initialized = true;
        return self;
    }

    /// Seed from `entropy`.
    ///
    /// `mbedtls_ctr_drbg_seed` (`src/include/mbedtls/ctr_drbg.h:346`) takes the
    /// entropy callback and its context rather than a context alone, and reads
    /// `MBEDTLS_CTR_DRBG_ENTROPY_LEN` bytes from it - 48 here
    /// (`src/include/mbedtls/ctr_drbg.h:107-124`), comfortably inside the
    /// accumulator's one-block limit. `custom` is null with length zero, which
    /// upstream reads as "no additional personalisation string"; this package
    /// has no per-deployment string to add, and a caller that has one should
    /// reach `c.mbedtls_ctr_drbg_seed` rather than have this signature pretend
    /// otherwise.
    pub fn seed(self: *Drbg, entropy: *Entropy) error{SeedFailed}!void {
        const status = c.mbedtls_ctr_drbg_seed(
            &self.context,
            c.mbedtls_entropy_func,
            &entropy.context,
            null,
            0,
        );
        if (status == 0) return;
        return error.SeedFailed;
    }

    /// Write `out.len` random bytes.
    ///
    /// One call may ask for at most `MBEDTLS_CTR_DRBG_MAX_REQUEST` bytes,
    /// 1024 here (`src/include/mbedtls/ctr_drbg.h:136-137`). That is a real
    /// limit rather than a nominal one: upstream's generator refuses a larger
    /// single request, and unlike `Entropy.fill` there is no shape of argument
    /// that makes it succeed, so this reports the refusal instead of looping.
    pub fn fill(self: *Drbg, out: []u8) error{RequestTooLarge, Failed}!void {
        if (out.len == 0) return;
        if (out.len > c.MBEDTLS_CTR_DRBG_MAX_REQUEST) return error.RequestTooLarge;
        const status = c.mbedtls_ctr_drbg_random(&self.context, out.ptr, out.len);
        if (status == 0) return;
        return error.Failed;
    }

    pub fn deinit(self: *Drbg) void {
        if (!self.initialized) return;
        self.initialized = false;
        c.mbedtls_ctr_drbg_free(&self.context);
    }
};

// ---------------------------------------------------------------------------
// Certificates and keys
// ---------------------------------------------------------------------------

fn dnGets(buf: []u8, dn: *const c.mbedtls_x509_name) error{BufferTooSmall}![]const u8 {
    if (buf.len == 0) return error.BufferTooSmall;
    const status = c.mbedtls_x509_dn_gets(buf.ptr, buf.len, dn);
    if (status < 0) return error.BufferTooSmall;
    const len: usize = @intCast(status);
    if (len > buf.len) return error.BufferTooSmall;
    return buf[0..len];
}

/// The X.509 verification policy: which signature hashes, public-key
/// algorithms, curves and RSA sizes a chain may use.
///
/// `mbedtls_x509_crt_profile` (`src/include/mbedtls/x509_crt.h:125-131`) is
/// four bitfields and nothing else, and upstream ships two instances of it as
/// `const` globals. A wrapper that exposed the raw struct would let a caller
/// hand `verify` an all-zero profile and silently switch off every check,
/// which is a mistake upstream's own documentation steers away from by telling
/// callers to start from a copy of a named profile and tune it
/// (`src/include/mbedtls/x509_crt.h:109-123`). This type does that: it is
/// always one of upstream's profiles, adjusted through a named operation.
///
/// The library's default is `default()`, and that is the policy
/// `mbedtls_x509_crt_verify` and an unconfigured `TlsConfig` apply.
pub const CertificateProfile = struct {
    inner: c.mbedtls_x509_crt_profile,

    /// Upstream's `mbedtls_x509_crt_profile_default`
    /// (`src/include/mbedtls/x509_crt.h:324`).
    ///
    /// The first field of that profile is the one that decides most chains:
    /// `src/library/x509_crt.c:89-97` builds it from SHA-256 and above, so a
    /// SHA-1-signed certificate is refused with
    /// `MBEDTLS_X509_BADCERT_BAD_MD` no matter who signed it. That is upstream's
    /// security policy and this module does not second-guess it; a peer that
    /// still signs with SHA-1 needs `allowingMd(.sha1)` and the caller's own
    /// judgement about whether to accept it.
    pub fn default() CertificateProfile {
        return .{ .inner = c.mbedtls_x509_crt_profile_default };
    }

    /// Accept one more signature hash on top of this profile.
    ///
    /// The operation upstream's documentation spells by hand
    /// (`src/include/mbedtls/x509_crt.h:113-116`): the `MBEDTLS_X509_ID_FLAG`
    /// macro at `src/include/mbedtls/x509_crt.h:98` is `1 << (id - 1)`, it is a
    /// macro and so does not survive translation, and upstream's own comment
    /// says the flag for zero (`MBEDTLS_MD_NONE`) is meaningless because the
    /// shift would be negative.
    pub fn allowingMd(self: CertificateProfile, md: Hash) CertificateProfile {
        const id: u32 = @intCast(md.mdType());
        var out = self;
        out.inner.allowed_mds |= @as(u32, 1) << @intCast(id - 1);
        return out;
    }
};

/// One X.509 certificate, or a chain of them.
///
/// `mbedtls_x509_crt_parse` (`src/include/mbedtls/x509_crt.h:529`) accepts PEM
/// and DER in one call and *copies* the bytes it needs into its own storage, so
/// the caller's buffer is free the moment `parse` returns and the field
/// `own_buffer` says so. Parsing a second certificate into the same `Certificate`
/// appends to the chain rather than replacing it, which is upstream's
/// linked-list design (`src/include/mbedtls/x509_crt.h:314-315`) and is why
/// `next` exists.
pub const Certificate = struct {
    crt: c.mbedtls_x509_crt,
    initialized: bool = false,

    pub fn init() Certificate {
        var self: Certificate = .{ .crt = undefined };
        c.mbedtls_x509_crt_init(&self.crt);
        self.initialized = true;
        return self;
    }

    /// Parse a PEM or DER certificate, appending to any chain already here.
    ///
    /// `bytes` is sentinel-typed because upstream requires it: the documented
    /// contract is that `buflen` includes the terminating NUL for PEM input
    /// (`src/include/mbedtls/x509_crt.h:520-521`), and the format decision is
    /// literally `buf[buflen - 1] == '\0'`
    /// (`src/library/x509_crt.c:1420-1423`). A buffer that omits the terminator
    /// is read as DER, and PEM text is not DER, so the answer is
    /// `error.Malformed` rather than a parse. Carrying the terminator in the
    /// slice type puts that requirement where the caller cannot miss it -
    /// `@embedFile` already yields a sentinel slice - and the one byte is added
    /// back here rather than left to every caller to remember.
    ///
    /// On failure the chain is left in whatever state upstream left it: the
    /// library documents no rollback, so a caller that needs a clean chain after a
    /// failed parse must `init` a fresh one. This wrapper does not clear the chain
    /// on failure, because doing so would free memory upstream may still point
    /// at.
    pub fn parse(self: *Certificate, bytes: [:0]const u8) ParseError!void {
        return parseOk(c.mbedtls_x509_crt_parse(&self.crt, bytes.ptr, bytes.len + 1));
    }

    /// The next certificate in the chain this parse produced, or null at the end.
    ///
    /// Upstream's `next` field is a `struct mbedtls_x509_crt *` with the null
    /// pointer at the end of the list (`src/include/mbedtls/x509_crt.h:314`). The
    /// returned `Certificate` *borrows* the storage of this one: it has no
    /// `deinit` of its own and must not be given one, because
    /// `mbedtls_x509_crt_free` frees the whole list from any member.
    pub fn next(self: *Certificate) ?*Certificate {
        const raw = self.crt.next orelse return null;
        return @ptrCast(raw);
    }

    /// The certificate's DER encoding, borrowed from the parsed storage.
    ///
    /// `raw` is `mbedtls_x509_buf`, an `int tag` plus `unsigned char *p` and
    /// `size_t len` (`src/include/mbedtls/x509.h:216`), and the pointer points
    /// into memory this `Certificate` owns. It stays valid until `deinit`.
    pub fn der(self: *const Certificate) []const u8 {
        const raw = self.crt.raw;
        if (raw.p == null or raw.len == 0) return &.{};
        return raw.p[0..raw.len];
    }

    /// The subject, as `mbedtls_x509_dn_gets` writes it.
    ///
    /// That function (`src/include/mbedtls/x509.h:323`) formats into the
    /// caller's buffer and returns the length it needs, so a short buffer is
    /// `error.BufferTooSmall` rather than a truncated name: a truncated
    /// distinguished name is a *different* name, and comparing one against
    /// another is how a hostname check is defeated.
    pub fn subject(self: *const Certificate, buf: []u8) error{BufferTooSmall}![]const u8 {
        return dnGets(buf, &self.crt.subject);
    }

    /// The issuer, formatted the same way as `subject`.
    pub fn issuer(self: *const Certificate, buf: []u8) error{BufferTooSmall}![]const u8 {
        return dnGets(buf, &self.crt.issuer);
    }

    /// The serial number, as `mbedtls_x509_serial_gets`
    /// (`src/include/mbedtls/x509.h:374`) writes it.
    ///
    /// The format is upstream's own and is not what every other tool prints:
    /// `src/library/x509.c:958-965` writes each byte as `%02X` with a colon
    /// between and none after, skipping a leading zero byte when there is more
    /// than one, and appending `....` when the serial is longer than 32 bytes.
    /// So the answer is *upper-case* colon-separated hexadecimal, and a caller
    /// comparing it with a lowercase form is comparing two spellings rather than
    /// two certificates.
    pub fn serial(self: *const Certificate, buf: []u8) error{BufferTooSmall}![]const u8 {
        if (buf.len == 0) return error.BufferTooSmall;
        const ser = self.crt.serial;
        const status = c.mbedtls_x509_serial_gets(buf.ptr, buf.len, &ser);
        if (status < 0) return error.BufferTooSmall;
        const len: usize = @intCast(status);
        if (len > buf.len) return error.BufferTooSmall;
        return buf[0..len];
    }

    /// The start of the validity window, as upstream parsed it.
    ///
    /// `mbedtls_x509_time` (`src/include/mbedtls/x509.h`) is six `int`s: `year`,
    /// `mon`, `day`, `hour`, `min`, `sec`. These are the certificate's own
    /// numbers, not a Unix timestamp, and `mon` is 1-based as ASN.1 writes it;
    /// the comparison upstream does is `mbedtls_x509_time_cmp`
    /// (`src/include/mbedtls/x509.h:386`).
    pub fn validFrom(self: *const Certificate) c.mbedtls_x509_time {
        return self.crt.valid_from;
    }

    /// The end of the validity window.
    pub fn validTo(self: *const Certificate) c.mbedtls_x509_time {
        return self.crt.valid_to;
    }

    /// Whether the Basic Constraints extension says this is a CA.
    ///
    /// `mbedtls_x509_crt_get_ca_istrue` (`src/include/mbedtls/x509_crt.h:929`) is
    /// the public accessor; the same fact is in the private `ca_istrue` field,
    /// and this wrapper uses the function rather than the field so it is not tied
    /// to upstream's private naming, which `src/include/mbedtls/private_access.h:15`
    /// turns into `private_ca_istrue`.
    pub fn isCa(self: *const Certificate) bool {
        return c.mbedtls_x509_crt_get_ca_istrue(&self.crt) == 1;
    }

    /// The X.509 version: 1, 2 or 3.
    pub fn version(self: *const Certificate) c_int {
        return self.crt.version;
    }

    /// The RSA modulus size in bits, or null when the key is not RSA.
    ///
    /// The type test is `mbedtls_pk_get_type` on the parsed key and the size comes
    /// from `mbedtls_pk_get_bitlen` (`src/include/mbedtls/pk.h`). Both are asked
    /// of the library rather than read out of the structure, because the key
    /// inside a certificate is a `mbedtls_pk_context` whose internals are not
    /// this package's to know.
    pub fn rsaBitLength(self: *const Certificate) ?u32 {
        if (c.mbedtls_pk_get_type(&self.crt.pk) != c.MBEDTLS_PK_RSA) return null;
        return @intCast(c.mbedtls_pk_get_bitlen(&self.crt.pk));
    }

    /// Verify this certificate against `trust`, writing the reason into `flags`.
    ///
    /// `mbedtls_x509_crt_verify` (`src/include/mbedtls/x509_crt.h:670`) takes a
    /// CRL chain, a common name, the flags pointer, and a verification callback
    /// with its context. This wrapper passes a null CRL, a null common name - so
    /// no CN comparison happens here, because the hostname check belongs to the
    /// TLS layer, which knows the name it asked for - and a null callback.
    ///
    /// The policy is upstream's default one. `mbedtls_x509_crt_verify` passes
    /// `&mbedtls_x509_crt_profile_default` itself
    /// (`src/library/x509_crt.c:3166-3170`), and that profile refuses SHA-1
    /// signatures (`src/library/x509_crt.c:89-97`), so a SHA-1-signed chain
    /// answers `error.Untrusted` with `MBEDTLS_X509_BADCERT_BAD_MD` in `flags`.
    /// A caller that has decided such a peer is acceptable names that decision
    /// with `verifyIntoWithProfile`.
    ///
    /// `flags` receives the `MBEDTLS_X509_BADCERT_*` bits
    /// (`src/include/mbedtls/x509.h:91-107`) and is the only way a caller learns
    /// *why*. The error returned here is deliberately coarse: each of those bits
    /// is a different decision about trust, and a wrapper mapping fourteen bits to
    /// fourteen error tags would be asserting that this module knows which remedy
    /// each one needs.
    pub fn verifyInto(self: *Certificate, trust: *Certificate, flags: *u32) VerifyError!void {
        const status = c.mbedtls_x509_crt_verify(&self.crt, &trust.crt, null, null, flags, null, null);
        return switch (status) {
            0 => {},
            c.MBEDTLS_ERR_X509_CERT_VERIFY_FAILED => error.Untrusted,
            else => error.Failed,
        };
    }

    /// Verify this certificate against `trust` under a profile the caller chose.
    ///
    /// `mbedtls_x509_crt_verify_with_profile`
    /// (`src/include/mbedtls/x509_crt.h:711`) is upstream's own answer to "the
    /// default policy rejects a chain I still want to check", and it differs from
    /// `verifyInto` in exactly one argument. The CRL, common name and callback
    /// are the same nulls `verifyInto` passes.
    pub fn verifyIntoWithProfile(
        self: *Certificate,
        trust: *Certificate,
        profile: *const CertificateProfile,
        flags: *u32,
    ) VerifyError!void {
        const status = c.mbedtls_x509_crt_verify_with_profile(
            &self.crt,
            &trust.crt,
            null,
            &profile.inner,
            null,
            flags,
            null,
            null,
        );
        return switch (status) {
            0 => {},
            c.MBEDTLS_ERR_X509_CERT_VERIFY_FAILED => error.Untrusted,
            else => error.Failed,
        };
    }

    /// Release the chain. Safe to call twice; the second call is a no-op.
    pub fn deinit(self: *Certificate) void {
        if (!self.initialized) return;
        self.initialized = false;
        c.mbedtls_x509_crt_free(&self.crt);
    }

    /// Whether this build's configuration parsed certificates at all.
    pub fn parsingAvailable() bool {
        return hasFeature("MBEDTLS_X509_CRT_PARSE_C") orelse false;
    }
};

/// A private key in PEM or DER form.
///
/// `mbedtls_pk_parse_key` (`src/include/mbedtls/pk.h:1116`) needs an entropy
/// source when the key is encrypted, and takes a callback plus its context rather
/// than a context alone; `entropy` is passed in and `mbedtls_entropy_func` is
/// the callback, which is what upstream's own `programs/ssl/ssl_server2.c` does.
///
/// The TLS stack needs this rather than a certificate: a certificate carries only
/// a public key, and `mbedtls_ssl_conf_own_cert`
/// (`src/include/mbedtls/ssl.h:3733`) takes the certificate and a
/// `mbedtls_pk_context` holding the private key separately.
pub const PrivateKey = struct {
    pk: c.mbedtls_pk_context,
    initialized: bool = false,

    pub fn init() PrivateKey {
        var self: PrivateKey = .{ .pk = undefined };
        c.mbedtls_pk_init(&self.pk);
        self.initialized = true;
        return self;
    }

    /// Parse an unencrypted PEM or DER private key.
    ///
    /// `pem` is sentinel-typed for the same reason `Certificate.parse` is:
    /// upstream's key parser reads PEM by searching for the header, and a
    /// buffer whose last byte is not the NUL it was given is not recognised as
    /// PEM at all - `mbedtls_pk_parse_key` over the fixture key answers
    /// `-15616` (`MBEDTLS_ERR_PEM_BAD_INPUT_DATA`) for the payload alone and `0`
    /// once the terminator is included. The terminator is therefore added back
    /// here rather than left to every caller to remember.
    ///
    /// The key material is copied into the context, so `pem` need not outlive the
    /// call. A passphrase-carrying parse is not wrapped here: it would need a
    /// password this signature has nowhere to put, and a caller with one should
    /// reach `c.mbedtls_pk_parse_key` directly rather than have this module guess
    /// how long to hold it.
    pub fn parsePem(self: *PrivateKey, pem: [:0]const u8, entropy: *Entropy) error{Malformed}!void {
        const status = c.mbedtls_pk_parse_key(
            &self.pk,
            pem.ptr,
            pem.len + 1,
            null,
            0,
            c.mbedtls_entropy_func,
            &entropy.context,
        );
        // Every failure upstream reports here is one a caller cannot recover
        // from differently - a malformed key and a failed allocation both mean
        // there is no key - so this names one error rather than inventing a
        // distinction it cannot act on.
        return switch (status) {
            0 => {},
            else => error.Malformed,
        };
    }

    pub fn deinit(self: *PrivateKey) void {
        if (!self.initialized) return;
        self.initialized = false;
        c.mbedtls_pk_free(&self.pk);
    }
};

// ---------------------------------------------------------------------------
// Sockets
// ---------------------------------------------------------------------------

/// A stream socket, as Mbed TLS's own transport layer holds it.
///
/// This wraps `mbedtls_net_context`, not a bare file descriptor, because that is
/// what `mbedtls_ssl_set_bio` (`src/include/mbedtls/ssl.h:2334`) wants: it takes a
/// `void *p_bio` plus three function pointers, and the natural pair is
/// `mbedtls_net_send`, `mbedtls_net_recv` and `mbedtls_net_recv_timeout` with the
/// context behind them. Going straight to `std.posix` would mean this facade had
/// its own transport, which is a second implementation rather than a binding.
///
/// **This type has no symbols where `MBEDTLS_NET_C` is off.** That is
/// `wasm32-wasi`: `src/library/net_sockets.c:22-24` refuses the file anywhere that
/// is neither unix-like nor Windows, and `src/library/common.h:34-46` defines
/// those. The Zig declarations still translate - they are prototypes in the
/// header - but the symbols are not in the archive, so calling anything here on
/// that target is a link error rather than a runtime refusal. A target that needs
/// a TLS transport without BSD sockets supplies its own
/// `mbedtls_ssl_send_t`/`mbedtls_ssl_recv_t` pair through `c` and uses
/// `Endpoint.setTransport` with no socket at all.
pub const Socket = struct {
    ctx: c.mbedtls_net_context,
    opened: bool = false,

    /// Connect to `host`:`port` over TCP.
    ///
    /// `mbedtls_net_connect` (`src/include/mbedtls/net_sockets.h:117`) takes the
    /// protocol explicitly rather than inferring it.
    pub fn connect(host: []const u8, port: []const u8) NetError!Socket {
        if (host.len == 0 or port.len == 0) return error.Refused;
        if (std.mem.indexOfScalar(u8, host, 0) != null) return error.Refused;
        if (std.mem.indexOfScalar(u8, port, 0) != null) return error.Refused;
        var self: Socket = .{ .ctx = undefined };
        c.mbedtls_net_init(&self.ctx);
        const status = c.mbedtls_net_connect(&self.ctx, host.ptr, port.ptr, c.MBEDTLS_NET_PROTO_TCP);
        try netOk(status);
        self.opened = true;
        return self;
    }

    /// Bind a listening socket to `port` on every interface.
    ///
    /// `mbedtls_net_bind` (`src/include/mbedtls/net_sockets.h:137`) opens the
    /// socket, binds it, and makes it listening when the protocol is TCP. A null
    /// `bind_ip` binds every interface, because upstream's own documentation says
    /// so and offers no way to say otherwise; a caller that must not expose a
    /// listener has to place it behind whatever its platform provides, and a
    /// loopback default invented here would hide that choice rather than make it.
    pub fn bindAll(port: []const u8) NetError!Socket {
        if (port.len == 0 or std.mem.indexOfScalar(u8, port, 0) != null) return error.Refused;
        var self: Socket = .{ .ctx = undefined };
        c.mbedtls_net_init(&self.ctx);
        const status = c.mbedtls_net_bind(&self.ctx, null, port.ptr, c.MBEDTLS_NET_PROTO_TCP);
        try netOk(status);
        self.opened = true;
        return self;
    }

    /// Accept one connection on a listening socket.
    ///
    /// `mbedtls_net_accept` (`src/include/mbedtls/net_sockets.h:157`) writes the
    /// peer address into a caller buffer when one is given; this passes null
    /// because nothing in this facade uses it, and an unused address buffer is one
    /// more thing to get wrong.
    pub fn accept(bind: *Socket) NetError!Socket {
        var self: Socket = .{ .ctx = undefined };
        c.mbedtls_net_init(&self.ctx);
        var peer_len: usize = 0;
        const status = c.mbedtls_net_accept(&bind.ctx, &self.ctx, null, 0, &peer_len);
        netOk(status) catch |err| {
            c.mbedtls_net_free(&self.ctx);
            return err;
        };
        self.opened = true;
        return self;
    }

    /// The descriptor, or `error.InvalidContext` when this socket is closed.
    ///
    /// `fd` is a plain `int` in `mbedtls_net_context`
    /// (`src/include/mbedtls/net_sockets.h:85-93`) and `-1` is upstream's closed
    /// value, so a closed socket is detected by value rather than by a flag this
    /// wrapper keeps alongside.
    pub fn descriptor(self: *const Socket) NetError!c_int {
        if (self.ctx.fd < 0) return error.InvalidContext;
        return self.ctx.fd;
    }

    /// Read up to `buf.len` bytes, returning how many arrived.
    ///
    /// Zero means the peer closed, which is a fact and not a failure.
    /// `mbedtls_net_recv` (`src/include/mbedtls/net_sockets.h:228`) answers
    /// `MBEDTLS_ERR_NET_CONN_RESET` for a reset and a negative errno otherwise.
    pub fn read(self: *Socket, buf: []u8) NetError!usize {
        if (buf.len == 0) return 0;
        const got = c.mbedtls_net_recv(&self.ctx, buf.ptr, buf.len);
        if (got >= 0) return @intCast(got);
        if (got == c.MBEDTLS_ERR_NET_CONN_RESET) return error.ConnectionReset;
        return error.System;
    }

    /// Write `bytes`, returning how many were accepted.
    pub fn write(self: *Socket, bytes: []const u8) NetError!usize {
        if (bytes.len == 0) return 0;
        const sent = c.mbedtls_net_send(&self.ctx, bytes.ptr, bytes.len);
        if (sent >= 0) return @intCast(sent);
        if (sent == c.MBEDTLS_ERR_NET_CONN_RESET) return error.ConnectionReset;
        return error.System;
    }

    /// Close the socket. Safe to call twice; the second call is a no-op.
    pub fn deinit(self: *Socket) void {
        if (!self.opened) return;
        self.opened = false;
        c.mbedtls_net_free(&self.ctx);
    }
};

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

/// Which side of the connection an endpoint is.
pub const Role = enum {
    client,
    server,

    /// The value `mbedtls_ssl_conf_endpoint` (`src/include/mbedtls/ssl.h:2114`)
    /// takes: `MBEDTLS_SSL_IS_CLIENT` is 0 and `MBEDTLS_SSL_IS_SERVER` is 1
    /// (`src/include/mbedtls/ssl.h:318-319`).
    pub fn wire(self: Role) c_int {
        return switch (self) {
            .client => c.MBEDTLS_SSL_IS_CLIENT,
            .server => c.MBEDTLS_SSL_IS_SERVER,
        };
    }
};

/// How strictly the peer's certificate is checked.
pub const VerifyMode = enum {
    /// `MBEDTLS_SSL_VERIFY_NONE` (0, `src/include/mbedtls/ssl.h:332`): the
    /// handshake completes without a usable chain. This is the one mode with no
    /// security, and it exists for a probe that is not about trust.
    none,
    /// `MBEDTLS_SSL_VERIFY_OPTIONAL` (1, `src/include/mbedtls/ssl.h:333`): a bad
    /// chain fails the handshake on a server and is recorded on a client.
    optional,
    /// `MBEDTLS_SSL_VERIFY_REQUIRED` (2, `src/include/mbedtls/ssl.h:334`),
    /// upstream's default (`src/include/mbedtls/ssl.h:197`).
    required,

    pub fn wire(self: VerifyMode) c_int {
        return switch (self) {
            .none => c.MBEDTLS_SSL_VERIFY_NONE,
            .optional => c.MBEDTLS_SSL_VERIFY_OPTIONAL,
            .required => c.MBEDTLS_SSL_VERIFY_REQUIRED,
        };
    }
};

/// The protocol versions this configuration can negotiate.
///
/// The tags are the values `mbedtls_ssl_conf_min_tls_version`
/// (`src/include/mbedtls/ssl.h:4517`) and `mbedtls_ssl_conf_max_tls_version`
/// (`:4460`) take, which are the same `MBEDTLS_SSL_VERSION_*` codes the
/// configuration itself uses (`src/include/mbedtls/ssl.h:1259-1261`).
pub const ProtocolVersion = enum(c_int) {
    tls1_2 = c.MBEDTLS_SSL_VERSION_TLS1_2,
    tls1_3 = c.MBEDTLS_SSL_VERSION_TLS1_3,
};

/// A TLS configuration, reusable across endpoints.
///
/// `mbedtls_ssl_config` is the configuration half and `mbedtls_ssl_context` the
/// connection half; upstream keeps them apart precisely so that one configuration
/// can drive many connections, and this wrapper keeps that split rather than
/// folding it into `Endpoint`.
///
/// Every reference stored by the setters below is a *borrow*: the `Certificate`,
/// `PrivateKey` and `Entropy` must outlive this `TlsConfig` and every `Endpoint`
/// made from it. `mbedtls_ssl_conf_ca_chain` (`src/include/mbedtls/ssl.h:3616`),
/// `mbedtls_ssl_conf_own_cert` (`:3733`) and `mbedtls_ssl_conf_rng` (`:2266`) all
/// store the pointers without copying.
pub const TlsConfig = struct {
    conf: c.mbedtls_ssl_config,
    initialized: bool = false,

    /// Create a configuration for one side of a connection.
    ///
    /// `mbedtls_ssl_config_defaults` is what fills in the ciphersuite list and
    /// every other field the handshake reads, and upstream says in its own words
    /// that it must be called unless every relevant field is set by hand
    /// (`src/include/mbedtls/ssl.h:5777-5778`). It also sets the endpoint, so
    /// the `mbedtls_ssl_conf_endpoint` call that used to follow is redundant.
    /// Without this the handshake walks a null ciphersuite list
    /// (`src/library/ssl_client.c:355`). The transport is stream
    /// (`MBEDTLS_SSL_TRANSPORT_STREAM`, 0, `src/include/mbedtls/ssl.h:301`).
    pub fn init(role: Role) TlsConfig {
        var self: TlsConfig = .{ .conf = undefined };
        c.mbedtls_ssl_config_init(&self.conf);
        self.initialized = true;
        // Upstream returns 0 for every input, so there is no failure to report
        // through this signature: every argument is a constant or `role.wire()`.
        std.debug.assert(c.mbedtls_ssl_config_defaults(
            &self.conf,
            role.wire(),
            c.MBEDTLS_SSL_TRANSPORT_STREAM,
            c.MBEDTLS_SSL_PRESET_DEFAULT,
        ) == 0);
        return self;
    }

    /// How strictly to check the peer's certificate.
    pub fn authMode(self: *TlsConfig, mode: VerifyMode) void {
        c.mbedtls_ssl_conf_authmode(&self.conf, mode.wire());
    }

    /// The trust anchors.
    ///
    /// `ca_crl` is null, which means no revocation checking: upstream's
    /// revocation check only happens when a CRL chain is supplied
    /// (`src/include/mbedtls/x509_crt.h:670`), and this package ships no CRL. A
    /// caller that needs revocation must build a `mbedtls_x509_crl` and reach
    /// `c.mbedtls_ssl_conf_ca_chain` itself - the alternative would be a
    /// parameter here that is always null, which is a promise this module cannot
    /// keep.
    pub fn caChain(self: *TlsConfig, chain: *Certificate) void {
        c.mbedtls_ssl_conf_ca_chain(&self.conf, &chain.crt, null);
    }

    /// The X.509 security profile this endpoint verifies the peer's chain under.
    ///
    /// `mbedtls_ssl_conf_cert_profile` (`src/include/mbedtls/ssl.h:3602`) stores
    /// the *pointer*, so `profile` - and everything it points at - must outlive
    /// this configuration and every endpoint made from it, on the same terms as
    /// `caChain`, `ownCertificate` and `alpnProtocols`.
    ///
    /// `mbedtls_ssl_config_defaults` already points the field at
    /// `mbedtls_x509_crt_profile_default` (`src/library/ssl_tls.c:6128`), so
    /// calling this is only how a caller *changes* the policy. Upstream's note at
    /// `src/include/mbedtls/ssl.h:3594` bounds what it covers: the chain's own
    /// signatures, not the handshake signatures, which `sig_hashes` governs and
    /// this wrapper does not reach.
    pub fn certProfile(self: *TlsConfig, profile: *const CertificateProfile) void {
        c.mbedtls_ssl_conf_cert_profile(&self.conf, &profile.inner);
    }

    /// This endpoint's own certificate chain and private key.
    ///
    /// `mbedtls_ssl_conf_own_cert` (`src/include/mbedtls/ssl.h:3733`) returns
    /// zero on success and is `int`, so this ignores a non-zero answer rather
    /// than reporting a success it did not observe. Upstream's documented
    /// failures here are allocation failures, and the handshake reports a
    /// configuration that did not take.
    pub fn ownCertificate(self: *TlsConfig, chain: *Certificate, key: *PrivateKey) void {
        _ = c.mbedtls_ssl_conf_own_cert(&self.conf, &chain.crt, &key.pk);
    }

    /// Where random bytes come from.
    ///
    /// Without this the library has no entropy and answers
    /// `MBEDTLS_ERR_SSL_NO_RNG` (-0x7400) at the first point it needs one, which
    /// is inside the handshake rather than here. Setting it explicitly makes the
    /// dependency visible at the point where a caller can satisfy it.
    ///
    /// A `Drbg`, not an `Entropy`. `mbedtls_ssl_conf_rng` wants an `f_rng`, and
    /// `mbedtls_entropy_func` does not satisfy that contract: it caps one
    /// request at `MBEDTLS_ENTROPY_BLOCK_SIZE`, and RSA blinding asks for more
    /// than that. `Drbg` documents the failure in full.
    ///
    /// `mbedtls_ssl_conf_rng` (`src/include/mbedtls/ssl.h:2266`) stores both the
    /// callback and the pointer, so `drbg` must outlive this configuration and
    /// every endpoint made from it.
    pub fn rng(self: *TlsConfig, drbg: *Drbg) void {
        c.mbedtls_ssl_conf_rng(&self.conf, c.mbedtls_ctr_drbg_random, &drbg.context);
    }

    /// The lowest protocol version this endpoint will negotiate.
    pub fn minVersion(self: *TlsConfig, version: ProtocolVersion) void {
        c.mbedtls_ssl_conf_min_tls_version(&self.conf, @intCast(@intFromEnum(version)));
    }

    /// The highest protocol version this endpoint will negotiate.
    pub fn maxVersion(self: *TlsConfig, version: ProtocolVersion) void {
        c.mbedtls_ssl_conf_max_tls_version(&self.conf, @intCast(@intFromEnum(version)));
    }

    /// The ALPN protocol list, in preference order.
    ///
    /// `mbedtls_ssl_conf_alpn_protocols` (`src/include/mbedtls/ssl.h:4314`) stores
    /// the *pointer* to the array and reads each `const char *` during the
    /// handshake, so `protocols` - and every slice in it - must outlive this
    /// configuration and every endpoint made from it. That is upstream's contract,
    /// stated in its own documentation, and it is why this takes a slice rather
    /// than copying into it.
    pub fn alpnProtocols(self: *TlsConfig, protocols: []const ?[*:0]const u8) error{BadInputData}!void {
        if (protocols.len == 0) return error.BadInputData;
        const status = c.mbedtls_ssl_conf_alpn_protocols(&self.conf, protocols.ptr);
        return switch (status) {
            0 => {},
            else => error.BadInputData,
        };
    }

    /// Release the configuration. Safe to call twice.
    ///
    /// This does *not* free the `Certificate`, `PrivateKey` or `Entropy` it
    /// borrows; those are the caller's and `deinit` does not touch them.
    pub fn deinit(self: *TlsConfig) void {
        if (!self.initialized) return;
        self.initialized = false;
        c.mbedtls_ssl_config_free(&self.conf);
    }
};

/// One TLS connection.
pub const Endpoint = struct {
    ssl: c.mbedtls_ssl_context,
    initialized: bool = false,

    pub fn init() Endpoint {
        var self: Endpoint = .{ .ssl = undefined };
        c.mbedtls_ssl_init(&self.ssl);
        self.initialized = true;
        return self;
    }

    /// Bind this connection to `config`.
    ///
    /// `mbedtls_ssl_setup` checks the configuration and answers
    /// `MBEDTLS_ERR_SSL_BAD_CONFIG` (-0x5E80) when it is incomplete - a server
    /// with no own certificate, for instance.
    pub fn setup(self: *Endpoint, config: *const TlsConfig) ConfigError!void {
        return confOk(c.mbedtls_ssl_setup(&self.ssl, &config.conf));
    }

    /// The name the certificate must match, for a client.
    ///
    /// `mbedtls_ssl_set_hostname` (`src/include/mbedtls/ssl.h:4130`) turns on
    /// hostname verification *and* supplies the name to send in SNI, so it must be
    /// called for both effects. Without it the handshake can succeed against a
    /// certificate for a different name, which is the whole point of SNI; see
    /// `verifyFlags` for what to check afterwards.
    pub fn setHostname(self: *Endpoint, hostname: []const u8) ConfigError!void {
        if (hostname.len == 0 or std.mem.indexOfScalar(u8, hostname, 0) != null) {
            return error.BadInputData;
        }
        return confOk(c.mbedtls_ssl_set_hostname(&self.ssl, hostname.ptr));
    }

    /// Send and receive over `socket`.
    ///
    /// `mbedtls_ssl_set_bio` (`src/include/mbedtls/ssl.h:2334`) takes a context and
    /// three callbacks. This passes `&socket.ctx` with `mbedtls_net_send`,
    /// `mbedtls_net_recv` and `mbedtls_net_recv_timeout`, which is the combination
    /// upstream's own `programs/ssl/ssl_server2.c` uses, and the third is what
    /// gives a blocking handshake its timeout.
    ///
    /// The socket is *borrowed*: this stores the pointer and never closes it. The
    /// socket must outlive this endpoint, and `deinit` does not touch it.
    pub fn setSocket(self: *Endpoint, socket: *Socket) void {
        c.mbedtls_ssl_set_bio(
            &self.ssl,
            &socket.ctx,
            c.mbedtls_net_send,
            c.mbedtls_net_recv,
            c.mbedtls_net_recv_timeout,
        );
    }

    /// Send and receive through callbacks the caller supplies.
    ///
    /// This is the transport a target without BSD sockets uses, and it is how a
    /// caller with its own I/O - a coroutine, an event loop, a file - drives TLS
    /// without going through `Socket`. The shapes are upstream's
    /// `mbedtls_ssl_send_t` (`src/include/mbedtls/ssl.h:813`),
    /// `mbedtls_ssl_recv_t` (`:837`) and `mbedtls_ssl_recv_timeout_t` (`:863`):
    /// each takes the context and returns the byte count, or a negative
    /// `MBEDTLS_ERR_SSL_WANT_READ` / `MBEDTLS_ERR_SSL_WANT_WRITE`, or another
    /// negative error.
    pub fn setTransport(
        self: *Endpoint,
        context: ?*anyopaque,
        send: *const fn (?*anyopaque, [*]const u8, usize) callconv(.c) c_int,
        recv: *const fn (?*anyopaque, [*]u8, usize) callconv(.c) c_int,
        recv_timeout: *const fn (?*anyopaque, [*]u8, usize, u32) callconv(.c) c_int,
    ) void {
        c.mbedtls_ssl_set_bio(&self.ssl, context, send, recv, recv_timeout);
    }

    /// Run the handshake.
    ///
    /// Blocking: the transport is asked for data until it arrives, the peer closes,
    /// or the timeout fires. `error.WantReadOrWrite` is therefore not expected
    /// from the `setSocket` route and means the caller supplied a non-blocking
    /// transport through `setTransport` and has to drive the handshake itself.
    pub fn handshake(self: *Endpoint) HandshakeError!void {
        return handshakeOk(c.mbedtls_ssl_handshake(&self.ssl));
    }

    /// Read decrypted bytes, returning how many arrived; zero means the peer
    /// closed cleanly.
    pub fn read(self: *Endpoint, buf: []u8) IoError!usize {
        if (buf.len == 0) return 0;
        const got = c.mbedtls_ssl_read(&self.ssl, buf.ptr, buf.len);
        // A clean close is reported as zero bytes, not as an error: RFC 8446 §6.1
        // defines `close_notify` as the end of a stream.
        if (got == c.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return 0;
        // `mbedtls_ssl_read` (`src/include/mbedtls/ssl.h:5312`) answers with the
        // number of bytes read, or a negative error code. Only the negative
        // half is a status for `ioOk` to translate: routing the count through
        // it would read every byte transferred as `error.Unknown`, which is the
        // one tag that switch reserves for a code nothing claims.
        if (got < 0) try ioOk(got);
        return @intCast(got);
    }

    /// Write `bytes`, returning how many were accepted.
    ///
    /// `mbedtls_ssl_write` (`src/include/mbedtls/ssl.h:5387`) answers the same
    /// way - a count, or a negative error code - and upstream's notes at
    /// `:5370-5381` say the caller may have to call again for the remainder and
    /// that a request larger than the active fragment length writes less than
    /// asked. This returns the count rather than looping, because a partial
    /// write is the caller's condition and not a fault in this module.
    pub fn write(self: *Endpoint, bytes: []const u8) IoError!usize {
        if (bytes.len == 0) return 0;
        const sent = c.mbedtls_ssl_write(&self.ssl, bytes.ptr, bytes.len);
        if (sent < 0) try ioOk(sent);
        return @intCast(sent);
    }

    /// Send `close_notify` so the peer learns the stream ended deliberately.
    ///
    /// `mbedtls_ssl_close_notify` returns 0 or a specific SSL error code
    /// (`src/include/mbedtls/ssl.h:5412-5417`); this discards it, because its
    /// documented failures are `MBEDTLS_ERR_SSL_WANT_READ/WRITE` on a socket
    /// that is not ready, which is the caller's condition rather than a fault
    /// in the notice. A caller that needs to know whether the notice arrived
    /// has to read the peer's answer, which is what `read` returning zero tells
    /// it.
    pub fn closeNotify(self: *Endpoint) void {
        _ = c.mbedtls_ssl_close_notify(&self.ssl);
    }

    /// The negotiated protocol version, or null before the handshake.
    ///
    /// Borrowed from the library; valid for the life of this endpoint.
    pub fn negotiatedVersion(self: *const Endpoint) ?[]const u8 {
        const text = c.mbedtls_ssl_get_version(&self.ssl) orelse return null;
        return std.mem.span(text);
    }

    /// The negotiated cipher suite, or null before the handshake.
    pub fn negotiatedCipher(self: *const Endpoint) ?[]const u8 {
        const text = c.mbedtls_ssl_get_ciphersuite(&self.ssl) orelse return null;
        return std.mem.span(text);
    }

    /// The `MBEDTLS_X509_BADCERT_*` bits from the peer's chain
    /// (`src/include/mbedtls/x509.h:91-107`), or zero when it verified.
    ///
    /// This is the answer to "why", where `handshake`'s error is only "that".
    pub fn verifyFlags(self: *const Endpoint) u32 {
        return c.mbedtls_ssl_get_verify_result(&self.ssl);
    }

    pub fn deinit(self: *Endpoint) void {
        if (!self.initialized) return;
        self.initialized = false;
        c.mbedtls_ssl_free(&self.ssl);
    }
};