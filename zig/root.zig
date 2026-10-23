// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// See FORK-LICENSE.md for what that identifier covers.
//!
//! Typed wrappers over Mbed TLS 3.6; `c` exposes the translated public headers.
//! Contexts use Mbed TLS allocation and require `deinit`; `Socket` is stream-only.
//! PSA Crypto lifecycle and DTLS remain available only through `c`.

const std = @import("std");

/// The translated public headers, verbatim.
pub const c = @import("c");

/// Loader core supplies `LoadSource` and `LoadError` in linked builds.
const rt = @import("rt");

/// Whether this module uses runtime dispatch, known at compile time.
pub const runtime_loaded: bool = if (@hasDecl(c, "rt_runtime_loaded")) c.rt_runtime_loaded else false;

/// Explicit provider path or system name; failed requests never fall back.
pub const LoadSource = if (runtime_loaded) c.LoadSource else rt.LoadSource;

/// Errors returned by `load`.
pub const LoadError = if (runtime_loaded) c.LoadError else rt.LoadError;

/// Load the runtime provider once; repeated identical requests are harmless.
/// Failed loads can be retried; linked builds panic because no provider exists.
pub fn load(source: LoadSource) LoadError!void {
    // `c.load` is referenced only in the comptime-selected runtime build.
    if (runtime_loaded) return c.load(source);
    std.debug.panic(
        "mbedtls: load was called on a linked build; this module is not " ++
            "runtime-loaded, so there is no library to load. Build with runtime " ++
            "loading configured, or do not call load.",
        .{},
    );
}

/// The retained provider request, or `null` before loading and in linked builds.
pub fn loadedSource() ?LoadSource {
    if (runtime_loaded) return c.loadedSource();
    return null;
}

/// Whether the library is ready; runtime builds use the loader's acquire-ordered state.
pub fn ready() bool {
    if (runtime_loaded) return c.rt_is_ready();
    return true;
}

/// Copy the library-reported version into `buf` and return it without NUL.
/// Requires at least 9 bytes or returns `BufferTooSmall`.
pub fn versionString(buf: []u8) error{BufferTooSmall}![]const u8 {
    if (buf.len < 9) return error.BufferTooSmall;
    c.mbedtls_version_get_string(buf.ptr);
    // Return bytes before NUL without assuming a sentinel buffer.
    const end = std.mem.indexOfScalar(u8, buf, 0) orelse buf.len;
    return buf[0..end];
}

/// Return the library's packed `MBEDTLS_VERSION_NUMBER`.
/// Compare against an external expectation; this is not a provenance check.
pub fn versionNumber() u32 {
    return c.mbedtls_version_get_number();
}

/// Query a compiled feature; `null` denotes invalid input or unavailable checks.
pub fn hasFeature(name: []const u8) ?bool {
    if (name.len == 0 or std.mem.indexOfScalar(u8, name, 0) != null) return null;
    return switch (c.mbedtls_version_check_feature(name.ptr)) {
        0 => true,
        -1 => false,
        else => null,
    };
}

/// Format a native status into `buf`, returning bytes before NUL or an empty string.
/// Output may be truncated; no minimum buffer size is required.
pub fn errorName(status: c_int, buf: []u8) []const u8 {
    if (buf.len == 0) return "";
    c.mbedtls_strerror(status, buf.ptr, buf.len);
    // `buf` is not sentinel-typed; use its full length when no NUL was written.
    return buf[0..(std.mem.indexOfScalar(u8, buf, 0) orelse buf.len)];
}

// Error mappings

/// Coarse handshake errors; use `errorName` to inspect the native status.
pub const HandshakeError = error{
    /// WANT_READ/WRITE; only a caller-supplied nonblocking transport returns it.
    WantReadOrWrite,
    /// `MBEDTLS_ERR_SSL_TIMEOUT` (-0x6800).
    Timeout,
    /// Peer requested a fresh handshake instead of resuming.
    ClientReconnect,
    /// Peer sent `close_notify` during the handshake.
    PeerCloseNotify,
    /// Transport ended without a peer `close_notify`.
    ConnectionEnded,
    /// Peer certificate verification failed; inspect `Endpoint.verifyFlags`.
    CertificateVerifyFailed,
    /// Invalid or unexpected protocol input; the connection cannot continue.
    ProtocolError,
    /// Record authentication failed; drop the connection.
    InvalidMac,
    /// Negotiation or configuration refusal; the caller must choose a remedy.
    NegotiationRefused,
    /// Mbed TLS allocation, buffer, or internal failure.
    InternalError,
    /// No error tag covers this native status.
    Unknown,
};

/// Record I/O errors; `PeerClosed` maps `close_notify` to a zero-byte read.
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

/// Certificate and key parse errors grouped by caller remedy.
pub const ParseError = error{
    /// Mbed TLS could not allocate while parsing.
    MemoryOrBuffer,
    /// Malformed certificate/key input; `errorName` retains native detail.
    Malformed,
    /// File-based certificate or key input could not be read.
    FileUnavailable,
};

/// Certificate-chain verification errors.
pub const VerifyError = error{
    /// The chain did not reach a trusted root; inspect `flags` for the cause.
    Untrusted,
    /// Verification failed for a reason not represented by flags.
    Failed,
};

/// Socket operation errors; POSIX failures remain `System` for `errno` inspection.
pub const NetError = error{
    /// Socket-operation failure or negative system error; inspect `errno`.
    System,
    /// The peer reset the connection.
    ConnectionReset,
    /// The context is already closed; the wrapper prevents double close.
    InvalidContext,
    /// Invalid host or arguments refused before a system call.
    Refused,
    /// The caller's output buffer was too small.
    BufferTooSmall,
};

/// Endpoint configuration errors from Mbed TLS.
pub const ConfigError = error{
    /// Mbed TLS rejected an argument.
    BadInputData,
    /// Mbed TLS could not allocate.
    AllocFailed,
    /// No random source is configured.
    NoRandom,
    /// The configuration is incomplete.
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

/// SHA-1, SHA-256, SHA-384 and SHA-512 digest selectors.
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

    /// The `mbedtls_md_type_t` value for this digest.
    pub fn mdType(self: Hash) c.mbedtls_md_type_t {
        return switch (self) {
            .sha1 => c.MBEDTLS_MD_SHA1,
            .sha256 => c.MBEDTLS_MD_SHA256,
            .sha384 => c.MBEDTLS_MD_SHA384,
            .sha512 => c.MBEDTLS_MD_SHA512,
        };
    }
};

/// Hash input into an exactly sized digest; wrong lengths return `OutputLengthWrong`.
/// Other native failures return `Failed`; use `c` for streaming.
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
    // Input length is validated; other native failures map to `Failed`.
    if (status == 0) return;
    return error.Failed;
}

/// Compute HMAC into an exactly sized digest.
/// Returns `OutputLengthWrong`, `DigestUnavailable` or `Failed`.
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

/// AES-128-CBC context; caller owns it and must call `deinit`.
/// Input is a nonempty multiple of 16; the in/out IV is mutated.
pub const Aes128Cbc = struct {
    context: c.mbedtls_aes_context,
    initialized: bool = false,

    /// Set an encryption key; returns BadKeyLength or Failed.
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

    /// Set a decryption key; returns BadKeyLength or Failed.
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

    /// Encrypt/decrypt nonempty whole blocks; output may alias input and must fit it.
    /// Mutates `iv`; returns InvalidLength, OutputTooSmall, or Failed.
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

/// AES-128-GCM context; caller owns it and calls `deinit`.
/// `seal` uses a 12-byte IV and a 16-byte tag.
pub const Aes128Gcm = struct {
    context: c.mbedtls_gcm_context,
    initialized: bool = false,

    /// Initialize an AES-128 key; returns BadKeyLength or Failed.
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

    /// Encrypt with a 12-byte IV and 16-byte tag; output must fit plaintext.
    /// Returns InvalidIvLength, OutputTooSmall, or Failed.
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
        return error.Failed;
    }

    /// Authenticate/decrypt; returns InvalidIvLength, OutputTooSmall, AuthenticationFailed, or Failed.
    /// Use a 12-byte IV; on authentication failure, do not read plaintext.
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

    /// Release the context; safe to call twice.
    pub fn deinit(self: *Aes128Gcm) void {
        if (!self.initialized) return;
        self.initialized = false;
        c.mbedtls_gcm_free(&self.context);
    }
};

/// ChaCha20-Poly1305 context; caller owns it and must call `deinit`.
/// Uses a 32-byte key, 12-byte nonce and 16-byte tag (RFC 8439).
pub const ChaCha20Poly1305 = struct {
    context: c.mbedtls_chachapoly_context,
    initialized: bool = false,

    /// Initialize a 32-byte key; returns BadKeyLength or Failed.
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

    /// Encrypt using a 12-byte nonce and 16-byte tag; output must fit plaintext.
    /// Returns InvalidNonceLength, OutputTooSmall, or Failed.
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

    /// Authenticate/decrypt; returns InvalidNonceLength, OutputTooSmall, AuthenticationFailed, or Failed.
    /// Use a 12-byte nonce; on authentication failure, do not read plaintext.
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

    /// Release the context; safe to call twice.
    pub fn deinit(self: *ChaCha20Poly1305) void {
        if (!self.initialized) return;
        self.initialized = false;
        c.mbedtls_chachapoly_free(&self.context);
    }
};

/// Caller-owned entropy context using sources enabled by this build; call `deinit`.
/// Source availability depends on the target; callers may add manual seed data.
pub const Entropy = struct {
    context: c.mbedtls_entropy_context,
    initialized: bool = false,

    /// Initialize with the sources enabled by this build.
    pub fn init() Entropy {
        var self: Entropy = .{ .context = undefined };
        c.mbedtls_entropy_init(&self.context);
        self.initialized = true;
        return self;
    }

    /// Mix caller-supplied seed bytes; any input length is accepted.
    /// Returns `SourceFailed`.
    pub fn updateManual(self: *Entropy, seed: []const u8) error{SourceFailed}!void {
        const status = c.mbedtls_entropy_update_manual(&self.context, seed.ptr, seed.len);
        if (status == 0) return;
        return error.SourceFailed;
    }

    /// Gather from registered sources; returns `SourceFailed`.
    pub fn gather(self: *Entropy) error{SourceFailed}!void {
        const status = c.mbedtls_entropy_gather(&self.context);
        if (status == 0) return;
        return error.SourceFailed;
    }

    /// Fill output from configured sources; zero-length output is a no-op.
    /// Returns `SourceFailed` when the sources cannot provide entropy.
    pub fn fill(self: *Entropy, out: []u8) error{SourceFailed}!void {
        if (out.len == 0) return;
        const status = c.mbedtls_entropy_func(&self.context, out.ptr, out.len);
        if (status == 0) return;
        return error.SourceFailed;
    }

    /// Release the context; safe to call twice.
    pub fn deinit(self: *Entropy) void {
        if (!self.initialized) return;
        self.initialized = false;
        c.mbedtls_entropy_free(&self.context);
    }
};

/// Caller-owned CTR-DRBG seeded from `Entropy`; call `deinit`.
/// Seed before use; each fill is limited to `MBEDTLS_CTR_DRBG_MAX_REQUEST`.
pub const Drbg = struct {
    context: c.mbedtls_ctr_drbg_context,
    initialized: bool = false,

    /// Initialize an unseeded generator.
    pub fn init() Drbg {
        var self: Drbg = .{ .context = undefined };
        c.mbedtls_ctr_drbg_init(&self.context);
        self.initialized = true;
        return self;
    }

    /// Seed from caller-owned entropy; it need not outlive this call.
    /// Returns `SeedFailed`.
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

    /// Fill output; requests above `MBEDTLS_CTR_DRBG_MAX_REQUEST` return `RequestTooLarge`.
    /// Other generation failures return `Failed`.
    pub fn fill(self: *Drbg, out: []u8) error{RequestTooLarge, Failed}!void {
        if (out.len == 0) return;
        if (out.len > c.MBEDTLS_CTR_DRBG_MAX_REQUEST) return error.RequestTooLarge;
        const status = c.mbedtls_ctr_drbg_random(&self.context, out.ptr, out.len);
        if (status == 0) return;
        return error.Failed;
    }

    /// Release the context; safe to call twice.
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

/// X.509 signature policy for hashes, public keys, curves and RSA sizes.
/// Defaults to upstream policy; use `allowingMd` to permit another hash.
pub const CertificateProfile = struct {
    inner: c.mbedtls_x509_crt_profile,

    /// Return upstream's default profile, which rejects SHA-1 signatures.
    pub fn default() CertificateProfile {
        return .{ .inner = c.mbedtls_x509_crt_profile_default };
    }

    /// Return a copy of this profile with `md` added to allowed signature hashes.
    pub fn allowingMd(self: CertificateProfile, md: Hash) CertificateProfile {
        const id: u32 = @intCast(md.mdType());
        var out = self;
        out.inner.allowed_mds |= @as(u32, 1) << @intCast(id - 1);
        return out;
    }
};

/// Parsed certificate chain; parsing copies input and appends later certificates.
/// Only the head owns the chain; nodes returned by `next` are borrowed.
pub const Certificate = struct {
    crt: c.mbedtls_x509_crt,
    initialized: bool = false,

    /// Initialize an empty certificate chain.
    pub fn init() Certificate {
        var self: Certificate = .{ .crt = undefined };
        c.mbedtls_x509_crt_init(&self.crt);
        self.initialized = true;
        return self;
    }

    /// Parse sentinel-terminated PEM or DER, appending to this chain; input is copied.
    /// Returns `ParseError`; a failed parse can leave a partial chain.
    pub fn parse(self: *Certificate, bytes: [:0]const u8) ParseError!void {
        return parseOk(c.mbedtls_x509_crt_parse(&self.crt, bytes.ptr, bytes.len + 1));
    }

    /// Return the next borrowed chain node, or null; do not deinitialize returned nodes.
    pub fn next(self: *Certificate) ?*Certificate {
        const raw = self.crt.next orelse return null;
        return @ptrCast(raw);
    }

    /// Borrow the certificate's DER bytes until this chain is deinitialized.
    pub fn der(self: *const Certificate) []const u8 {
        const raw = self.crt.raw;
        if (raw.p == null or raw.len == 0) return &.{};
        return raw.p[0..raw.len];
    }

    /// Format the subject into `buf`; returns `BufferTooSmall` if it does not fit.
    pub fn subject(self: *const Certificate, buf: []u8) error{BufferTooSmall}![]const u8 {
        return dnGets(buf, &self.crt.subject);
    }

    /// Format the issuer into `buf`; returns `BufferTooSmall` if it does not fit.
    pub fn issuer(self: *const Certificate, buf: []u8) error{BufferTooSmall}![]const u8 {
        return dnGets(buf, &self.crt.issuer);
    }

    /// Format the serial as uppercase, colon-separated hex; short buffers return `BufferTooSmall`.
    pub fn serial(self: *const Certificate, buf: []u8) error{BufferTooSmall}![]const u8 {
        if (buf.len == 0) return error.BufferTooSmall;
        const ser = self.crt.serial;
        const status = c.mbedtls_x509_serial_gets(buf.ptr, buf.len, &ser);
        if (status < 0) return error.BufferTooSmall;
        const len: usize = @intCast(status);
        if (len > buf.len) return error.BufferTooSmall;
        return buf[0..len];
    }

    /// Return the parsed validity start; fields are calendar values, not a Unix timestamp.
    pub fn validFrom(self: *const Certificate) c.mbedtls_x509_time {
        return self.crt.valid_from;
    }

    /// The end of the validity window.
    pub fn validTo(self: *const Certificate) c.mbedtls_x509_time {
        return self.crt.valid_to;
    }

    /// Whether Basic Constraints marks this certificate as a CA.
    pub fn isCa(self: *const Certificate) bool {
        return c.mbedtls_x509_crt_get_ca_istrue(&self.crt) == 1;
    }

    /// The X.509 version: 1, 2 or 3.
    pub fn version(self: *const Certificate) c_int {
        return self.crt.version;
    }

    /// Return the RSA modulus size in bits, or null for a non-RSA key.
    pub fn rsaBitLength(self: *const Certificate) ?u32 {
        if (c.mbedtls_pk_get_type(&self.crt.pk) != c.MBEDTLS_PK_RSA) return null;
        return @intCast(c.mbedtls_pk_get_bitlen(&self.crt.pk));
    }

    /// Verify against `trust` with the default profile; TLS handles hostname checks.
    /// Returns `Untrusted` or `Failed` and writes verification bits to `flags`.
    pub fn verifyInto(self: *Certificate, trust: *Certificate, flags: *u32) VerifyError!void {
        const status = c.mbedtls_x509_crt_verify(&self.crt, &trust.crt, null, null, flags, null, null);
        return switch (status) {
            0 => {},
            c.MBEDTLS_ERR_X509_CERT_VERIFY_FAILED => error.Untrusted,
            else => error.Failed,
        };
    }

    /// Verify against `trust` with `profile`; hostname checking remains separate.
    /// Returns `Untrusted` or `Failed` and writes verification bits to `flags`.
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

/// Caller-owned private key; its context copies the key material.
/// Parsing uses caller-supplied entropy; call `deinit` to release it.
pub const PrivateKey = struct {
    pk: c.mbedtls_pk_context,
    initialized: bool = false,

    /// Initialize an empty private-key context.
    pub fn init() PrivateKey {
        var self: PrivateKey = .{ .pk = undefined };
        c.mbedtls_pk_init(&self.pk);
        self.initialized = true;
        return self;
    }

    /// Parse sentinel-terminated, unencrypted PEM or DER using `entropy`.
    /// Input is copied; invalid keys return `Malformed`.
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
        return switch (status) {
            0 => {},
            else => error.Malformed,
        };
    }

    /// Release the key context; safe to call twice.
    pub fn deinit(self: *PrivateKey) void {
        if (!self.initialized) return;
        self.initialized = false;
        c.mbedtls_pk_free(&self.pk);
    }
};

/// TCP stream socket; caller owns it and must call `deinit`.
/// Available only where the build includes `MBEDTLS_NET_C` (Unix-like and Windows).
pub const Socket = struct {
    ctx: c.mbedtls_net_context,
    opened: bool = false,

    /// Connect to `host`:`port` using TCP; returns `NetError`.
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

    /// Listen on `port` across all interfaces; returned socket is caller-owned.
    /// Returns `NetError`; restrict exposure at the platform boundary if needed.
    pub fn bindAll(port: []const u8) NetError!Socket {
        if (port.len == 0 or std.mem.indexOfScalar(u8, port, 0) != null) return error.Refused;
        var self: Socket = .{ .ctx = undefined };
        c.mbedtls_net_init(&self.ctx);
        const status = c.mbedtls_net_bind(&self.ctx, null, port.ptr, c.MBEDTLS_NET_PROTO_TCP);
        try netOk(status);
        self.opened = true;
        return self;
    }

    /// Accept one connection from this listening socket; returns `NetError`.
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

    /// Return the descriptor, or `InvalidContext` when closed.
    pub fn descriptor(self: *const Socket) NetError!c_int {
        if (self.ctx.fd < 0) return error.InvalidContext;
        return self.ctx.fd;
    }

    /// Read up to `buf.len` bytes; zero means the peer closed cleanly.
    /// Returns `ConnectionReset` or `System` on failure.
    pub fn read(self: *Socket, buf: []u8) NetError!usize {
        if (buf.len == 0) return 0;
        const got = c.mbedtls_net_recv(&self.ctx, buf.ptr, buf.len);
        if (got >= 0) return @intCast(got);
        if (got == c.MBEDTLS_ERR_NET_CONN_RESET) return error.ConnectionReset;
        return error.System;
    }

    /// Write bytes, returning the count accepted; partial writes are possible.
    pub fn write(self: *Socket, bytes: []const u8) NetError!usize {
        if (bytes.len == 0) return 0;
        const sent = c.mbedtls_net_send(&self.ctx, bytes.ptr, bytes.len);
        if (sent >= 0) return @intCast(sent);
        if (sent == c.MBEDTLS_ERR_NET_CONN_RESET) return error.ConnectionReset;
        return error.System;
    }

    /// Close the socket; safe to call twice.
    pub fn deinit(self: *Socket) void {
        if (!self.opened) return;
        self.opened = false;
        c.mbedtls_net_free(&self.ctx);
    }
};

/// Client or server endpoint role.
pub const Role = enum {
    client,
    server,

    /// The `mbedtls_ssl_conf_endpoint` value for this role.
    pub fn wire(self: Role) c_int {
        return switch (self) {
            .client => c.MBEDTLS_SSL_IS_CLIENT,
            .server => c.MBEDTLS_SSL_IS_SERVER,
        };
    }
};

/// Peer certificate verification policy.
pub const VerifyMode = enum {
    /// Disable certificate checks; the handshake can complete without a trusted chain.
    none,
    /// Reject invalid chains on servers; record them on clients.
    optional,
    /// Require a valid peer certificate; this is the upstream default.
    required,

    pub fn wire(self: VerifyMode) c_int {
        return switch (self) {
            .none => c.MBEDTLS_SSL_VERIFY_NONE,
            .optional => c.MBEDTLS_SSL_VERIFY_OPTIONAL,
            .required => c.MBEDTLS_SSL_VERIFY_REQUIRED,
        };
    }
};

/// TLS versions supported by this configuration.
pub const ProtocolVersion = enum(c_int) {
    tls1_2 = c.MBEDTLS_SSL_VERSION_TLS1_2,
    tls1_3 = c.MBEDTLS_SSL_VERSION_TLS1_3,
};

/// Caller-owned reusable stream TLS configuration; call `deinit`.
/// Referenced certificates, keys, RNGs, profiles and ALPN names are borrowed.
pub const TlsConfig = struct {
    conf: c.mbedtls_ssl_config,
    initialized: bool = false,

    /// Initialize a stream configuration for one endpoint role.
    pub fn init(role: Role) TlsConfig {
        var self: TlsConfig = .{ .conf = undefined };
        c.mbedtls_ssl_config_init(&self.conf);
        self.initialized = true;
        // Defaults always succeed for these constant arguments.
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

    /// Set borrowed trust anchors; this does not configure CRL revocation checks.
    pub fn caChain(self: *TlsConfig, chain: *Certificate) void {
        c.mbedtls_ssl_conf_ca_chain(&self.conf, &chain.crt, null);
    }

    /// Set the borrowed certificate-chain verification profile.
    /// It affects chain signatures, not TLS handshake signature algorithms.
    pub fn certProfile(self: *TlsConfig, profile: *const CertificateProfile) void {
        c.mbedtls_ssl_conf_cert_profile(&self.conf, &profile.inner);
    }

    /// Set the borrowed local certificate chain and private key.
    /// Mbed TLS errors are ignored here and may surface during setup or handshake.
    pub fn ownCertificate(self: *TlsConfig, chain: *Certificate, key: *PrivateKey) void {
        _ = c.mbedtls_ssl_conf_own_cert(&self.conf, &chain.crt, &key.pk);
    }

    /// Configure the borrowed DRBG used for TLS random requests.
    /// The DRBG must outlive this config and its endpoints.
    pub fn rng(self: *TlsConfig, drbg: *Drbg) void {
        c.mbedtls_ssl_conf_rng(&self.conf, c.mbedtls_ctr_drbg_random, &drbg.context);
    }

    /// The lowest protocol version this endpoint will negotiate.
    pub fn minVersion(self: *TlsConfig, version: ProtocolVersion) void {
        c.mbedtls_ssl_conf_min_tls_version(&self.conf, @intCast(@backingInt(version)));
    }

    /// The highest protocol version this endpoint will negotiate.
    pub fn maxVersion(self: *TlsConfig, version: ProtocolVersion) void {
        c.mbedtls_ssl_conf_max_tls_version(&self.conf, @intCast(@backingInt(version)));
    }

    /// Set the borrowed ALPN list in preference order.
    /// The list and names must outlive this config and its endpoints; empty lists return `BadInputData`.
    pub fn alpnProtocols(self: *TlsConfig, protocols: []const ?[*:0]const u8) error{BadInputData}!void {
        if (protocols.len == 0) return error.BadInputData;
        const status = c.mbedtls_ssl_conf_alpn_protocols(&self.conf, protocols.ptr);
        return switch (status) {
            0 => {},
            else => error.BadInputData,
        };
    }

    /// Release this configuration; borrowed values remain caller-owned; safe to call twice.
    pub fn deinit(self: *TlsConfig) void {
        if (!self.initialized) return;
        self.initialized = false;
        c.mbedtls_ssl_config_free(&self.conf);
    }
};

/// Caller-owned TLS connection; call `deinit`.
pub const Endpoint = struct {
    ssl: c.mbedtls_ssl_context,
    initialized: bool = false,

    /// Initialize an empty TLS endpoint.
    pub fn init() Endpoint {
        var self: Endpoint = .{ .ssl = undefined };
        c.mbedtls_ssl_init(&self.ssl);
        self.initialized = true;
        return self;
    }

    /// Bind this endpoint to `config`; incomplete settings return `BadConfig`.
    /// The configuration and its borrowed dependencies must outlive this endpoint.
    pub fn setup(self: *Endpoint, config: *const TlsConfig) ConfigError!void {
        return confOk(c.mbedtls_ssl_setup(&self.ssl, &config.conf));
    }

    /// Set peer hostname for SNI and certificate hostname verification.
    /// Empty/NUL names return `BadInputData`; other native failures return `ConfigError`.
    pub fn setHostname(self: *Endpoint, hostname: []const u8) ConfigError!void {
        if (hostname.len == 0 or std.mem.indexOfScalar(u8, hostname, 0) != null) {
            return error.BadInputData;
        }
        return confOk(c.mbedtls_ssl_set_hostname(&self.ssl, hostname.ptr));
    }

    /// Borrow a socket for TLS I/O; it must outlive this endpoint.
    /// Uses Mbed TLS TCP callbacks with timeout-aware receive.
    pub fn setSocket(self: *Endpoint, socket: *Socket) void {
        c.mbedtls_ssl_set_bio(
            &self.ssl,
            &socket.ctx,
            c.mbedtls_net_send,
            c.mbedtls_net_recv,
            c.mbedtls_net_recv_timeout,
        );
    }

    /// Install caller-supplied transport callbacks and context; they must outlive this endpoint.
    /// Nonblocking callbacks signal readiness with `WANT_READ` or `WANT_WRITE`.
    pub fn setTransport(
        self: *Endpoint,
        context: ?*anyopaque,
        send: *const fn (?*anyopaque, [*]const u8, usize) callconv(.c) c_int,
        recv: *const fn (?*anyopaque, [*]u8, usize) callconv(.c) c_int,
        recv_timeout: *const fn (?*anyopaque, [*]u8, usize, u32) callconv(.c) c_int,
    ) void {
        c.mbedtls_ssl_set_bio(&self.ssl, context, send, recv, recv_timeout);
    }

    /// Drive the TLS handshake; returns `HandshakeError`.
    /// `WantReadOrWrite` requires retrying a nonblocking callback transport.
    pub fn handshake(self: *Endpoint) HandshakeError!void {
        return handshakeOk(c.mbedtls_ssl_handshake(&self.ssl));
    }

    /// Read decrypted bytes; zero means clean peer close.
    /// Returns `IoError` on TLS or transport failure.
    pub fn read(self: *Endpoint, buf: []u8) IoError!usize {
        if (buf.len == 0) return 0;
        const got = c.mbedtls_ssl_read(&self.ssl, buf.ptr, buf.len);
        // TLS `close_notify` is a clean zero-length stream end.
        // Only negative returns are status codes; nonnegative values are byte counts.
        if (got == c.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return 0;
        if (got < 0) try ioOk(got);
        return @intCast(got);
    }

    /// Write bytes and return the accepted count; partial writes are possible.
    /// Returns `IoError` on TLS or transport failure.
    pub fn write(self: *Endpoint, bytes: []const u8) IoError!usize {
        if (bytes.len == 0) return 0;
        const sent = c.mbedtls_ssl_write(&self.ssl, bytes.ptr, bytes.len);
        if (sent < 0) try ioOk(sent);
        return @intCast(sent);
    }

    /// Send TLS `close_notify`; WANT_READ/WANT_WRITE status is ignored.
    /// Read until zero to confirm a clean peer close.
    pub fn closeNotify(self: *Endpoint) void {
        _ = c.mbedtls_ssl_close_notify(&self.ssl);
    }

    /// Borrow the negotiated protocol version, or null before handshake.
    pub fn negotiatedVersion(self: *const Endpoint) ?[]const u8 {
        const text = c.mbedtls_ssl_get_version(&self.ssl) orelse return null;
        return std.mem.span(text);
    }

    /// Borrow the negotiated cipher suite, or null before handshake.
    pub fn negotiatedCipher(self: *const Endpoint) ?[]const u8 {
        const text = c.mbedtls_ssl_get_ciphersuite(&self.ssl) orelse return null;
        return std.mem.span(text);
    }

    /// Return X.509 verification flags; zero means the peer chain verified.
    pub fn verifyFlags(self: *const Endpoint) u32 {
        return c.mbedtls_ssl_get_verify_result(&self.ssl);
    }

    /// Release the endpoint; safe to call twice.
    pub fn deinit(self: *Endpoint) void {
        if (!self.initialized) return;
        self.initialized = false;
        c.mbedtls_ssl_free(&self.ssl);
    }
};
