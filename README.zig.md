# Zig API

```zig
const mbedtls = @import("mbedtls");
const c = mbedtls.c;
```

The facade wraps common hashing, ciphers, entropy, X.509, TCP and TLS operations. Use `c` for the translated declarations that need native Mbed TLS details.

## Module helpers

- `runtime_loaded` is a compile-time `bool`. `ready()` is true for linked builds and after a runtime provider is published.
- `load(source)` accepts `LoadSource.path` with an absolute path or `LoadSource.system` with a bare library name. Relative paths and names with separators are invalid.
- Runtime load errors are `EmptySource`, `SourceTooLong`, `InvalidSource`, `UnsupportedTarget`, `OpenFailed`, `MissingSymbol`, `ValidationFailed`, `ProviderMismatch` and `ReentrantLoad`.
- A failed load publishes no table and can be retried. Repeating the active request is harmless. A different request fails. The provider stays loaded for the process lifetime.
- Calling `load` in a linked build panics. A runtime build must load a provider before any native call.
- `loadedSource()` returns the selected request, or `null` before loading and in linked builds.

The loader checks the Mbed TLS 3.6 version family, one entropy-context layout and SHA-256 of `abc`. It does not check every configuration-dependent structure, callback or allocator. Use a provider built with a compatible configuration.

## Version and errors

- `versionString(buf)` copies the library version and returns the bytes before NUL. `buf` must hold at least 9 bytes.
- `versionNumber()` returns the library's packed version number. It is not a provenance check.
- `hasFeature(name)` returns `true`, `false` or `null` for invalid input or unavailable feature checks.
- `errorName(status, buf)` formats a native status into caller storage. The result can be truncated. An empty buffer returns an empty slice.

| Error set | Tags | Meaning |
|---|---|---|
| `HandshakeError` | `WantReadOrWrite`, `Timeout`, `ClientReconnect`, `PeerCloseNotify`, `ConnectionEnded`, `CertificateVerifyFailed`, `ProtocolError`, `InvalidMac`, `NegotiationRefused`, `InternalError`, `Unknown` | Handshake outcomes. |
| `IoError` | `WantReadOrWrite`, `Timeout`, `PeerClosed`, `ConnectionEnded`, `ProtocolError`, `InvalidMac`, `InternalError`, `Unknown` | TLS record I/O failures. |
| `ParseError` | `MemoryOrBuffer`, `Malformed`, `FileUnavailable` | Shared parser errors. |
| `VerifyError` | `Untrusted`, `Failed` | Inspect output flags for verification detail. |
| `NetError` | `System`, `ConnectionReset`, `InvalidContext`, `Refused`, `BufferTooSmall` | `System` covers other platform errors. |
| `ConfigError` | `BadInputData`, `AllocFailed`, `NoRandom`, `BadConfig` | TLS configuration failures. |

The wrappers group native failures. Use `c` when code needs native status values.

## Hashing and ciphers

- `Hash` selects SHA-1, SHA-256, SHA-384 or SHA-512. `len()` returns 20, 32, 48 or 64 bytes. `mdType()` returns the Mbed TLS selector.
- `hash(algorithm, input, out)` requires exactly `Hash.len()` bytes and returns `OutputLengthWrong` or `Failed`. Use `c` for streaming hashes.
- `hmac(algorithm, key, message, out)` also requires the exact digest length. It returns `OutputLengthWrong`, `DigestUnavailable` or `Failed`.
- `Aes128Cbc.initEncrypt` and `initDecrypt` require a 16-byte key. They return `BadKeyLength` or `Failed`.
- `crypt` accepts nonempty whole blocks and mutates its 16-byte IV. The output must hold all input bytes.
- `crypt` returns `InvalidLength`, `OutputTooSmall` or `Failed`. Input and output may alias.
- `Aes128Gcm.init` requires a 16-byte key. It returns `BadKeyLength` or `Failed`.
- GCM uses a 12-byte IV and a 16-byte tag. `seal` returns `OutputTooSmall`, `InvalidIvLength` or `Failed`.
- `open` returns `OutputTooSmall`, `InvalidIvLength`, `AuthenticationFailed` or `Failed`. Do not use plaintext after authentication fails.
- `ChaCha20Poly1305.init` requires a 32-byte key. It returns `BadKeyLength` or `Failed`.
- ChaCha20-Poly1305 uses a 12-byte nonce and a 16-byte tag. `seal` returns `OutputTooSmall`, `InvalidNonceLength` or `Failed`.
- `open` returns `OutputTooSmall`, `InvalidNonceLength`, `AuthenticationFailed` or `Failed`. Do not use plaintext after authentication fails.

Call each cipher context's `deinit`. Calling it twice on the same value is safe.

## Entropy and DRBG

- `Entropy.init()` creates a context for the sources enabled by this build. `updateManual(seed)`, `gather()` and `fill(out)` can return `SourceFailed`.
- `Drbg.init()` creates an unseeded CTR-DRBG. `seed(&entropy)` returns `SeedFailed`.
- `fill(out)` returns `RequestTooLarge` above `MBEDTLS_CTR_DRBG_MAX_REQUEST`. Other generation failures return `Failed`.
- `Entropy` and `Drbg` own native contexts. Call `deinit` when done. The entropy context is used during seeding and need not outlive that call.

## X.509 and keys

- `Certificate.init()` creates an empty chain. `parse(bytes)` accepts sentinel-terminated PEM or DER, copies input, returns `ParseError` and can leave a partial chain on failure.
- `next()` returns a borrowed node. Only the chain head owns the list and may be deinitialized. `der()` borrows bytes until the head is deinitialized. Call `deinit` on the head to release the chain.
- `subject`, `issuer` and `serial` format into caller buffers and return `BufferTooSmall` rather than truncate. `serial` uses uppercase, colon-separated hexadecimal.
- `verifyInto(trust, &flags)` uses the default profile. `CertificateProfile.default()` follows upstream policy and rejects SHA-1 signatures.
- `verifyIntoWithProfile` accepts `CertificateProfile`. Zero flags means verification succeeded. Hostname verification is separate.
- `PrivateKey.parsePem` accepts sentinel-terminated, unencrypted PEM or DER. It copies the key material and uses caller entropy during parsing.
- Invalid keys return `Malformed`. Call `deinit` to release the context.
- `profile.allowingMd(md)` returns a copy that permits another signature hash.
- `Certificate` also exposes `validFrom`, `validTo`, `isCa`, `version`, `rsaBitLength` and `parsingAvailable`.
- Validity values use calendar fields, not Unix timestamps. `rsaBitLength()` returns `null` for non-RSA keys.

## TCP and TLS

- `Socket.connect(host, port)` opens a TCP connection and returns `NetError`.
- `Socket.accept(&listener)` returns an owned connection or `NetError`.
- `bindAll(port)` listens on every interface. Use `c.mbedtls_net_bind` to select an address.
- `descriptor()` returns `InvalidContext` after close.
- `Socket.read` returns zero on a clean peer close. `Socket.write` may accept fewer bytes than requested. Call `deinit` to close the socket.
- `Role` selects client or server.
- `VerifyMode` selects `none`, `optional` or `required`. `required` is the default. `none` disables certificate checks. `optional` rejects invalid chains on servers and records them on clients.
- `ProtocolVersion` selects TLS 1.2 or TLS 1.3.
- `TlsConfig.init(role)` creates a stream configuration. It borrows trust chains, profiles, local certificates, private keys, DRBGs and ALPN names.
- Keep those values alive through every endpoint that uses the configuration.
- `authMode`, `caChain`, `certProfile`, `ownCertificate`, `rng`, `minVersion`, `maxVersion` and `alpnProtocols` configure the session.
- `caChain` does not enable CRL checks. `alpnProtocols` rejects an empty list.
- `ownCertificate` reports no error. Mbed TLS may report a rejected pair during setup or handshake.
- Call `TlsConfig.deinit()` to release the configuration.
- `Endpoint.setup(&config)` borrows the config and its dependencies. It returns `ConfigError`. `setHostname` configures SNI and hostname verification.
- `setSocket(&socket)` borrows the socket. `setTransport` borrows its context and C-ABI callbacks. All borrowed values must outlive the endpoint.
- `handshake()` returns `HandshakeError`. A nonblocking transport must retry `WantReadOrWrite`.
- `Endpoint.read` returns decrypted bytes, or zero after a clean peer close.
- `Endpoint.write` can be partial. `closeNotify()` sends the TLS close alert and ignores nonblocking status. Read until zero to confirm a clean peer close.
- `verifyFlags()` returns peer-chain flags, where zero means verification succeeded.
- `negotiatedVersion()` and `negotiatedCipher()` borrow strings until the endpoint is released. Call `Endpoint.deinit()` when done.

Mbed TLS-owned memory uses the C allocator. The facade does not accept a Zig allocator.