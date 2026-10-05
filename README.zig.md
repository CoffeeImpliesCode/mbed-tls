# The Zig interface

How the Mbed TLS 3.6.7 SDK is consumed from Zig: the typed surface in
`zig/root.zig`, the raw translated C route, the runtime-loading route, the
ownership rules, and the external ABI boundary a loaded provider has to satisfy.

For provenance, licensing and the support matrix see
[`README.md`](README.md); for the source-level evidence behind the ABI
statements see [`FORK-NOTES.md`](FORK-NOTES.md) §3 and §5.

**Status: nothing has been observed.** No configuration of this package has been
built, run or cross-compiled. Everything below describes `zig/root.zig` and
`runtime/` as they stand in the source, and every gate that would turn a
statement here into a result is `PENDING-VERIFICATION` in
[`README.md`](README.md)'s support matrix.

## The three names

```zig
const mbedtls = @import("mbedtls");   // dep.module("mbedtls")
const c = mbedtls.c;                  // pub const c = @import("c")
```

| Route | What you get | When to use it |
|---|---|---|
| Typed | the documented facade published by `zig/root.zig` | ordinary embedding |
| Raw | `mbedtls.c`, the translated headers, verbatim | an entry point, a struct or a constant the facade does not wrap |
| Runtime | the same facade over a table resolved after an explicit `load` | when the library is chosen at run time |

`c` is re-exported **on the `mbedtls` module**, not published as a module of its
own: registering it separately would hand a dependent the declarations without
the archives that satisfy them.

### What `c` carries

The whole header-declared API — `mbedtls/*`'s 74 headers and `psa/*`'s 23, as
`zig/translate.h` names them, minus the eight this package does not name and
minus `mbedtls_config.h`, which the generated one replaces. That includes:

* **`mbedtls/*`**: the symmetric primitives, the public-key primitives, hashing,
  HMAC, the PSA-backed one-shot interface, ASN.1, PEM, PKCS#5, PKCS#8, PKCS#12,
  the allocators, X.509 parsing and writing, and the whole TLS stack with its
  transport and diagnostics.
* **`mbedtls/compat-2.x.h`**: the 3.x compatibility shims, which upstream ships
  in the public include directory and which this package's translated surface
  therefore carries.
* **`psa/*`**: the PSA Cryptography API in full, including the driver and
  composite headers, because `psa/crypto.h` reaches them and a provider built
  with this configuration exports what they declare.

Three headers upstream ships are deliberately **not** named in
`zig/translate.h`, and the reasons are upstream's rather than this package's:

* `mbedtls/check_config.h` — a set of `#error` guards with no declarations in
  it at all. It is already included by `build_info.h` (`src/include/mbedtls/
  build_info.h:192`).
* `mbedtls/private_access.h` — upstream marks it `MBEDTLS_PRIVATE`. It is a
  macro vocabulary for internal use, and including it here would make this
  package's translation declare upstream's private surface as though it were
  public.
* `psa/crypto_config.h` — read only when `MBEDTLS_PSA_CRYPTO_CONFIG` is defined
  (`build_info.h:134-143`), and the configuration `zig/config_gen.zig` generates
  does not define it: PSA's mechanisms follow the legacy `MBEDTLS_*` options
  through `mbedtls/config_psa.h`, which is what upstream's own default
  configuration does. Naming it would include a header whose whole content sits
  inside a guard that is not set.

The four `psa/crypto_adjust_*` headers are not named either. Each carries
  `#error "Do not include psa/crypto_adjust_*.h manually!"` at its own line 19-25,
  and `mbedtls/config_psa.h` reaches two of them (`:23` and `:59`) at the point
  where the configuration has just been read — so naming them in the aggregate
  header would be including them in the wrong order.

In a `-Druntime=true` build `c` is a **generated dispatch** instead of the
translation step's own output. It publishes the same namespace: every type,
constant and data value is re-exported from the translation rather than
restated, so `Certificate` is the same nominal type either way and nothing here
needs a cast.

## The typed surface

Every wrapper below names the upstream `file:line` its behaviour is read from,
in its own doc comment in `zig/root.zig`. What follows is the shape.

### Version, features and errors

* `runtime_loaded: comptime bool` — true in a `-Druntime=true` build. A
  consumer can write two code paths and have only the one it chose analyzed.
* `versionString(buf) error{BufferTooSmall}![]const u8` — asks the library
  through `mbedtls_version_get_string` (`src/include/mbedtls/version.h:40`),
  whose buffer "should be at least 9 bytes in size" (`:38`), and refuses a
  shorter one rather than truncating into it.
* `versionNumber() u32` — `MBEDTLS_VERSION_NUMBER`, `0x03060700` for this
  release (`src/include/mbedtls/build_info.h:36`).
* `hasFeature(name) ?bool` — `mbedtls_version_check_feature`
  (`version.h:70`) returns 0, -1 **or -2** (feature checking not compiled in),
  so this returns an optional boolean rather than inventing an answer for the
  third case.
* `errorName(status, buf) []const u8` — `mbedtls_strerror`
  (`src/include/mbedtls/error.h:165`) writes what fits and truncates. 3.6
  removed the `MBEDTLS_STRERROR_MAX_SIZE` constant 2.x had, so there is no
  length this module can require: the caller supplies the buffer, and a code
  with no table entry answers the empty string rather than a message this module
  invented.

### Error sets

Six, each cut at what a caller can *do* about it rather than at what the C
returns:

| Set | Covers |
|---|---|
| `HandshakeError` | every way the TLS handshake can end, from the `MBEDTLS_ERR_SSL_*` codes at `src/include/mbedtls/ssl.h:47-203`, grouped by what the caller can do |
| `IoError` | record read/write ends. `MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY` is **not** an error here: a TLS stream ends by reading zero bytes, and a caller that must tell "closed" from "failed" is asking a byte stream a question it does not answer |
| `ParseError` | `MBEDTLS_ERR_X509_*` from `mbedtls_x509_crt_parse` (`x509_crt.h:529`) and the key parser, cut at: more memory or a bigger buffer, different bytes, or stop trusting them |
| `VerifyError` | why a chain did not verify; `Certificate.verifyInto`'s `flags` names which check stopped it, from the `MBEDTLS_X509_BADCERT_*` bits at `src/include/mbedtls/x509.h:91-107` |
| `NetError` | the `MBEDTLS_ERR_NET_*` codes at `src/include/mbedtls/net_sockets.h:38-60`. The low-level POSIX codes are **folded in rather than mapped**, because the library leaves `errno` as the platform set it and inventing tags for it would be a taxonomy with no owner |
| `ConfigError` | `mbedtls_ssl_conf_*` and `mbedtls_ssl_setup` refusing their argument |

### Hashing and ciphers

* `Hash` — `sha1`, `sha256`, `sha384`, `sha512`, with `.len()` (20/32/48/64) and
  `.mdType()` (`MBEDTLS_MD_*`). SHA-384 is the 384-bit truncation of SHA-512,
  which is how `src/include/mbedtls/sha512.h` spells it.
* `hash(algorithm, input, out)` — upstream's own one-shot entry points
  (`sha256.h:167`, `sha512.h`). `out.len` must be exactly the digest length; a
  shorter one is `error.OutputLengthWrong` rather than a short write, because a
  caller that asked for the wrong length has a bug a truncated digest would
  hide. A caller with a stream needs the incremental `starts`/`update`/`finish`
  trio and should reach it through `c`.
* `hmac(algorithm, key, message, out)` — `mbedtls_md_hmac` (`md.h:518`) needs
  an `mbedtls_md_info_t *` from `mbedtls_md_info_from_type` (`md.h:149`), which
  returns null when the digest was not compiled in. A null here is
  `error.DigestUnavailable`, not a null dereference.
* `Aes128Cbc` — `initEncrypt`/`initDecrypt`/`crypt`/`deinit`. CBC threads the
  IV through every call, so **`iv` is mutated in place and the caller keeps
  ownership of it**. `input.len` must be a nonzero multiple of 16; upstream
  answers `MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH` for anything else and this
  checks first rather than handing over a length it knows is rejected.
* `Aes128Gcm` — `init`/`seal`/`open`/`deinit`, 128-bit tag, 96-bit IV. A
  non-96-bit nonce is refused rather than reinterpreted.
* `ChaCha20Poly1305` — `init`/`seal`/`open`/`deinit`, exactly as RFC 8439
  constructs it: 32-byte key, 12-byte nonce, 16-byte tag. Any other length is a
  different construction, not a parameter, so it is refused rather than passed
  on.

### Entropy

`Entropy` — `init()`, `updateManual(seed)`, `gather()`, `fill(out)`, `deinit()`.
`mbedtls_entropy_context` (`src/include/mbedtls/entropy.h:106-112`) holds
`MBEDTLS_ENTROPY_MAX_SOURCES` sources — 20 at `entropy.h:58` — and a
`MBEDTLS_ENTROPY_BLOCK_SIZE` accumulator, so **its layout is a function of the
configuration**. With no hardware source registered — this configuration
registers none, because `MBEDTLS_ENTROPY_HARDWARE_ALT` is not defined — the
built-in sources are the platform ones, and `gather` cannot produce a strong
answer where upstream found none unless the caller has called `updateManual`.
That is upstream's rule; this wrapper does not hide it by adding a source of its
own, because choosing an entropy source is the caller's decision.

### X.509

* `Certificate` — `init`, `parse(bytes)`, `next`, `der`, `subject(buf)`,
  `issuer(buf)`, `serial(buf)`, `validFrom`, `validTo`, `isCa`, `version`,
  `rsaBitLength`, `verifyInto(trust, *flags)`, `deinit`, plus
  `Certificate.parsingAvailable()`.
  * `subject` and `issuer` are `mbedtls_x509_dn_gets`
    (`src/include/mbedtls/x509.h:323`), not `mbedtls_dn_gets` — the declared
    name is the namespaced one. `CHANGELOG.md` entry 7 records the correction.
  * **`serial` is upper-case hex**, because upstream writes `%02X`
    (`src/library/x509.c:962`). `CHANGELOG.md` entry 7 records the
    documentation correction.
  * `der` **borrows**: it points into memory the library owns and is valid until
    `deinit`.
  * `next` returns a **non-owning** `*Certificate` view of the next link in the
    chain, because upstream's list is freed as a whole from any member
    (`mbedtls_x509_crt_free`, `x509_crt.h:887`). A borrowed view therefore has
    **no `deinit` of its own**; releasing the head releases the chain.
  * `verifyInto` is `mbedtls_x509_crt_verify` (`x509_crt.h:670`) and reports the
    `MBEDTLS_X509_BADCERT_*` bits through `flags`. Zero means it verified.
* `PrivateKey` — `init`, `parsePem(pem, *Entropy)`, `deinit`. The RNG is the
  caller's because upstream's signature requires one
  (`src/include/mbedtls/pk.h:1116`).

### Transport and TLS

* `Socket` — `connect(host, port)`, `bindAll(port)`, `accept(*Socket)`,
  `descriptor`, `read`, `write`, `deinit`.
  * **`bindAll` binds every interface.** `mbedtls_net_bind`
    (`net_sockets.h:137`) takes a null address or an address, and upstream offers
    no way to ask for a loopback-only listener, so the address is null. A
    listener on a shared machine is therefore on every interface for the life of
    the process. Inventing a loopback default would hide that rather than make
    it disappear. A caller that must not expose a listener has to reach
    `c.mbedtls_net_bind` with a real address; that is a one-line change.
  * The port is a caller string and nothing in this library chooses one, so a
    collision is `error.System` rather than a silent retry.
  * `descriptor` answers `error.InvalidContext` once closed, which is how a
    double `deinit` is caught.
* `Role` — `client`, `server`; `wire()` maps to `MBEDTLS_SSL_IS_CLIENT` /
  `_IS_SERVER` (`ssl.h:318-319`).
* `VerifyMode` — `none`, `optional`, `required`
  (`MBEDTLS_SSL_VERIFY_*`, `ssl.h:332-334`). **`none` is the one mode with no
  security** and exists for a probe that is not about trust.
* `ProtocolVersion` — `tls1_2`, `tls1_3`, as upstream's own
  `MBEDTLS_SSL_VERSION_TLS1_2` / `_TLS1_3` (`ssl.h:1260-1261`).
* `TlsConfig` — `init(role)`, `authMode`, `caChain(*Certificate)`,
  `ownCertificate(*Certificate, *PrivateKey)`, `rng(*Entropy)`,
  `minVersion`, `maxVersion`, `alpnProtocols`, `deinit`.
  * **`caChain` stores the pointer without copying it**
    (`mbedtls_ssl_conf_ca_chain`, `ssl.h:3616`), so the certificate must outlive
    the configuration and `deinit` does not touch it. That is upstream's
    documented contract, not a leak this package introduced.
  * `ownCertificate` likewise stores both pointers (`ssl.h:3733`); its return
    value is discarded and a configuration that did not take is visible on the
    first handshake.
  * `rng` registers `mbedtls_entropy_func` and the caller's `*Entropy`
    (`ssl.h:2266`), so the entropy context must outlive the configuration and
    the endpoints built from it.
  * `alpnProtocols` refuses an empty list rather than passing one upstream would
    reject.
* `Endpoint` — `init`, `setup(*TlsConfig)`, `setHostname`,
  `setSocket(*Socket)`, `setTransport(context, send, recv, recv_timeout)`,
  `handshake`, `read`, `write`, `closeNotify`, `negotiatedVersion`,
  `negotiatedCipher`, `verifyFlags`, `deinit`.
  * `setTransport` is the door for a transport this SDK does not have —
    a memory BIO, a DTLS timer, an already-connected fd. `Socket` is the one
    transport it wraps.
  * `handshake` never returns `WantReadOrWrite` on the blocking route `Socket`
    provides, because the socket carries a timeout; a caller driving its own
    transport through `setTransport` **must** handle it.
  * `read` reports a clean peer close as **zero bytes, not an error**:
    `MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY` is raised at
    `src/library/ssl_msg.c:5297`, and RFC 8446 §6.1 is how the client learns
    the stream ended deliberately rather than being cut.
  * `negotiatedVersion` and `negotiatedCipher` **borrow** from the library and
    are valid for the life of the endpoint.
  * `verifyFlags` is `mbedtls_ssl_get_verify_result` (`ssl.h:4881`) — the answer
    to "why", where `handshake`'s error is only "that".

## Ownership rules a caller must respect

* **Every owning wrapper has an idempotent `deinit`.** A second call is a no-op,
  and `initialized` is cleared before the C free, so a wrapper that is copied
  cannot be released twice. Every test that creates one releases it on every
  path, including the failing one.
* **`Certificate.next` is a borrowed view with no `deinit`.** Upstream frees the
  whole chain from any member (`mbedtls_x509_crt_free`, `x509_crt.h:887`), so a
  second close would walk freed memory. A `*Certificate` from `next` must not
  outlive the head it came from, and must never be deinitialised itself.
* **`TlsConfig` borrows its certificate, key and entropy.** Three pointers
  stored without copying, per upstream's own signatures. They must outlive the
  configuration **and** every endpoint built from it; `deinit` frees the
  configuration only.
* **`Aes128Cbc.crypt` mutates the caller's IV.** Upstream takes it as an in/out
  `unsigned char iv[16]`.
* **`Endpoint.setSocket` borrows the socket, and `Socket` must outlive every
  endpoint built on it.** `deinit` on the endpoint does not touch it.
* **`Certificate.der` and `Endpoint.negotiatedVersion`/`negotiatedCipher`
  borrow.** Both are valid until the owning wrapper is released or the next
  handshake replaces them. `subject`/`issuer`/`serial` **copy** into the caller's
  buffer instead, and refuse a buffer that is too small rather than truncating a
  distinguished name into a different one.
* **The allocator belongs to the C library.** `mbedtls_calloc` and
  `mbedtls_free` (`src/library/platform.c:44-55`) are libc `calloc`/`free`
  through `mbedtls_platform_set_calloc_free` (`platform.c:57-63`) unless a
  platform hook is set. **No Zig allocator is in the path**, so
  `std.testing.allocator` is not a leak oracle for anything Mbed TLS allocates
  and nothing here claims it is. `deinit` is the whole release.
* **A runtime-loaded library is never released.** `load` has no counterpart; the
  table lives for the life of the process and the loader does not close the
  provider. One rule covers both configurations: **a state is always closed
  through the route that opened it** — a linked build never frees a loaded
  provider's object, and a loaded build never frees a linked archive.

## What is deliberately not here

Three gaps, stated so a reader does not have to infer them.

* **PSA Crypto's key lifecycle.** `psa_crypto_init`, the key slots, the
  secure-element drivers and `psa/crypto_se_driver.h` are all in the translation
  and reachable through `c`, but there is no typed wrapper. A PSA key is owned
  by a slot table inside the library, so a wrapper whose `deinit` could be
  skipped would leak a **slot**, not a pointer. That is a real hazard and this
  package does not paper over it with a wrapper whose failure mode is
  undocumented.
* **DTLS.** The DTLS configuration and timer entry points are reachable through
  `c`. No wrapper claims DTLS, and `Socket` is a stream transport only.
* **Anything that would re-derive a value upstream defines.** `versionString`
  asks the library rather than restating `build.zig.zon`'s `.version`;
  `hasFeature` asks `mbedtls_version_check_feature`, which reads the same
  configuration this build compiled against.

## The runtime route

`-Druntime=true` builds the same library and routes native calls through one
process-lifetime table instead of linking against it. It is orthogonal to
`-Dlinkage`.

```zig
const mbedtls = @import("mbedtls");

// exactly one of these, explicitly; there is no fallback between them
try mbedtls.load(.{ .path = "/usr/local/lib/libmbedtls.so.21" });  // an absolute path
try mbedtls.load(.{ .system = "libmbedtls.so.21" });                // the soname
```

* **The classification is a prefix, not an exclusion.** `provider_prefix` is
  `"mbedtls_,psa_"` (`runtime/graph.zig:94`) and `libc_noise` is **empty**
  (`runtime/graph.zig:104`). A declaration is routed when its name starts with
  one of those prefixes and kept direct otherwise, so a C-library symbol can
  never be resolved out of the provider — the provider *depends* on the C
  library, and the loader opens the provider with `RTLD_LOCAL` precisely so a
  lookup cannot find it there. The alternative, enumerating every libc name that
  reaches the translation through the headers' include closure, depends on the
  libc family, on `_FORTIFY_SOURCE` and on which fortified aliases that libc
  version declares; a name missing from such a list is not cosmetic, it is
  routed and every load then fails with `MissingSymbol` on a name the provider
  never owed. A prefix rule has no such failure mode.
* `provider_optional` and `provider_excluded` are both **empty**, and written
  out rather than omitted, so adding a header with an optional or
  deliberately-direct entry point is a change in `runtime/graph.zig` with a name
  in it. A provider that does not export the whole `mbedtls_`/`psa_` set is
  refused rather than half used.
* **One table per configured module, for the life of the process.** No library
  object, no returned API view, no unload. `loadedSource()` reports what was
  selected and its answer stays valid for the life of the process.
* Calling a native entry point before a successful load **panics in every
  optimization mode**, naming the symbol (`runtime/generate.zig:1019-1022`). A
  failed attempt publishes nothing; an explicit later `load` is allowed and an
  automatic one never happens. A repeated request with the same source is
  idempotent; a different source after a success is `ProviderMismatch` and the
  library already in use stays in use.
* `LoadSource` and `LoadError` are the types the linked branch also imports from
  the loader core, so both branches present one signature. `LoadError` is
  `EmptySource`, `SourceTooLong`, `InvalidSource`, `UnsupportedTarget`,
  `OpenFailed`, `MissingSymbol`, `ValidationFailed`, `ProviderMismatch` and
  `ReentrantLoad` (`runtime/loader.zig:77-116`). A relative path is
  `InvalidSource`, never a search. On a target with no dynamic library loader
  `load` is an honest `UnsupportedTarget`, not a fallback to a linked copy.
* In a linked build `load` **stops the program** with a message saying there is
  no provider, rather than quietly succeeding. `runtime_loaded` is false there,
  so a consumer that supports both configurations tells them apart at comptime
  and never analyzes the branch it does not have.
* **One C file** is compiled for the route: `runtime/sync.c` supplies the
  loader's mutex, condition variable and thread identity, `runtime/sync.h`
  declares them, and `runtime/library.zig` binds the five `mbedtls_rt_*` symbols
  by exact name. `runtime/graph.zig:83` sets the prefix `mbedtls_rt` and
  `:217` passes it as `-DRT_SYNC_PREFIX=mbedtls_rt`; `runtime/sync.h:10-11`
  `#error`s if that macro is missing. The two spellings of the prefix have to
  agree — this package names the symbols and the build defines the macro — and a
  build where they disagree does not link, which is the whole error report.
  `runtime/loader.zig` itself names no symbol of its own, which is what lets two
  SDKs, or two configurations of one SDK, hold their own loader state in one
  process without sharing any of it.

### What a loaded provider must match

Resolving the symbols proves the library has those names. It says nothing about
whether the consumer and the provider agree about anything else, so the boundary
is in two parts: what `runtime/library.zig` actually checks before publishing a
table, and what it deliberately does not.

**Checked before anything is published**, every failure a `ValidationFailed`
the caller sees (`runtime/library.zig:229-285`):

1. **Family.** `mbedtls_version_get_string_full`
   (`src/include/mbedtls/version.h:51`) copies `MBEDTLS_VERSION_STRING_FULL`
   (`build_info.h:38`) verbatim (`src/library/version.c:25-29`), and the result
   must begin **`"Mbed TLS 3.6."`**. That prefix rather than the whole
   `"Mbed TLS 3.6.7"` because a patch release inside the same LTS line is the
   same ABI family, and this package is pinned to one patch, not one minor. It
   is what separates 3.6 from 3.5, from 3.4, from 2.28 and from 4.x.
2. **Layout, by allocating through it.** One `mbedtls_entropy_context` is
   created with **this translation's own `sizeof`** and handed to the provider,
   then destroyed (`mbedtls_entropy_init`, `entropy.h:135`;
   `mbedtls_entropy_free`, `:142`). Doing the free here rather than at process
   exit is what keeps the check from leaking if it fails. It is the first struct
   whose *layout* crosses the boundary: a provider compiled with a different
   `MBEDTLS_ENTROPY_MAX_SOURCES` or `MBEDTLS_ENTROPY_BLOCK_SIZE` writes a
   different number of bytes into it.
3. **An independent cryptographic answer.** SHA-256 of the three bytes `"abc"`
   must equal `ba7816bf…15ad`, the single-message digest FIPS 180-4 Appendix B
   publishes for `abc`. **The constant is a published standard value, not
   something this package computed**, and a provider whose SHA-256 is broken,
   stubbed, or answering through a driver it does not have is refused here
   rather than discovered inside a caller's handshake.

**Not checked, and therefore obligations on the caller**, not claims of
compatibility:

4. **Configuration, beyond the entropy struct.** Mbed TLS's layouts and buffer
   sizes are **compile-time constants read out of the configuration header**, not
   run-time negotiation. `mbedtls_ssl_context` (`ssl.h:1731`) is a large struct
   whose field types are configuration-dependent, and every public struct is
   fixed by the same header. A provider built with a different configuration has
   a *different struct under the same name*, so every offset the C code reads
   through them is wrong. `mbedtls_version_check_feature` is how a provider is
   asked which options it was built with, and the load-time check does **not**
   call it: a check that returns -1 for a missing feature is not a check of a
   *struct layout*, and this package cannot enumerate every layout-relevant
   option without becoming a second copy of `mbedtls_config.h`.
5. **The allocator is the provider's.** `mbedtls_calloc`/`mbedtls_free` are
   libc `calloc`/`free` unless `MBEDTLS_PLATFORM_C` dispatches them through
   `mbedtls_platform_set_calloc_free`. Nothing in this SDK can observe, bound or
   account for those allocations, and a test framework cannot supply a leak
   oracle for memory a third-party allocator owns.
6. **Callbacks cross in both directions.** `mbedtls_ssl_conf_*`,
   `mbedtls_x509_crt_verify` and the PSA key-derivation calls take function
   pointers the provider will call back with the provider's own calling
   convention, and `mbedtls_ecp_curve_info` and the other accessors return
   pointers into the provider's own static tables.
7. **Same-provider close.** A state is always closed through the route that
   opened it.

One thing is deliberately **not** called at load time: upstream's own check for
this family, `mbedtls_psa_crypto_config_check` behind `MBEDTLS_SELF_TEST`, whose
self-test path calls `exit`. A loader that has to answer `ValidationFailed`
cannot use a check that kills the process, so the facts it would have checked —
the version family and one real cryptographic operation — are checked in the
form above instead, which returns.

**The supported external ABI family is Mbed TLS 3.6**, built from these headers
with the configuration `zig/config_gen.zig` generates. **Mbed TLS 4.x is a
different ABI** — 4.0 moved the primitives into a separate TF-PSA-Crypto
repository and removed the legacy `mbedtls_sha256_*`, `mbedtls_gcm_*` and
`mbedtls_rsa_*` entry points, so a 4.x object would fail on `MissingSymbol`
before any check ran. **Mbed TLS 2.28 is a different ABI** for the other
reason: its configuration is older, its layouts differ and its TLS 1.3 support is
absent. Both are refused by the version-family check above, by name, before
anything is published.

## What the tests cover

`tests.zig` is **27 tests**, and **no gate has run them**. Every expected value
is a published standard vector or an independently measured fact about a
fixture, never a value this build computed and accepted back.

* **Hashing** — SHA-256, SHA-384, SHA-512 and SHA-1 of `"abc"` against the
  single-message digests FIPS 180-4 Appendix B and RFC 1321 Appendix A.1 print;
  the empty message against the same table's empty-message digest; a
  wrong-length output buffer refused rather than truncated.
* **HMAC-SHA-256** — RFC 4231 §4.2 test case 1.
* **Block ciphers** — AES-128-CBC against SP 800-38A §F.2.1's first block, plus
  a length the mode cannot carry refused, plus a decryption round trip as a
  supplement rather than as the oracle.
* **AEADs** — AES-128-GCM against the GCM specification's Test Case 2, and
  ChaCha20-Poly1305 against RFC 8439 §2.8.2, each with a modified tag refused
  and the plaintext left unusable, and a wrong-length nonce refused rather than
  reinterpreted.
* **Ownership** — a second `deinit` is a no-op rather than a double free; an
  AEAD context whose key was never accepted releases nothing twice; a key of the
  wrong length is refused **and the context is already released**.
* **X.509** — the vendored test CA and server certificate parse to the fields
  OpenSSL reads out of them (a different implementation from the one under
  test); the fixture chain verifies against the fixture CA **and only against
  it**; bytes that are not a certificate and a truncated certificate are refused
  rather than half accepted; a distinguished name that does not fit is refused,
  not truncated; and a borrowed chain link carries the chain's lifetime, not its
  own.
* **TLS** — a real TLS 1.3 handshake over a loopback socket carrying a request
  and an answer, against the fixture and nothing else; a client with no trust
  anchor refusing the server's certificate, with the reason available separately
  through `verifyFlags`; and a socket closing once, with a second close not
  closing it again.

**The three loopback tests are compiled for every cross target and run only
where `MBEDTLS_NET_C` is on.** On `wasm32-wasi` they report `SkipZigTest`,
which is a recorded platform boundary rather than a dropped target — the same
condition `zig/config_gen.zig` decides from the resolved target, read out
without calling anything, so a test can tell "this build has no transport" from
"the library failed".

**Two ports are fixed and stated rather than chosen**: the handshake tests bind
`39443`, the socket-ownership test binds `39445`. `Socket.bindAll` takes a port
and nothing else, so nothing in this library chooses one and there is no way to
ask which port a run took. A collision is a non-zero exit with no retry.

**No test pins a version string or a default constant.** `smoke.zig` prints the
version the library reports and never compares it; the pin is
`tools/check-provenance.sh`'s job, and comparing
`versionNumber()` against a number read out of `build_info.h` would be the
library agreeing with itself, which is provenance and not behaviour.

## What a gate still owes

| Route | Command | Status |
|---|---|---|
| linked, static | `zig build test`, `zig build smoke` | `PENDING-VERIFICATION` |
| linked, ReleaseSafe | `zig build test -Doptimize=ReleaseSafe` | `PENDING-VERIFICATION` |
| linked, shared | `zig build test -Dlinkage=dynamic` | `PENDING-VERIFICATION` |
| compile-only, six targets | `zig build check` | `PENDING-VERIFICATION` |
| runtime-loaded | `zig build smoke -Druntime=true -- --provider <path>` | `PENDING-VERIFICATION` |
| consumer, entered directly | `cd consumer && zig build run` | `PENDING-VERIFICATION` |
| 53 platforms | `cross-test` | `PENDING-VERIFICATION` |

**The suite is not currently written for the loaded route.** `tests.zig` names
no `load`, no `MBED_TLS_TEST_PROVIDER` and no `runtime_loaded`, so a
`-Druntime=true` test binary would reach its first native call through an
unpublished table and stop there. The loaded route's behavioural coverage is
therefore `smoke.zig` and `consumer/src/main.zig`, both of which do load
explicitly. [`FORK-NOTES.md`](FORK-NOTES.md) §11 carries this as an open item
rather than a claim about the loaded configuration.