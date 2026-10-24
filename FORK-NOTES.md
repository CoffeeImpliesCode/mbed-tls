# Fork notes

## Source deviations

The vendored `src/` tree and `README.upstream.md` are unchanged. These fork-owned files add the Zig facade, runtime route, and package examples.

| File | Change and reason |
|---|---|
| `zig/config_gen.zig` | Generates configuration from target facts so cross builds do not inherit host features. |
| `zig/root.zig` | Adds typed wrappers with ownership and error checks while keeping translated C available as `c`. |
| `zig/translate.h`, `zig/inline.c` | Selects target-configured public headers and supplies local C wrappers for cipher bitfield accessors that translate-c demotes to extern declarations. |
| `runtime/graph.zig` | Routes `mbedtls_` and `psa_` symbols to providers while leaving libc symbols direct. |
| `runtime/generate.zig` | Owns parsed prefix storage through dispatch generation and emits wrappers that panic before load. |
| `runtime/library.zig` | Checks the provider ABI family, entropy-context layout, and SHA-256 answer before use. |
| `runtime/loader.zig` | Shared loader keeps its MIT SPDX line. `NOTICE.md` records this shared-file exception. |
| `tests.zig` | Tests wrapper ownership and loads `MBED_TLS_TEST_PROVIDER` in runtime mode without treating `std.testing.allocator` as a leak oracle for C allocations. |
| `smoke.zig` | Provides a deterministic linked example and loads an explicit provider in runtime mode. |
| `consumer/build.zig`, `consumer/build.zig.zon` | Define a standalone package that consumes `dep.module("mbedtls")` and embeds the dependency's published TLS fixtures. |
| `consumer/src/main.zig` | Imports the `mbedtls` module and loads an explicit provider in runtime mode. |

The typed facade does not wrap the PSA key lifecycle or DTLS. Those APIs remain available through `c`, and `Socket` is stream-only.

Runtime mode requires an explicit provider. The loader checks the 3.6 ABI family, one entropy-context layout, and SHA-256 of `abc`. Callers remain responsible for other public struct layouts, callbacks, and provider allocator behavior.
The default certificate profile is copied from provider data through the guarded runtime accessor. Version validation scans a bounded buffer.
The public headers declare memory-buffer allocation, secure-element driver registration and PSA entropy injection even when their implementations are disabled. Runtime dispatch treats those seven entry points as optional, matching the generated configuration. Calls still fail if the provider lacks the requested entry point. All enabled provider entry points remain required. Missing-symbol diagnostics name the required export.
Cipher-info and context accessors that read `mbedtls_cipher_info_t` use local `zig_mbedtls_` C wrappers in both linkage modes. Upstream defines them as static inline functions, so providers need not export them. The wrappers use the generated target configuration and the C compiler's bitfield layout.

## Build graph deviations

- `build.zig` uses explicit source lists aligned with upstream's CMake groups: 81 crypto units, 9 X.509 units, 18 TLS units, and 5 third-party units. It omits `src/library/ecp_curves_new.c`, an upstream compatibility stub containing only a typedef.
- The release tarball includes its generated files: `error.c`, `version_features.c`, `ssl_debug_helpers_generated.c`, `psa_crypto_driver_wrappers.h`, and `psa_crypto_driver_wrappers_no_static.c`. The build runs no upstream generator, Makefile, or CMake project. The release lacks `mbedtls-framework` and the upstream test suite.
- `zig/config_gen.zig` emits one configuration header per target. It sets AES-NI for x86, AESCE for Arm, Padlock for 32-bit x86, and networking only where sockets are supported. `build.zig` passes it to both C compilation and `translate-c`, then installs it as `include/mbedtls/mbedtls_config.h`.
- The graph builds `libmbedcrypto`, `libmbedx509`, and `libmbedtls` in upstream order. It publishes one `mbedtls` module and exposes the three archives as separate artifacts.
- Static linkage is the default. Dynamic linkage keeps upstream's ABI versions. A target without a dynamic linker rejects dynamic linkage instead of returning a static archive under a shared name.
- Native `check` graphs omit targets that cannot support the selected linkage or runtime-loading mode. Runtime checks compile the three libraries separately from the dispatch facade.
- `-Druntime=true` selects explicit provider dispatch independently of linkage. The archives are still built and installed, but the facade does not link them in runtime mode. The loader has no fallback, retry, or unload operation.
- `-Dsystem=true` and `-fsys=mbedtls` fail during configuration. The generated feature set controls public struct layouts, so bundled headers cannot safely describe an unrelated system library.
- The `consumer` step launches the standalone package with `--build-file` and a separate local cache. Zig 0.17 receives global-cache and library paths through `ZIG_GLOBAL_CACHE_DIR` and `ZIG_LIB_DIR`.

## Platform boundaries

- `FreeBSD` builds add `-D__BSD_VISIBLE=1` because upstream sets `_POSIX_C_SOURCE` before calling `explicit_bzero`. OpenBSD does not need this define.
- `wasm32-wasi` disables `MBEDTLS_NET_C`, so the network transport is unavailable and loopback tests skip. It has no dynamic linker, so dynamic linkage is refused.
- ELF shared objects use a version script for the `mbedtls_`, `psa_`, `PSA_`, and `MBEDTLS_` prefixes. Windows accepts static linkage only and links `ws2_32` and `bcrypt`.
- Mach-O has no version-script equivalent in this build. Shared objects therefore also export upstream's internal symbols, so callers must not use symbol presence as an API test.
- `package.nix` builds only for the native platform. `flake.nix` publishes five Unix systems and does not publish Windows.
