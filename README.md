# mbed-tls

Mbed TLS 3.6.7 provides TLS, X.509, cryptographic primitives and the PSA Cryptography API.
This Zig 0.17.0 package adds typed wrappers, a translated C surface and optional runtime loading.

## Source deviations

The vendored `src/`, `fixtures/` and `README.upstream.md` are unchanged from the release. `UPSTREAM.md` records the source pin.

- `zig/root.zig` adds typed wrappers for cryptography, entropy, X.509, sockets and TLS.
- `zig/translate.h` selects public Mbed TLS and PSA headers for the raw `c` namespace.
- `runtime/` adds explicit runtime loading for `mbedtls_` and `psa_` symbols.
- `tests.zig`, `smoke.zig`, `consumer/` and `tools/` add fork-owned checks and examples.

The facade does not wrap the PSA key lifecycle or DTLS. Use `c` for those APIs. `Socket` supports TCP streams.

## Build deviations

Zig compiles explicit source lists: 81 crypto units, 5 third-party units, 9 X.509 units and 18 TLS units. The build omits `src/library/ecp_curves_new.c`, an upstream compatibility stub.

The build uses generated sources shipped in the release. It runs no upstream Make, CMake or code generators.
`zig/config_gen.zig` creates one configuration header per target. C compilation and `translate-c` use it.
The build installs that header as `include/mbedtls/mbedtls_config.h`.

The libraries build in upstream order: `mbedcrypto`, `mbedx509`, then `mbedtls`. C compilation uses C11 and GNU extensions. The package checks the manifest version against the upstream header.

## Support matrix

`zig build check` compiles the libraries, tests and example for these targets. It does not run them. This is a configured target list, not a runtime test result.

| Target | Boundary |
|---|---|
| `x86_64-linux-gnu` | Compile-only check target. |
| `aarch64-linux-gnu` | Compile-only check target. |
| `aarch64-macos-none` | Compile-only check target. |
| `x86_64-windows-gnu` | Compile-only check target. Windows exports use a module definition file. |
| `riscv64-linux-gnu` | Compile-only check target. |
| `wasm32-wasi` | Networking is disabled. Dynamic loading is unavailable. |

FreeBSD adds `__BSD_VISIBLE=1` for `explicit_bzero`. OpenBSD needs no extra define.
Mach-O shared libraries use no version script, so they also export internal symbols.

The Nix flake provides static and shared packages for `x86_64-linux`, `aarch64-linux`, `x86_64-darwin`, `aarch64-darwin` and `x86_64-freebsd`.
`package.nix` builds for the native platform only.

## Consumption

Place a local checkout inside the dependent package root. Zig 0.17 rejects local dependency paths outside that root.

```zig
.dependencies = .{
    .@"mbed-tls" = .{ .path = "deps/mbed-tls" },
},
```

Then add the module and, if needed, request individual archives:

```zig
const dep = b.dependency("mbed-tls", .{
    .target = target,
    .optimize = optimize,
    .linkage = .static,
    .runtime = false,
});
exe_mod.addImport("mbedtls", dep.module("mbedtls"));

const crypto = dep.artifact("mbedcrypto");
const x509 = dep.artifact("mbedx509");
const tls = dep.artifact("mbedtls");
```

`mbedtls` is the published module and exposes translated declarations through `mbedtls.c`.
In linked mode, `mbedtls` links the three archives. Runtime mode leaves them off the module's link line. Dependents can also request the `mbedcrypto`, `mbedx509` and `mbedtls` artifacts.
C consumers get headers, the generated configuration, libraries and `mbedtls.pc`.

| Option | Default | Effect |
|---|---|---|
| `-Dlinkage=static` or `-Dlinkage=dynamic` | `static` | Select static archives or shared libraries with upstream ABI versions. Dynamic linkage needs a target dynamic loader. |
| `-Druntime=true` | `false` | Resolve native symbols after an explicit `mbedtls.load` call. This is independent of linkage. |
| `-Dsystem=true` or `-fsys=mbedtls` | Unsupported | Configuration fails. System-library mode is not provided. |

Runtime loading requires an explicit provider path or system name before any native call. The loader has no fallback or unload operation.
