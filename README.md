# mbed-tls

**Mbed TLS 3.6.7** — the portable TLS, X.509 and cryptography library, and the
PSA Cryptography API reference implementation — as a complete standalone Zig SDK:
all three upstream archives compiled from the pinned release tarball, the 89
public headers, a **per-target generated configuration header**, a typed Zig
surface, the raw translated C route and an optional runtime-loading route.
No CMake, no autotools, no make, no build-time download, no system library.

* Upstream: tag `mbedtls-3.6.7`, commit
  `068ff080b369adfac81509f9b57b2afabaf82dc5`, released 2026-07-07,
  `mbedtls-3.6.7.tar.bz2`, sha256
  `a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6` — see
  [`UPSTREAM.md`](UPSTREAM.md).
* Native source: **unmodified**. All 336 vendored files are recorded by digest in
  [`UPSTREAM.sha256`](UPSTREAM.sha256) and checked by
  [`tools/check-provenance.sh`](tools/check-provenance.sh).
* Licence: **`Apache-2.0 OR GPL-2.0-or-later`**, the choice being the
  recipient's, for both the vendored native source and this fork's own files.
  The tree is **not** one label: four per-file exceptions are itemised in
  [`NOTICE.md`](NOTICE.md). See "Licence" below for what this package actually
  ships and what it records.
* Upstream's own README is preserved byte for byte as
  [`README.upstream.md`](README.upstream.md), 336 lines, sha256
  `6ea15aafaf9765a730b651eeb5376bf54b646c5ee5fcc6b7c80d6d0d209a3fb4`.
* Zig: **0.16.0**.

**No gate has been run for this package.** No build, no test, no smoke run, no
cross-target compile, no Nix build and no CI job has been executed. Every status
below is `PENDING-VERIFICATION`; the driver owns every result, and none of them
is in this file.

## Native-source deviations

**None.** Every one of the 336 files under `src/`, `fixtures/` and the preserved
upstream README is byte-identical to the release tarball. No portability patch,
no reformat, no `#if` added around a platform workaround, no upstream file
edited.

That is a checkable claim rather than an assertion:

```sh
sha256sum -c UPSTREAM.sha256          # the bytes
tools/check-provenance.sh             # the bytes, the exact file set, the notice
```

`tools/check-provenance.sh` does two things a plain checksum run cannot. It
compares the recorded path list against what is on disk, so an **added**,
removed or renamed file fails as loudly as an edited one; and it re-reads the
grant itself — Mbed TLS's dual statement in `src/LICENSE`, the Everest
Apache-2.0 notice in its own generated source, and the three fixture names in
both this package's records and the digest manifest.

Three upstream facts shape this SDK, all read out of the source rather than
assumed:

* **The release archive ships the generated sources, so this build generates
  none of upstream's own.** Five files are named `GENERATED_FILES` at
  `src/library/Makefile:5-9`: `error.c`, `version_features.c`,
  `ssl_debug_helpers_generated.c`, `psa_crypto_driver_wrappers.h` and
  `psa_crypto_driver_wrappers_no_static.c`. All five are vendored
  pre-generated, and upstream says so at `README.upstream.md:61`: the generated
  files "are not included in the development branch of Mbed TLS, but the
  generated files are included in official releases". No Perl or Python
  generator runs here, and none is vendored, because none is in the tarball.
* **The `mbedtls-framework` submodule is absent and this tree does not fake
  it.** Upstream's own words at `README.upstream.md:57` are that it "is not
  needed to consume a release archive (zip or tar)". So there is no `framework/`
  directory and no example programs here. `src/library/Makefile:12-23` therefore
  refuses to build in this tree — that is upstream's own guard, not a fork edit.
  This SDK does not run that makefile.
* **The one file this build does generate is the configuration header**, and it
  is generated *per target*. See "Native-build deviations" below.

## Native-build deviations

What the compiled package does that upstream's own `Makefile` and CMake tree do
not. Each is a fork decision with a stated reason; none of them changes an
algorithm, a public header or a struct layout upstream defines.

* **Zig builds it; both upstream build systems are unused.** `build.zig`
  compiles the exact closure `src/library/CMakeLists.txt` names: **81**
  `src_crypto` units, **9** `src_x509` and **18** `src_tls`, plus the **five**
  `3rdparty` units that `3rdparty/everest/Makefile.inc` and
  `3rdparty/p256-m/Makefile.inc` add. `libmbedcrypto` receives the 81 crypto
  units **and** the five third-party units, because that is where upstream's
  `library/Makefile` puts them. **113 translation units in the closure.**
* **The source lists are explicit per-file arrays, never globs.** A glob would
  change what this package compiles the next time a file appears, and it would
  do so in a commit whose diff is one line. `src/library/ecp_curves_new.c` is
  on disk and in no list: upstream keeps it "only for compatibility with custom
  build systems in LTS branches" and its whole body is
  `typedef int iso_c_forbids_an_empty_translation_unit;`. It is vendored,
  digested and deliberately not compiled, and `build.zig` says so inline rather
  than leaving the omission for a reader to infer.
* **Three archives, upstream's names and upstream's layering.** `libmbedcrypto`
  under `libmbedx509` under `libmbedtls`, each a complete `addLibrary` over its
  own list, linked in that order.
* **Two delivery linkages.** `-Dlinkage=static` (default) produces
  `libmbedcrypto.a`, `libmbedx509.a` and `libmbedtls.a`; `-Dlinkage=dynamic`
  produces shared objects carrying **upstream's own ABI numbers** —
  `libmbedcrypto.so.16`, `libmbedx509.so.7`, `libmbedtls.so.21`, read out of
  `SOEXT_CRYPTO`, `SOEXT_X509` and `SOEXT_TLS` at `src/library/Makefile:77-79`.
  Matching them is the point: a system library with the same name must be
  interchangeable at the ABI level or the number is a lie. A target with no
  dynamic linker refuses `.dynamic` (`deliveredLinkage`, `build.zig:868-881`)
  rather than handing back an archive under a name the caller did not ask for.
* **The exported surface is upstream's naming convention, as a rule rather than
  a list.** On ELF a generated version script exports `mbedtls_*`, `psa_*`,
  `PSA_*` and `MBEDTLS_*` and marks everything else `local`
  (`setVersionScript`, `build.zig:725-739`); on Windows a generated module
  definition file states the same four patterns (`build.zig:658-667`). Neither is
  a hand-maintained catalogue of 1500 names that could fall out of step with the
  headers, and a header that adds a symbol needs no change to either.
* **A per-target configuration header, generated for the target being built.**
  `zig/config_gen.zig` runs on the build machine with the *resolved target's*
  facts as command-line arguments, reads this package's own copy of upstream's
  `src/include/mbedtls/mbedtls_config.h`, and writes one complete configuration
  header for that target. `builtin.target` appears nowhere in it, so host
  platform macros can never be copied onto a cross target. The header is reached
  through `-DMBEDTLS_CONFIG_FILE='"mbed_tls_target_config.h"'` — the hook
  upstream documents for exactly this purpose at
  `src/include/mbedtls/build_info.h:112-116` — with the generated directory on
  the include path of **both** the C compile line and the `translate-c` line, so
  the declarations and the compiled code cannot describe different
  configurations.
  * **The build-internal name is deliberately not `mbedtls_config.h`.**
    `build_info.h` reaches that name with a *quoted* include, which resolves
    beside `build_info.h` before any `-I` directory is consulted, so a file of
    that name on the include path would never be found. The generated header
    cannot shadow anything.
  * **Four target-derived decisions**, each anchored to the upstream line that
    requires it, and each written into the generated header's own banner so the
    reason travels with the option: `MBEDTLS_AESNI_C` on for x86 and x86-64
    only (`src/library/aesni.h:23-24`), `MBEDTLS_AESCE_C` on for Arm only
    (`src/library/aesce.h:23-26`), `MBEDTLS_PADLOCK_C` on for 32-bit x86 only
    (`src/library/padlock.h:33-36`, and `src/library/aes.c:32-42` rejects it
    elsewhere), and `MBEDTLS_NET_C` on only where the platform has the sockets
    library (`src/library/net_sockets.c:22-24` refuses it, and
    `src/library/common.h:34-46` is what defines where it is allowed).
  * **One generated file *is* installed**, as
    `include/mbedtls/mbedtls_config.h`: a consumer including any Mbed TLS header
    needs a configuration there, and the one that describes a different feature
    set than the linked library is the failure this workspace rules out by name.
    A dependent therefore needs no compile macro at all.
* **A typed Zig surface beside the raw one.** `zig/root.zig` publishes a
  documented facade over the same library, and re-exports the translated headers
  as `c` on that same module. Full detail in
  [`README.zig.md`](README.zig.md).
* **One published module, three published artifacts.** `dep.module("mbedtls")`
  carries the facade and links all three archives beneath it. The three
  archives are separately addressable as `dep.artifact("mbedcrypto")`,
  `dep.artifact("mbedx509")` and `dep.artifact("mbedtls")`, so a dependent that
  wants only the primitives can link one.
* **Optional runtime loading.** `-Druntime=true` selects a load-at-runtime route
  with explicit `path` or `system` selection, one process-lifetime table, no
  fallback and no automatic retry. Orthogonal to `-Dlinkage`. Under it the
  archives are still built and installed — delivery and dispatch are different
  questions — but they are **not** on the facade's link line, so nothing can
  resolve them statically behind the loader's back.
* **No system-library mode, and the refusal is explicit.**
  `-Dsystem=true` / `-fsys=mbedtls` selects an installed Mbed TLS whose headers
  and struct layouts are not the ones this graph builds, and a dependent would
  then be compiling bundled headers against a different library. `build.zig`
  **panics at configure time** with that message rather than silently producing a
  bundled library under a system-mode spelling (`build.zig:1159-1167`). A fork
  with no system mode records the rule as vacuous, not satisfied
  ([`FORK-NOTES.md`](FORK-NOTES.md) §4).
* **C11 with the GNU extensions, pinned.** `-std=c11 -D_GNU_SOURCE`
  (`c_flags`, `build.zig:333-336`). Upstream has no `-std=` anywhere in
  `src/library/Makefile`, so this pins one and makes it a fact of the build
  rather than a fact about whichever clang is installed. `-D_GNU_SOURCE` is
  needed because `net_sockets.c:63-70` reaches `<sys/socket.h>`, `<netdb.h>`
  and friends that glibc hides without it.
* **`-D__BSD_VISIBLE=1` on FreeBSD only.** `src/library/platform_util.c:14-16`
  opens by defining `_POSIX_C_SOURCE 200112L` (to keep `gmtime_r` under
  `-std=c11`), and FreeBSD reads that define the other way: its
  `sys/_visible.h` takes the `_POSIX_C_SOURCE` branch and never defines
  `__BSD_VISIBLE`, which is exactly what `strings.h:53-54` gates
  `explicit_bzero` on — so `platform_util.c:43-45` turns
  `MBEDTLS_PLATFORM_HAS_EXPLICIT_BZERO` on for FreeBSD >= 11.0.3 and
  `platform_util.c:98` then calls a function the header will not declare
  (`error: call to undeclared function 'explicit_bzero'`). `-D_DEFAULT_SOURCE`
  does not reach that branch on this target; the macro does
  (`freebsd_c_flags`, `build.zig:339-343`, `cFlags` at `build.zig:356-361`).
  OpenBSD needs none of it: `platform_util.c:14` already excludes OpenBSD from
  the `_POSIX_C_SOURCE` define and its `sys/cdefs.h` defaults `__BSD_VISIBLE`
  to 1.
* **One version, checked at configure time.** `build.zig` refuses to configure
  unless `build.zig.zon`'s `.version` equals the 3.6.7 read out of
  `src/include/mbedtls/build_info.h:27-29`, so the manifest and the header cannot
  describe different releases.
* **The installed closure comes from one writer.** `lib/` with the three
  archives; `include/mbedtls/` (71 headers) and `include/psa/` (18 headers) in
  their own subdirectories, because the headers include each other by those
  exact names and a flat layout would make `#include "mbedtls/build_info.h"`
  unresolvable; `include/mbedtls/mbedtls_config.h`, the generated one;
  `lib/pkgconfig/mbedtls.pc`; and `share/licenses/mbed-tls/` holding
  `src/LICENSE`, `NOTICE.md`, `FORK-LICENSE.md`, `UPSTREAM.md` and
  `README.upstream.md` — the five `licence_records` at `build.zig:405-411`.
  **89 vendored headers install out of the 97 the tarball carries**; the eight
  that do not are `check_config.h`, `private_access.h`, `psa/crypto_config.h`
  and the four `psa/crypto_adjust_*` headers, all reached through
  `build_info.h` rather than named by a consumer, and
  `mbedtls/mbedtls_config.h`, which is replaced by the generated one.
* **Three published archive names, upstream's, never this fork's.** The
  pkg-config file is `mbedtls.pc` and reports `-lmbedtls -lmbedx509
  -lmbedcrypto`, plus `-lm` where `libm` is separate and `-ldl` for a shared
  build where `libdl` is. Nothing upstream's own makefile installs is renamed.

### History of these deviations

The deviations above are the current state. [`CHANGELOG.md`](CHANGELOG.md)
numbers each one — entries 1 through 7, all landed as the import itself — and
[`FORK-NOTES.md`](FORK-NOTES.md) records the condition, the symptom, the fix and
the boundary of every decision, including the four corrections entry 7 lists.

## Support matrix

### No gate has been run

**No build, test, smoke run, cross-target check, Nix build, devenv output or CI
job has been run for this package.** Nothing in this section is a result. Every
cell describes what has to happen; the driver owns all of it.

### The six compile targets

`zig build check` compiles the libraries, the facade, the tests and the example
for each of these without running any of them (`check_targets`,
`build.zig:425-432`). A successful foreign compile is `build_only`, never a test
pass.

| Target | What a gate would establish | Status |
|---|---|---|
| `x86_64-linux-gnu` | the 113-unit closure compiles and links, and `test` and `smoke` run against the linked route | `PENDING-VERIFICATION` |
| `aarch64-linux-gnu` | the same, compiled for the target | `PENDING-VERIFICATION` |
| `aarch64-macos-none` | the same, compiled for the target | `PENDING-VERIFICATION` |
| `x86_64-windows-gnu` | the same, compiled for the target; a module definition file states the export list | `PENDING-VERIFICATION` |
| `riscv64-linux-gnu` | the same, compiled for the target | `PENDING-VERIFICATION` |
| `wasm32-wasi` | the same, compiled for the target. **Mbed TLS 3.6 is expected to compile here and this build does not refuse it**: the one boundary the platform imposes is expressed where it belongs — `zig/config_gen.zig` turns `MBEDTLS_NET_C` off, so the `mbedtls_net_*` transport has no symbols, and the three tests that drive a loopback socket report `SkipZigTest` rather than failing. Nothing has compiled this yet | `PENDING-VERIFICATION` |

`refused_check_targets` is **empty** and `refusalFor` returns `null` for every
operating system. The refusal mechanism is kept because it is how a target gets
dropped *deliberately* and recorded rather than quietly:
`checkMatrixPartition` (`build.zig:455-474`) panics if either list and
`refusalFor` disagree, so moving a row out of `check_targets` is a change with a
name in it. **No cell may be called passing.** A target with no observed runner
is `build_only` at best, and this package does not even claim that, because
nothing has been compiled.

### The two linkages and the two routes

| Configuration | What a gate would establish | Status |
|---|---|---|
| linked, static delivery | `zig build`, `test` and `smoke` against `libmbedcrypto.a` / `libmbedx509.a` / `libmbedtls.a` | `PENDING-VERIFICATION` |
| linked, shared delivery | the same against the three shared objects and their upstream ABI sonames | `PENDING-VERIFICATION` |
| runtime-loaded | the example and the consumer program run through the resolved table, against an **explicitly named** provider | `PENDING-VERIFICATION` |
| installed C surface | a plain C program compiled against the installed headers and `mbedtls.pc`, in both linkages | `PENDING-VERIFICATION` |
| consumer package | `dep.module("mbedtls")` resolving from a package that did not write it, in both linkages | `PENDING-VERIFICATION` |

A successfully compiled `libmbedcrypto.a` is **not** a facade result, and a
`zig fmt` exit 0 is not a gate. The behavioural proof is the published-standard
answers below: SHA-256 of `"abc"` against FIPS 180-4 Appendix B, HMAC-SHA-256
against RFC 4231 §4.2 case 1, AES-128-CBC against NIST SP 800-38A §F.2.1,
AES-128-GCM against the GCM specification's Test Case 2, ChaCha20-Poly1305
against RFC 8439 §2.8.2, and a real TLS handshake against upstream's own
published test certificate. **No expected value is one this build computed.**

### The gates the driver must run

| Gate | Command | Status |
|---|---|---|
| build | `zig build` | `PENDING-VERIFICATION` |
| tests, Debug | `zig build test` | `PENDING-VERIFICATION` |
| tests, ReleaseSafe | `zig build test -Doptimize=ReleaseSafe` | `PENDING-VERIFICATION` |
| smoke | `zig build smoke` | `PENDING-VERIFICATION` |
| compile matrix | `zig build check` (the six targets above) | `PENDING-VERIFICATION` |
| consumer, nested | `zig build consumer` | `PENDING-VERIFICATION` |
| consumer, entered directly | `cd consumer && zig build run` | `PENDING-VERIFICATION` |
| shared delivery | `zig build test -Dlinkage=dynamic`, `zig build smoke -Dlinkage=dynamic` | `PENDING-VERIFICATION` |
| runtime-loaded route | `zig build smoke -Druntime=true -- --provider <path>` | `PENDING-VERIFICATION` |
| installed closure | `zig build install --prefix out` | `PENDING-VERIFICATION` |
| published platform matrix | `cross-test`, 53 platforms, using `cross-test.profile.sh` | `PENDING-VERIFICATION` |
| provenance | `tools/check-provenance.sh` | `PENDING-VERIFICATION` |
| Nix, static | `nix build .#static` | `PENDING-VERIFICATION` |
| Nix, shared | `nix build .#shared` | `PENDING-VERIFICATION` |
| devenv outputs | `devenv build outputs.static`, `devenv build outputs.shared` | `PENDING-VERIFICATION` |

### Observed: the 53-platform matrix

**`OBSERVED`**, one run, one source state. `cross-test --output
<scratch>/cross/mbed-tls --jobs 8 --build-jobs 8` with the pinned Zig 0.16.0
at `/home/tmp2/gertullj/cache/zig/p/N-V-__8AAFFSVRWqblwBIcA-Yqv-u7sbjsJoww8K0mWaHbmJ/zig`,
run from this tree's root on 2026-10-05. Run id `20261005-202203-22837-9367`.

- **Harness exit code `1`**, status `fail`, `target_count` **53**.
- Harness counts, verbatim: `pass=7 fail=32 build_only=14 partial=0`.
- Per cell, classified by cause: **12 pass**, **0 runtime_fail**, **27
  build_fail**, **14 build_only**, **0 refused**.
- Receipt: `<scratch>/foundation-libs/cross/mbed-tls/cross-test-summary.json`,
  one `build-<target>.log` per cell beside it, and
  `fork-source-digests.txt` for the exact fork-owned sources.

The two readings differ, and the difference matters. The harness counts a cell
whose run exits non-zero as `fail`. Five cells here (`armeb-linux`,
`mips64-linux`, `riscv32-linux`, `riscv64-linux`, `powerpc64-linux`) built the
whole closure and then failed the loopback TLS tests inside `bindAll`
(`zig/root.zig:1419`). Those tests bind the **fixed** ports 39443, 39444 and
39445 (`tests.zig:762`, `:933`, `:1029`), so with eight targets in flight two
emulated cells hold the same port. All five pass at `--jobs 1`, verified
individually (`serial-confirm-summary.json`, harness exit `0` each). That is a
**fixture defect in `tests.zig`, not a platform boundary**, and it is recorded
as a defect.

**The 27 `build_fail` cells, each with a cause:**

| Cause | Cells | Boundary? |
|---|---|---|
| `zig/config_gen.zig` `Params.known` (`config_gen.zig:102-106`) names 14 architectures; `Options.parse` returns `error.UnknownArchitecture` at `config_gen.zig:245` for `aarch64_be`, `hexagon`, `loongarch64`, `mipsel`, `mips64el`, `powerpc64le`, `thumb`, `thumbeb` | 13 | **No.** The fork's own generator. In scope to fix |
| Pinned-toolchain header defects surfaced by `zig translate-c` on this fork's `zig/translate.h`: `generic-netbsd/sys/endian.h:74` (`unknown type name 'pragma'`, 101 errors, 7 cells), `generic-openbsd/time.h:61` (`typedef __size_t size_t` against aro `stddef.h:8`, 3 cells: `arm-openbsd`, `powerpc-openbsd`, `x86-openbsd`), `generic-openbsd/mips64/endian.h:40` (`__MIPSEL__ or __MIPSEB__ must be defined`, 1 cell: `mips64-openbsd`), `any-windows-any/malloc.h:193,221` (`use of undeclared identifier '_ALLOCA_S_MARKER_SIZE'`, 3 errors, 1 cell: `x86-windows`) | 12 | **Yes**, of Zig 0.16.0, evidenced by the toolchain's own file and line |
| `lld-link` leaves the Winsock2 set and `BCryptGenRandom` undefined; `build.zig:771-772` links only `m` and `dl`, while upstream's own `src/library/CMakeLists.txt:225-227` links `ws2_32 bcrypt` on WIN32 | 2 | **No.** Fork build graph. In scope to fix |

**The 14 `build_only` cells** each compiled the full 113-unit closure; the run
step reported `runtime_unavailable`, and per workspace rule a foreign compile is
`build_only`, never a pass. `wasm32-wasi` is among them and **compiled all 113
units cleanly**, with the run step `skipped` and no error, which **confirms** the
expectation recorded above at "The six compile targets": this build does not
refuse that target, and no `setjmp.h` diagnostic appears in
`build-wasm32-wasi.log`. It remains `build_only`, not a pass, because wasmtime is
not installed here and no test ran. The five FreeBSD cells are `build_only` for
the same reason: they were `build_failed` before the `-D__BSD_VISIBLE=1` fix
(`CHANGELOG.md` entry 9) and compile now.

No cell was **refused**: `refused_check_targets` is `[]` and `refusalFor`
returns `null` for every operating system (`build.zig:492-496`).

This section records one observed run and moves nothing else. `PENDING-VERIFICATION`
on the gate table above is the driver's to move.

Add `-j8`, `--cache-dir "$CACHE/mbed-tls/<target>"` and `--summary all` per the
workspace's verification interface.

### The 53-platform matrix, and what `cross-test.profile.sh` states

`cross-test.profile.sh` is settings only. It selects the standard `zig build
test` step (`CROSS_BUILD_STEP=test`), four build jobs, and the two timeouts.
There is deliberately **no** `CROSS_MATRIX` and **no** `TARGETS` array in it: a
matrix named there would replace Zig 0.16.0's published Tier 1/2 table rather
than add to it. Which platforms Mbed TLS supports is a property of this
repository's own build graph, not of a setting — a failing cell is a fact to
diagnose and record, never a reason to drop the cell.

**Two open items in that profile are recorded rather than corrected here**,
because both are the provenance owner's files and neither is a gate:

1. It says the closure is "the 84 translation units of
   `src/library/CMakeLists.txt`'s `src_crypto`, `src_x509` and `src_tls` lists,
   plus the five `3rdparty` units". The real closure is **113**: 81 + 9 + 18 + 5.
   "84" is wrong and should read 108 for the three lists, or 113 for the whole
   closure. [`FORK-NOTES.md`](FORK-NOTES.md) §13.
2. `tools/check-provenance.sh` step 3a cannot succeed against the current
   records, and `UPSTREAM.md:299-311` already says so: the step takes
   `grep -m1 -oE '^[0-9a-f]{64}'` of each file and requires them equal, but
   `UPSTREAM.md` records the release digest in a table row rather than as a bare
   64-digit line. With `set -e` the grep's non-zero exit ends the script at that
   line. Reconciling the two is the integrity-script owner's change. Until it
   lands, `tools/check-provenance.sh` is `PENDING-VERIFICATION` **and is expected
   to fail at step 3a**, which is why the CI workflow asserts that documented
   state rather than a pass.
3. Whether `sha256sum -c UPSTREAM.sha256` tolerates the three leading `#` comment
   lines in that manifest is a question for the **first observed run**, not a
   fact asserted here. This package has not run it.

## Consumption

Four routes. Full detail, with ownership rules and the runtime ABI boundary, in
[`README.zig.md`](README.zig.md).

### From Zig, typed

```zig
// build.zig.zon of a dependent
.dependencies = .{ .@"mbed-tls" = .{ .path = "../mbed-tls" } },

// build.zig of a dependent
const dep = b.dependency("mbed-tls", .{ .target = target, .optimize = optimize });
exe_mod.addImport("mbedtls", dep.module("mbedtls"));
```

```zig
const mbedtls = @import("mbedtls");

// hashing, measured against FIPS 180-4 Appendix B
var digest: [32]u8 = undefined;
try mbedtls.hash(.sha256, "abc", &digest);

// the fixture chain, verified against upstream's own test CA
var ca = mbedtls.Certificate.init();
defer ca.deinit();
try ca.parse(ca_pem);
```

`Hash`, `Aes128Cbc`, `Aes128Gcm`, `ChaCha20Poly1305`, `Entropy`, `Certificate`,
`PrivateKey`, `Socket`, `TlsConfig` and `Endpoint` are the typed surface, each
with an idempotent `deinit` and each naming the upstream `file:line` its
behaviour is read from.

### From Zig, the raw native route

```zig
const c = @import("mbedtls").c; // the translated headers, verbatim
```

`c` is **the whole header-declared Mbed TLS and PSA API** — every function,
type, constant and callback in the eighty public headers `zig/translate.h`
names, with upstream's own types, including the 3.x compatibility shims in
`mbedtls/compat-2.x.h` and the full `psa/crypto.h` surface. The typed facade is
a convenience *over* it, never a replacement for it.

### From C

The installed tree carries the headers, the archives, the generated
configuration and a pkg-config file, so a C consumer needs nothing but an
include path and three `-l` flags:

```c
#include <mbedtls/build_info.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>

unsigned char digest[32];
mbedtls_sha256((const unsigned char *) "abc", 3, digest, 0);
```

```sh
cc prog.c $(pkg-config --cflags mbed-tls) \
   $(pkg-config --libs mbed-tls) -o prog
```

`include/mbedtls/mbedtls_config.h` is the header this library was **built with**,
installed under the name `build_info.h` reaches, so no `-DMBEDTLS_CONFIG_FILE` is
needed by a consumer. Under `-Dlinkage=dynamic`, add
`-Wl,-rpath,<prefix>/lib`.

### With Nix

`package.nix` is the single source-only derivation; `flake.nix` and
`devenv.nix` both call it, so they cannot describe different packages.

```sh
nix build .#static     # libmbedcrypto.a, libmbedx509.a, libmbedtls.a
nix build .#shared     # the three .so objects with upstream's ABI sonames
nix build .#default    # this SDK's own policy: static
devenv shell           # canonical development environment, tools only
devenv build outputs.static
devenv build outputs.shared
```

`flake.nix` publishes five Unix systems. It deliberately does **not** publish
`x86_64-windows`: `package.nix`'s `meta.platforms` names Windows because the
source and the build graph compile for it, but exposing a Nix system is a claim
that a Nix build succeeds there, and no such build has been observed. The gate
is named rather than worked around.

The canonical devenv tasks:

```sh
devenv tasks run sdk:build           # compile and install under an external prefix
devenv tasks run sdk:build:shared    # the same, as shared objects
devenv tasks run sdk:test            # and sdk:test:release-safe, sdk:smoke, sdk:check
devenv tasks run sdk:check:shared    # the six-target compile check, shared delivery
devenv tasks run sdk:consumer        # the separate consumer/ package
devenv tasks run sdk:provenance      # tools/check-provenance.sh
devenv tasks run sdk:package:static  # devenv build outputs.static
```

### Runtime loading

`-Druntime=true` swaps the linked calls for calls through one
process-lifetime table, selected explicitly:

```zig
const mbedtls = @import("mbedtls");

fn start() !void {
    try mbedtls.load(.{ .path = "/usr/local/lib/libmbedtls.so.21" });  // an absolute path
    try mbedtls.load(.{ .system = "libmbedtls.so.21" });                // the soname
}
```

There is no path-to-system fallback, no automatic retry and no unload. Calling
any native entry point before a successful load panics in every optimization
mode, naming the symbol. A provider is classified by **prefix** — every
declaration whose name starts with `mbedtls_` or `psa_` — so nothing can fall out
of the set and no C-library name is ever resolved out of the provider
(`provider_prefix`, `runtime/graph.zig:94`). The load-time checks are the
version family, an entropy context created and destroyed through the same
table, and SHA-256 of `"abc"` against FIPS 180-4 Appendix B — the last of which
is an independent standard answer, not a value this package computed. The full
ABI boundary, including what is deliberately **not** checked, is in
[`README.zig.md`](README.zig.md).

## Licence

Mbed TLS is **`Apache-2.0 OR GPL-2.0-or-later`**, and the choice is the
recipient's. Upstream's own words, at `src/LICENSE:1-4`: "This means that users
may choose which of these licenses they take the code under."
`src/LICENSE` carries **both full texts** — Apache 2.0 at `:9-209` and GPLv2 at
`:215-553` — and `README.upstream.md:317` states the blanket rule: "Unless
specifically indicated otherwise in a file, Mbed TLS files are provided under a
dual Apache-2.0 OR GPL-2.0-or-later license".

**What this package actually ships, read out of the tree rather than assumed:**

* **The whole dual grant, for both groups.** 285 vendored files carry
  `SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later`, and this fork's own
  files are released under the same dual term, with both texts reproduced in
  full in [`FORK-LICENSE.md`](FORK-LICENSE.md). The GPL-2.0-or-later arm is a
  live alternative for any recipient and nothing in this package withdraws it.
* **One arm is what the packaging metadata names.** `package.nix` records
  `meta.license = lib.licenses.asl20`, because that field takes one SPDX
  expression and a disjunction does not fit. The Apache-2.0 arm is recorded
  because it is the permissive one, because it is the arm this fork's own files
  are tagged with, and because it covers the bundled Apache-2.0-only material
  exactly. **That field is a statement about the core library, not an
  inventory**, and [`NOTICE.md`](NOTICE.md) is authoritative.
* **There is no GPL tooling in this tree to keep distinct.** No GPL-only
  toolchain, no GPL-only test harness, no copyleft component outside the
  dual-licensed source. Nothing here needs the "keep the library licence
  distinct from optional GPL tooling" separation, because there is no separate
  GPL tooling to separate. What *is* per-file is recorded below.
* **Four per-file exceptions, and the tree is not one label.**
  `src/3rdparty/everest/` (26 files) is **Apache-2.0 only**, Copyright (c) INRIA
  and Microsoft Corporation, with no GPL alternative offered;
  `src/configs/ext/crypto_config_profile_medium.h` is **BSD-3-Clause**, Arm
  Limited; `src/configs/ext/tfm_mbedcrypto_config_profile_medium.h` is
  **Apache-2.0**, ARM Limited. The fourth is the set of sixteen Everest sources
  that carry a prose notice and **no SPDX tag at all**, named individually in
  [`NOTICE.md`](NOTICE.md) so a scanner cannot read them as unlicensed.
  `tools/check-provenance.sh` fails if Everest's own Apache-2.0 notice ever
  disappears from its sources.
* **43 of the 336 files carry no SPDX tag**, and every one of them is named in
  [`NOTICE.md`](NOTICE.md) under either the blanket statement or its own prose
  notice. "No tag" is not "no grant".

**This fork's own files** — build graph, typed facade, translation header,
per-target configuration generator, runtime route, tests, example, consumer
package, packaging, integrity script and documentation — are released under the
**same `Apache-2.0 OR GPL-2.0-or-later`** term under the owner's per-project
authorization, recorded with both full texts in
[`FORK-LICENSE.md`](FORK-LICENSE.md). Arm, the Trusted Firmware group, The Mbed
TLS Contributors, INRIA, Microsoft Corporation, Manuel Pégourié-Gonnard and Arm
Limited are not claimed as authors of any of them, and the fork's grant adds no
condition to Mbed TLS's.

**Upstream's obligations survive all of it.** A consumer who ships an Mbed TLS
3.6.7 binary, static or shared library, header, or certificate fixture still
owes The Mbed TLS Contributors' notice and the full licence text; a consumer who
redistributes the Everest subtree still owes INRIA's and Microsoft Corporation's
Apache-2.0 notice. `share/licenses/mbed-tls/` is where the five records travel
(`build.zig:405-411`); the Everest notice travels inside its own sources, which
is where upstream put it.

**One deviation is recorded, not tidied away:** `runtime/loader.zig:1` reads
`// SPDX-License-Identifier: MIT`, while every other fork-authored file says
`Apache-2.0 OR GPL-2.0-or-later`. The file is fork code under this repository's
grant like the rest, so this grant covers it — but a scanner would stop at that
line, and it is a smaller grant than the one the file records.
[`FORK-NOTES.md`](FORK-NOTES.md) §12 carries it as an open item for its owner.

## Records

| File | What it holds |
|---|---|
| [`UPSTREAM.md`](UPSTREAM.md) | the pin, the import mechanism, what was and was not taken, the closure as upstream lists it, the handshake fixture's provenance, and the branch-vs-tag reason |
| [`UPSTREAM.sha256`](UPSTREAM.sha256) | all 336 vendored-file digests — the complete set, not a selection |
| [`NOTICE.md`](NOTICE.md) | the per-file licence inventory: 336 upstream files, four per-file exceptions, and every fork-authored file with its tag |
| [`FORK-LICENSE.md`](FORK-LICENSE.md) | the owner's grant for this fork's own files, both licence texts in full, and its limits |
| [`CHANGELOG.md`](CHANGELOG.md) | numbered fork-only changes, entries 1 through 7 |
| [`FORK-NOTES.md`](FORK-NOTES.md) | every decision as condition / symptom / fix / targets bound, plus the open items |
| [`README.zig.md`](README.zig.md) | the Zig interface: the typed surface, the raw C route, the runtime route, ownership, and the ABI boundary |
| [`README.upstream.md`](README.upstream.md) | upstream's own `README.md`, byte for byte, digested as upstream material |
| `.github/workflows/verify.yml` | this fork's own CI: provenance, the native graph in both linkages, the six compile targets, and the consumer package |

No entry in any of them reports a gate result, because no gate has been run.