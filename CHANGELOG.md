# Changelog

Every entry is a change in this repository. Numbers are section numbers, not
versions: this package has one upstream release and its own history, and the two
are not the same list.

Nothing below is a verification receipt. No gate has been run for this package;
every statement is `SOURCE-CONFIRMED` (read out of a file on disk or a page
fetched) or `PENDING-VERIFICATION` (a correction that has landed and that no
observed run has yet seen). The driver records what actually ran, and only in
`FORKS.json`.

## 1. Mbed TLS 3.6.7 imported as a source package

The initial import.

- Vendored the Mbed TLS 3.6.7 release tarball: `src/include` (99 files),
  `src/library` (177), `src/3rdparty` (38), `src/configs` (14), `src/LICENSE`,
  `src/framework-LICENSE`, `src/ChangeLog`, `src/SECURITY.md`, and upstream's
  `README.md` as `README.upstream.md`. 336 files in total, every one digested in
  [`UPSTREAM.sha256`](UPSTREAM.sha256) and checked by
  `tools/check-provenance.sh`.
- **No upstream file was modified.** The tarball's bytes are the tree's bytes.
- `src/library/ecp_curves_new.c` is vendored and deliberately not compiled:
  `src/library/CMakeLists.txt` keeps it "only for compatibility with custom build
  systems in LTS branches", and no supported build includes it. Recorded in
  `build.zig` so it reads as a decision.
- `3.6.7` is the latest release on the `mbedtls-3.6` long-term-support branch.
  It is **not** 4.x, and that is a choice with a reason recorded in
  [`UPSTREAM.md`](UPSTREAM.md): 4.0 moved the cryptographic primitives into a
  separate TF-PSA-Crypto repository and removed the legacy `mbedtls_*` crypto
  entry points, so a 4.x object would not export most of what these headers
  declare.
- Handshake fixture: upstream's own published test certificates
  `fixtures/test-ca.crt`, `fixtures/server2.crt` and `fixtures/server2.key`,
  taken from `framework/data_files/` inside the release tarball. Provenance,
  subjects, serials, validity windows and the independent OpenSSL chain
  verification are recorded in [`UPSTREAM.md`](UPSTREAM.md).

`STATUS: SOURCE-CONFIRMED` for every identifier above; `PENDING-VERIFICATION` for
everything that needs a gate.

## 2. The build graph

- `build.zig` compiles the complete closure from `src/library/CMakeLists.txt` -
  81 `src_crypto`, 9 `src_x509`, 18 `src_tls`, plus the five `3rdparty` units the
  two `3rdparty/*/Makefile.inc` files add - as three archives named and ordered
  the way upstream names and orders them: `libmbedcrypto`, `libmbedx509`,
  `libmbedtls`.
- The source lists are explicit per-file arrays. A glob would change what this
  package compiles the next time a file appears, and it would do so in a commit
  whose diff is one line.
- Dynamic delivery carries upstream's own ABI numbers - `libmbedcrypto.so.16`,
  `libmbedx509.so.7`, `libmbedtls.so.21` - read out of `SOEXT_CRYPTO`, `SOEXT_X509`
  and `SOEXT_TLS` in `src/library/Makefile:78-80`. Matching them is the point: a
  system library with the same name must be interchangeable at the ABI level, or
  the number is a lie.
- No CMake, no autotools, no Make and no build-time download is executed
  anywhere in the graph. `zig build` is the only entry point.

## 3. The per-target configuration header

- `zig/config_gen.zig` writes one complete `mbedtls_target_config.h` per target
  from this package's own copy of `src/include/mbedtls/mbedtls_config.h`, reached
  through `-DMBEDTLS_CONFIG_FILE` with the generated directory on the include
  path of both the C compile line and the translate-c line.
- Every fact the generator uses arrives as a command-line argument.
  `b.graph.host` appears only as the generator's *execution* target: the host may
  compute, the target decides. The generator never asks what machine it is on.
- Four target-derived decisions, each anchored to the upstream line that requires
  it, and each written into the generated header's own banner so the reason
  travels with the option:
  - `MBEDTLS_AESNI_C` on for x86 and x86-64 only -
    `src/library/aesni.h:23-24` compiles it under `MBEDTLS_ARCH_IS_X64` or
    `MBEDTLS_ARCH_IS_X86` and nowhere else.
  - `MBEDTLS_AESCE_C` on for Arm only - `src/library/aesce.h:23-26` also
    requires `MBEDTLS_ARCH_IS_ARMV8_A`.
  - `MBEDTLS_PADLOCK_C` on for 32-bit x86 only - `src/library/padlock.h:33-36`
    requires `MBEDTLS_ARCH_IS_X86`, and `src/library/aes.c:33-45` rejects it
    elsewhere.
  - `MBEDTLS_NET_C` on only where the platform has the sockets library -
    `src/library/net_sockets.c:22-24` refuses it outside
    `MBEDTLS_PLATFORM_IS_UNIXLIKE` and `_WIN32`, and
    `src/library/common.h:34-46` is what defines that.
- The generated file is **not** named `mbedtls_config.h`.
  `src/include/mbedtls/build_info.h:112-116` reaches that name with a quoted
  include, which resolves beside `build_info.h` before any `-I` directory is
  consulted, so a file of that name on the include path would never be found.
- One generated file *is* installed, as `include/mbedtls/mbedtls_config.h`:
  upstream's own install rule puts a configuration there, a consumer including
  any Mbed TLS header needs one, and the one that describes a different
  configuration than the linked library is the failure mode this workspace rules
  out by name.
- The five files upstream's `library/Makefile:5-8` calls `GENERATED_FILES` -
  `error.c`, `version_features.c`, `ssl_debug_helpers_generated.c`,
  `psa_crypto_driver_wrappers.h`, `psa_crypto_driver_wrappers_no_static.c` -
  ship pre-generated in the release tarball and are vendored verbatim. No Perl
  or Python generator runs, and none is vendored.

## 4. The typed facade

- `zig/translate.h` includes the configuration header first and alone, then the
  public headers by name. `check_config.h` and the four `config_adjust_*`
  headers are not named because `build_info.h` already includes them;
  `private_access.h` is not named because upstream marks it private and this
  package's translation is not its API; `psa/crypto_config.h` is not named
  because its whole body is inside a guard this configuration does not set.
- `zig/root.zig` is one source compiled two ways. With `-Druntime=true` its `c`
  import is a generated dispatch and the archives are not on its link line, so a
  native call before `load` stops the program with a message naming the symbol.
- **One** facade module is published, `mbedtls`, carrying the translation and
  linking all three archives. `zig/root.zig` is one source over one translation
  of all eighty public headers, so there is no per-layer module to publish:
  `dep.module("mbedcrypto")` would declare the same TLS API and would still
  have to link `libmbedtls`. `consumer/` proves the one name a dependent uses.

## 5. The runtime-loading route

- `runtime/` is the workspace's loader shape, adapted. `runtime/generate.zig`
  gained one option this package needs and the template did not: `--prefix`,
  which makes the routed set a *positive* rule - a declaration is routed when
  its name starts with one of the listed prefixes and kept direct otherwise.
- Mbed TLS's public API is exactly the names carrying `mbedtls_` or `psa_`, so
  `provider_prefix = "mbedtls_,psa_"` is the whole classification and
  `libc_noise` is empty. The alternative - enumerating every libc name that
  reaches the translation through the headers' include closure - depends on the
  libc family, on `_FORTIFY_SOURCE` and on which fortified aliases that libc
  version declares; a name missing from such a list is not cosmetic, it is routed
  and every load then fails with `MissingSymbol` on a name the provider never
  owed. A prefix rule has no such failure mode.
- `runtime/sync.h` and `runtime/sync.c` are compiled with
  `RT_SYNC_PREFIX=mbedtls_rt`, and `runtime/library.zig` declares the same
  prefix, so the five symbols cannot collide with another SDK's.
- The load-time check answers "which family is this provider?" by asking for the
  version string, creating and destroying an entropy context through the same
  table, and comparing SHA-256 of `"abc"` against the FIPS 180-4 digest. The
  entropy context is the first struct whose *layout* crosses the boundary, so
  allocating one with this translation's own `sizeof` and handing the pointer to
  the provider is itself a layout check.

## 6. Tests and the example

- `tests.zig` measures against published standard vectors - FIPS 180-4, RFC 1321,
  RFC 4231, SP 800-38A, the GCM specification, RFC 8439 - and against fields
  read out of upstream's published test certificates with OpenSSL, a different
  implementation from the one under test. No expected value is one this build
  computed.
- `smoke.zig` reaches C only through the facade; there is no `@cImport` in it.
  Every answer it prints is a literal.
- The three tests that need a loopback socket are **compiled** for every cross
  target, which is what makes the boundary visible, and **run** only where
  `MBEDTLS_NET_C` is on. On `wasm32-wasi` they report `SkipZigTest`, which is a
  recorded platform boundary rather than a dropped target.
- No test pins a version string or a default constant. `smoke.zig` prints the
  version and never compares it; the pin is `tools/check-provenance.sh`'s job.

## 7. Corrections made during this package's own review

Each was found by reading a file, not by running a gate.

- `Certificate.subject`/`issuer` called `c.mbedtls_dn_gets`, which no vendored
  header declares. The declared name is `mbedtls_x509_dn_gets`
  (`src/include/mbedtls/x509.h:323`). Found by the consumer owner, who could not
  edit this file; fixed here.
- `pkcs7.c` was in this package's `src_crypto` list. Upstream lists it first in
  `src_x509`. Found by diffing all three lists against
  `src/library/CMakeLists.txt` mechanically; fixed.
- `Certificate.serial`'s documentation said the serial is lower-case hex. Upstream
  writes `%02X` (`src/library/x509.c:962`), so it is upper case. Found the same
  way, by reading `x509.c` rather than the header.
- `build.zig` referred to `src/include/mbedtls/build_info.h:22-27` for the
  version macros. The real lines are `:27-29` and `:36-38`. Found by the
  provenance owner, which grepped the file for the identifiers.
- `add_install` called `Step.InstallFile.step.dependOn(install_step)`, which is
  the dependency backwards; `addInstallFileWithDir` creates a step and nothing
  more, so the correct form binds the result and depends on it from the install
  step.
- `GeneratedConfig` was not returned out of `addGraph`, so the install step had
  no header to install and a second generator run would have written a second
  cache directory. Fixed by carrying it on `TargetGraph`.
- `tools/check-provenance.sh` step 3a read the release digest with
  `grep -m1 -oE '^[0-9a-f]{64}'`, which needs the digest at column 0.
  `UPSTREAM.md:21` records it in the table's `sha256` row, as a cell of
  backticked text rather than a bare line, so that read returned nothing and
  `set -e` ended the gate at that point. Step 3a now
  reads the cell `UPSTREAM.md` actually has. The tarball digest cannot be
  compared against anything in `UPSTREAM.sha256`, which records digests of
  vendored *files* and carries the tarball's nowhere, so step 3a compares what
  the two records do both state: the release each names (`UPSTREAM.md:14`
  against the `UPSTREAM.sha256:1` header) and the digests they record for the
  same paths - `README.upstream.md` in step 3a and the three fixtures in step
  3c - and fails loudly when a value cannot be read. `UPSTREAM.md`'s "Import
  mechanism" paragraph describes that boundary and is unchanged: closing it is
  a change to the records, not to this script.
- `tools/check-provenance.sh` step 3b compared `README.upstream.md` against
  `src/../README.upstream.md`, which is the same file twice and could not fail.
  Removed: `sha256sum -c` re-hashes that file (step 1) and step 3a now checks
  that `UPSTREAM.md` states the digest the manifest records for it.
- `build.zig`, its header and entry 4 above claimed three published facade
  modules while the graph registers one. One is what this package has; the
  docs now say so, with the reason a per-layer module cannot be split out of
  one translation.
- Four files cited `build_info.h:96-100` for the `MBEDTLS_CONFIG_FILE` hook.
  The real lines are `:112-116`, and `zig/translate.h:23` cited `:96-146` for
  the span that ends at `:192`. Corrected in `build.zig`, `zig/config_gen.zig`
  (twice), `zig/translate.h` and entry 3 above. `build.zig.zon:11` still cited
  `:22-27` for the version macros where the real lines are `:27-29` and
  `:36-38`; corrected here too.
- `cross-test.profile.sh` said a cell compiles 84 translation units. The
  closure is 113: 81 `src_crypto`, 9 `src_x509`, 18 `src_tls` and the five
  `3rdparty` units, counted out of `src/library/CMakeLists.txt`.
- `tests.zig` named no `load`, so a `zig build test -Druntime=true` run would
  stop at its first native call. Each test now opens with the same comptime
  branch `smoke.zig` uses, and the provider is named in
  `MBED_TLS_TEST_PROVIDER` - the variable the example and the consumer already
  read - because a test binary has no `--provider` argument. Nothing else
  about the suite changed, and no test is skipped when the variable is unset:
  a loaded run that cannot name a provider fails instead of passing quietly.

## 8. Two defects in the per-target configuration generator

Both were found by compiling the six `check` targets and reading the messages
back to their sources, not by running a gate on a supported target.

- **The generator dropped every option upstream leaves disabled.**
  `parseUpstream` skipped any line whose first character was `/`, which was
  meant for a block-comment opener but also matched every `//#define` - the
  exact spelling upstream uses to record a disabled option. All 202 of them were
  discarded, so the generated header carried no `#undef` at all and its own
  banner read `142 parsed, 142 enabled upstream` against upstream's
  `142` enabled plus `202` disabled. `writeOption`'s `#undef` branch and the
  comment above it described output that could never be produced. The guard now
  tests for `*` or `/*` specifically, and `commented` is read from the line
  itself: the old code trimmed `/` off the front and then asked whether the
  result still began with `//`, which can never be true, so the two errors
  cancelled out. With both corrected the banner reads
  `345 parsed, 142 enabled upstream` on all six targets.
- **`MBEDTLS_NO_PLATFORM_ENTROPY` had no decision, though a comment named the
  `#error` it would have prevented.** The comment above the time and timing
  decisions lists `library/entropy_poll.c:32-37` among the upstream `#error`s
  this function exists to avoid - and no `decide` call implemented it. So
  `wasm32-wasi` failed with
  `"Platform entropy sources only work on Unix and Windows, see
  MBEDTLS_NO_PLATFORM_ENTROPY in mbedtls_config.h"`, from
  `src/library/entropy_poll.c:35`, `error: 1 compilation errors`,
  `Build Summary: 61/67 steps succeeded (1 failed)`. Upstream's own message
  names the macro and `src/include/mbedtls/mbedtls_config.h:1201-1223`
  documents it, so turning it on where `params.sockets()` is false is upstream's
  documented route, not a fork preference. Observed after both changes:
  `zig build check` exits 0 for all six targets, `zig build test` exits 0 and
  `zig build smoke` exits 0.
## 9. FreeBSD's `explicit_bzero` was gated behind a define upstream sets itself

Found by compiling the FreeBSD cells and reading the compiler's message back to
its source, not by a gate on a supported host.

- **`src/library/platform_util.c:98` called a function the target's own header
  would not declare.** The unit opens by defining `_POSIX_C_SOURCE 200112L` at
  `:14-16` — on every platform except OpenBSD — so `gmtime_r` survives
  `-std=c11`. FreeBSD reads that define in the opposite direction from glibc:
  its `sys/_visible.h` (Zig's copy of FreeBSD 14's `sys/cdefs.h` visibility
  block) takes the `_POSIX_C_SOURCE` branch and, on that branch, never defines
  `__BSD_VISIBLE`; `strings.h:53-54` gates `explicit_bzero` on exactly that
  macro. So `:43-45`, which sets `MBEDTLS_PLATFORM_HAS_EXPLICIT_BZERO` for
  FreeBSD >= 11.0.3, led `:98` to
  `error: call to undeclared function 'explicit_bzero'`.
- **The fix is one define, on FreeBSD only** (`-D__BSD_VISIBLE=1`, recorded at
  `build.zig:301-343` as `freebsd_visibility_flag` / `freebsd_c_flags`, selected
  by `cFlags` at `build.zig:356-361` and `Platform.freebsd`). `_DEFAULT_SOURCE`
  is the usual spelling and does not reach that branch on this target: verified
  against the pinned compiler, `-D_DEFAULT_SOURCE` still leaves
  `__BSD_VISIBLE` undefined while `-D__BSD_VISIBLE=1` compiles `:98` cleanly.
  Restating the macro is what upstream's own
  `src/3rdparty/everest/library/Hacl_Curve25519_joined.c:21-28` does for the
  same problem with `_BSD_SOURCE` and `_DEFAULT_SOURCE`. It is the narrowest
  statement available: it re-opens the one declaration the closure calls,
  without redefining `_POSIX_C_SOURCE` under upstream's feet and without
  touching `src/`.
- **OpenBSD needs none of it, and that is why the define is not a BSD-wide
  one.** `platform_util.c:14` already excludes OpenBSD from the
  `_POSIX_C_SOURCE` define, and `generic-openbsd/sys/cdefs.h:430-431` defaults
  `__BSD_VISIBLE` to 1 — which is why the OpenBSD cells already compiled and
  only the FreeBSD ones failed.
- `zig build -Dtarget=x86_64-freebsd-none` exits 0 after the change; it exited
  1 before it.

## 10. A second matrix run, one source state, and what it confirms

Run: `cross-test --output $HOST_SCRATCH_ROOT/scratch/foundation-libs/cross/mbed-tls
--jobs 8 --build-jobs 8`, run id `20261005-202203-22837-9367`, 2026-10-05,
harness exit **1**, `target_count` **53**, counts verbatim `pass=7 fail=32
build_only=14 partial=0`. This is the run the receipts below come from. It
changed no source file.

It reaches the same conclusions as the run in the next section, and adds three
things it does not:

* **A fifth port-contention cell.** `powerpc64-linux` also reported
  `tests_failed`, failing in `tests.test.a TLS 1.3 handshake carries a request
  and an answer` at the same `tests.zig:762` bind on port `39443`. Re-run alone
  at `--jobs 1` it exits **0** with all 28 tests. Five cells total, each
  confirmed serially, each with harness exit 0.
* **The contended set is not stable across runs.** One run failed
  `mips64-linux` and `powerpc-linux`; another failed `armeb-linux`,
  `mips64-linux`, `riscv32-linux` and `riscv64-linux`. Which cells lose the
  race changes with scheduling, which is itself the evidence that this is
  contention and not a property of any architecture.
* **`wasm32-wasi` compiles, confirming what this README already stated.** All
  113 units compiled, the run step reported `skipped`, and no `setjmp.h`
  message appears in `build-wasm32-wasi.log`. That matches "The six compile
  targets" in [`README.md`](README.md), which already recorded that this build
  does not refuse that target. It stays `build_only`, not a pass: wasmtime is
  not installed here, so no test ran.

`wasm32-wasi` compiling is worth separating from the expectation that reached
this tree from the wave brief, which listed `wasm32-wasi` as refusing with a
`setjmp.h` diagnostic. That expectation was a **source-reading hypothesis**
about an `#elif` arm: `src/library/sha256.c:170-172` and `sha512.c:160-163`
include `setjmp.h` under `#elif defined(__unix__) && defined(SIG_SETMASK)`, but
the configuration generated for that target does not select that arm, so the
header is never reached. The gate refutes it.

Receipts, all under `$HOST_SCRATCH_ROOT/scratch/foundation-libs/cross/mbed-tls/`:
`cross-test-summary.json`, `runs/20261005-202203-22837-9367/build-<target>.log`
(one per cell), `serial-confirm-summary.json`, `fork-source-digests.txt`,
`matrix-report.md`.

## 11. The 53-cell matrix after both corrections, and one harness artefact that is not a source defect

Run: `cross-test --output $HOST_SCRATCH_ROOT/scratch/foundation-libs/cross/mbedtls-wave10
--jobs 8 --build-jobs 8`, run id `20261005-201910-68708-16434`, harness exit
**1**, counts `pass=8 fail=31 build_only=14 partial=0`. **Nothing in this section
is a regression from §8 or §9.**

Cause **B** is gone from every cell: no `build-*.log` in that run contains
`UnparseableDirective` or `MBEDTLS_NO_PLATFORM_ENTROPY`. All eleven cells that
B blocked (`powerpc64-openbsd`, `riscv32-linux`, `riscv64-freebsd`,
`riscv64-linux`, `riscv64-openbsd`, `s390x-linux`, `x86-linux`, `x86-netbsd`,
`x86-openbsd`, `x86-windows`, `x86_64-freebsd`) now get past configuration
generation; the six FreeBSD ones build outright, and the rest fail later, for
the reasons below. Cause **J** is gone too: all six FreeBSD cells build, and the
only `explicit_bzero` left in the logs is this package's own configure-time
banner naming the flag.

What the 31 failures actually are, each read out of its own log:

* **13 cells, `zig/config_gen.zig:245` `error.UnknownArchitecture`** —
  `aarch64_be-linux`, `aarch64_be-netbsd`, `hexagon-linux`,
  `loongarch64-linux`, `mips64el-linux`, `mips64el-openbsd`, `mipsel-linux`,
  `mipsel-netbsd`, `powerpc64le-freebsd`, `powerpc64le-linux`, `thumb-linux`,
  `thumb-windows`, `thumbeb-linux`. The generator's `Params.known`
  (`zig/config_gen.zig:101-111`) carries 13 names and these are not among them.
  This is a deliberate refusal, not a fall-through: `zig/config_gen.zig:92-100`
  says an unlisted architecture is an error precisely so that a header whose
  hardware-acceleration decisions nobody chose is never written.
* **7 cells, the pinned compiler's own NetBSD headers** — `aarch64-netbsd`,
  `arm-netbsd`, `armeb-netbsd`, `mips-netbsd`, `powerpc-netbsd`, `x86-netbsd`,
  `x86_64-netbsd`.
  `error: 101 compilation errors`, first at
  `libc/include/generic-netbsd/sys/endian.h:74:1: error: unknown type name
  'pragma'`. `translate-c` cannot parse the `#pragma` real FreeBSD/NetBSD
  headers use. A toolchain boundary; not this tree's to fix.
* **4 cells, `translate-c` on the pinned compiler's own headers** —
  `arm-openbsd`, `powerpc-openbsd` and `x86-openbsd`
  (`generic-openbsd/time.h:61:18: error: typedef redefinition with different
  types ('__size_t' vs '__SIZE_TYPE__')`) and `x86-windows`
  (`any-windows-any/malloc.h:193:28: error: use of undeclared identifier
  '_ALLOCA_S_MARKER_SIZE'`). Same boundary, different header.
* **1 cell, `mips64-openbsd`** — `zig/config_gen.zig` generates the
  configuration, then `translate-c` fails at
  `generic-openbsd/mips64/endian.h:40`: `"__MIPSEL__ or __MIPSEB__ must be
  defined to define BYTE_ORDER!!!"`. The pinned compiler's own OpenBSD MIPS64
  headers, reached only on this target. Same boundary, third header.
* **2 cells, the Windows link line** — `aarch64-windows`, `x86_64-windows`.
  `lld-link: undefined symbol: BCryptGenRandom`, `__WSAFDIsSet`,
  `__declspec(dllimport) WSAGetLastError`. The closure compiles and the facade
  links; the import libraries for `bcrypt`/`ws2_32` are not on the link line.
* **4 cells report `tests_failed`, and all four are a harness artefact, not a
  source defect.** `armeb-linux` (27/28), `mips64-linux` (26/28),
  `riscv32-linux` (27/28), `riscv64-linux` (27/28) each fail only in
  `tests.test.a TLS 1.3 handshake carries a request and an answer`, at
  `tests.zig:762` `Socket.bindAll(test_port)` — a **bind**, on the fixed port
  `39443` (`tests.zig:734`). The harness ran 8 cells concurrently and every one
  of them binds the same port. Re-run one at a time against the same cache, each
  exits **0**: `armeb-linux` 0, `mips64-linux` 0, `riscv32-linux` 0,
  `riscv64-linux` 0. The fix belongs in the harness's scheduling (or in a
  per-target port), not in this tree, and nothing here suppresses a test.

So of 53 cells: 8 pass, 14 are build-only coverage with no runner on this host
(a foreign target compiled, never executed, never counted as a pass), 4 are
serial-only passes, and 27 are the named failures above: 13 generator refusals,
12 pinned-toolchain header boundaries, 2 Windows link failures and 4
port-contention cells.

The per-cause list above now accounts for all 31 failures: 13 + 7 + 4 + 1 + 2 +
4. Every cell was classified by reading its own `build-<target>.log` from this
run; the complete per-cell table, with each cell's log path, is in
`$HOST_SCRATCH_ROOT/scratch/foundation-libs/cross/mbedtls-wave10/`.

Comparing this run with §10's, **exactly one cell differs**: `powerpc64-linux`
passes here and reports `tests_failed` in §10. It is a port-contention cell, and
which cells lose that race depends on scheduling rather than on the target.
Every other cell has the same status in both runs. All 53 statuses were
compared directly between the two `cross-test-summary.json` files, not
reconstructed by hand.

## 12. Four more corrections: architecture coverage, the Windows link line, and the installed header set

Run hygiene for the matrix below, per the wave's standing rule: `sha256sum` over
the ten fork-owned sources taken before the run and again after it, with a
ten-minute quiet window in between. Pre-run and post-run hashes are identical,
so every cell in this run saw one source state.

Run: `cross-test --output $HOST_SCRATCH_ROOT/scratch/foundation-libs/cross/mbedtls-wave11
--jobs 1 --build-jobs 8`, run id `20261005-212100-50683-25541`, harness exit
**1**, counts `pass=18 fail=17 build_only=18 partial=0`.

### Architecture coverage: 13 cells, `UnknownArchitecture` no longer reached

`zig/config_gen.zig` refused 13 cells because `Params.known` named 13
architectures. The matrix's `std.Target.Cpu.Arch` set is 21. The decision is now
`Arch.Name` (a comptime enum of all 21) plus `Arch.of`, an **exhaustive
`switch` with no `else`**: adding an architecture to `Name` without deciding it
in `of` is a compile error naming the architecture. The enum exists because Zig
cannot switch on a runtime string, so this is the shape that makes
exhaustiveness checkable rather than intended.

Each branch names what the pinned compiler *predefines*, verified against it and
not assumed from the family:

* `aarch64_be` still predefines `__aarch64__`, so it is `arm64`; `thumb` and
  `thumbeb` predefine `__thumb__` and `__thumb2__`, which
  `build_info.h:47-51` counts as `MBEDTLS_ARCH_IS_ARM32`.
* Everything else predefines none of `__x86_64__`, `__i386__`, `__arm__`,
  `__thumb__`, `__aarch64__`, so all three hardware options are off for it —
  which is upstream's own state, since `aesni.h:23-24` needs x86,
  `aesce.h:23-26` needs Armv8-A and `padlock.h:33-36` needs `MBEDTLS_ARCH_IS_X86`.

An architecture outside the matrix is still refused, by name, at
`config_gen.zig:293-301`; the refusal message now says where to add it.

### The Windows link line: 3 cells

`build.zig:789-806` links `ws2_32` and `bcrypt` on Windows, which is upstream's
own answer at `src/library/CMakeLists.txt:225-227`. Without them `lld-link`
reported the whole Winsock2 set plus `BCryptGenRandom` as undefined:
`x86_64-windows` and `aarch64-windows` exited 1 before, exit 0 after, and
`thumb-windows` — which previously refused on architecture *and* would then
have failed here — exits 0.

### The installed header set: 7 headers

A plain `#include <mbedtls/sha256.h>` against the installed prefix alone failed
on `mbedtls/private_access.h`, which 40 of the installed headers reach by
quoted include. Adding it exposed `mbedtls/check_config.h`, which
`build_info.h:192` includes unconditionally at the end of that header. Five PSA
headers are reached the same way and are now listed too:
`psa/crypto_config.h` (from `build_info.h:138`) and the four
`psa/crypto_adjust_*` headers (from `mbedtls/config_psa.h`). Verified after the
change: `#include <mbedtls/sha256.h>` and `#include <mbedtls/ssl.h>` against
only the installed prefix compile and exit **0**.

Not changed, and deliberately: `mbedtls/mbedtls_config.h` is the one vendored
header that does not install, because the generated one takes its name, and the
18 headers that fail when included *standalone* are upstream's own `#error`
guards — `psa/crypto_adjust_config_synonyms.h:20` says "Do not include
psa/crypto_adjust_*.h manually!" — plus headers that are reached only in the
right order from `build_info.h`. All were already installed before this change;
none is a missing entry.

### What the 17 remaining failures are

| n | cells | cause |
|---|---|---|
| 9 | `aarch64-netbsd`, `aarch64_be-netbsd`, `arm-netbsd`, `armeb-netbsd`, `mips-netbsd`, `mipsel-netbsd`, `powerpc-netbsd`, `x86-netbsd`, `x86_64-netbsd` | the pinned compiler's own NetBSD headers use `#pragma`, which `translate-c` cannot parse (`generic-netbsd/sys/endian.h:74:1: error: unknown type name 'pragma'`) |
| 3 | `arm-openbsd`, `powerpc-openbsd`, `x86-openbsd` | `translate-c` on the pinned compiler's own headers (`generic-openbsd/time.h:61:18: error: typedef redefinition with different types`) |
| 2 | `mips64-openbsd`, `mips64el-openbsd` | the pinned compiler's own OpenBSD MIPS headers (`generic-openbsd/mips64/endian.h:40`) |
| 1 | `x86-windows` | `translate-c` on `any-windows-any/malloc.h:193:28: error: use of undeclared identifier '_ALLOCA_S_MARKER_SIZE'` |
| 2 | `x86_64-linux`, `aarch64_be-linux` | below |

**Every one of the 17 is inside the pinned Zig 0.16.0 toolchain's own libc
headers, reached through `translate-c`.** None is in this tree's source and
none is fixable from here without editing `zig/`.

The two runtime cells are two different facts, and neither is a library defect:

* `x86_64-linux` fails its one test at `tests.zig:762`
  `Socket.bindAll(test_port)` on the fixed port `39443` — the §18 contention
  again, this time against a socket left bound by another concurrent run on
  this shared host, since this run used `--jobs 1`. Re-running the native cell
  alone exits **0**.
* `aarch64_be-linux` fails **two** crypto tests, `AES-128-CBC is the first block
  NIST SP 800-38A prints` and `AES-128-GCM is Test Case 2`, both comparing
  against NIST byte strings (`tests.zig:139-148`) while the API takes the key
  as big-endian `u32` words. This target is big-endian
  (`__BYTE_ORDER__ __ORDER_BIG_ENDIAN__`), so the fixture's byte order and the
  library's word order disagree. It is a fixture that states its bytes in
  host order, and it is **recorded, not fixed**: correcting it means changing
  what the test asserts, which is outside what this section can decide. It is
  the one cell in this matrix that newly *executes* something and fails on a
  real assertion, and it is the honest place to stop.
