# FORK-NOTES — the decisions, what each cost, and what is still open

Every entry is **condition / symptom / fix / targets bound**, as the workspace's
horizon learning mandate requires, so a later wave in another directory, library
or toolchain version can apply the lesson without re-deriving it.

Two things this file is not. It is not a verification receipt: **no gate has
been run for this package**, and nothing here reports a result. And it is not
the build or the licence record — those are [`CHANGELOG.md`](CHANGELOG.md) and
[`NOTICE.md`](NOTICE.md). What it is: why each decision was made, what it cost,
and what a later wave has to know before touching it.

Status vocabulary: `SOURCE-CONFIRMED` (read out of a file on disk, never
executed), `PENDING-VERIFICATION` (a correction has landed and no observed run
has seen it), `CONSTRAINT` (a binding design rule with no observation behind
it), `HYPOTHESIS` (reasoned and unexecuted).

## 1. `certificates` and `ciphersuites` are answers, not constants, and the split is the point

* **Condition.** `zig/root.zig` publishes two header-declared C accessors that
  Mbed TLS's own build computes: `mbedtls_version_get_string` and
  `mbedtls_version_check_feature` (`src/include/mbedtls/version.h:40`, `:70`).
  Both were the obvious candidates for a wrapper that *restates* a value.
* **Symptom (the trap).** A facade that returns the pinned `3.6.7` literal, or
  that returns a `bool` from `mbedtls_version_check_feature`, has re-derived a
  value upstream defines. The first lies the moment a dependent links a
  differently configured build; the second has to invent an answer for the
  `-2` the function returns when feature checking was not compiled in at all
  (`version.h:66-72`).
* **Fix.** `versionString` asks the library and hands back the bytes with the
  terminating NUL removed, refusing a buffer shorter than the "at least 9 bytes"
  the header documents (`version.h:38`) rather than truncating into it.
  `hasFeature` returns `?bool`: `true` for 0, `false` for -1, `null` for -2 and
  for a name that is empty or contains a NUL. Neither function consults
  `build.zig.zon`, which is a build-input record and not a runtime answer. The
  same rule is why `tests.zig` compares nothing against `versionNumber()`: a
  number read out of `build_info.h` compared against the library's own copy is
  the library agreeing with itself, which is provenance, not behaviour. The pin
  is `tools/check-provenance.sh`'s job.
* **Targets bound.** Bounded to this package's facade. The general rule is the
  workspace's: a facade never re-derives a value upstream defines. A different
  toolchain version does not re-open it, because the shape of the answer comes
  from the C, not from Zig.

## 2. The generated configuration is per target, and its name cannot be `mbedtls_config.h`

* **Condition.** Mbed TLS's configuration is the feature set **and** several
  struct layouts, buffer sizes and preconditions. Upstream's answer is a Perl
  `Configure` script that asks the host's questions and writes into the source
  tree. This package runs neither.
* **Symptom.** Three failures, each of which a checked-in header or a
  host-derived one would produce. (a) One header for every target, and the
  target-dependent options are not cosmetic: `src/library/aes.c:32-42` `#error`s
  if `MBEDTLS_PADLOCK_C` is set on a target that is not 32-bit x86, and
  `src/library/net_sockets.c:22-24` `#error`s if `MBEDTLS_NET_C` is set
  anywhere that is neither unix-like nor Windows. (b) Copying host platform
  macros onto a cross target — the failure this workspace rules out by name — is
  exactly what a header generated on the build machine from the build machine's
  answers is. (c) Hand-maintaining a second copy of upstream's 4 446-line
  `mbedtls_config.h` makes every re-sync a re-audit of four hundred lines
  instead of a diff.
* **Fix.** `zig/config_gen.zig` runs on the build machine and takes the
  **resolved target's** facts as command-line arguments: arch, OS, ABI,
  endianness, pointer width, and the target's own triple for the banner.
  **`builtin.target` appears nowhere in it** (`zig/config_gen.zig`, whole file),
  so the host cannot decide anything; `b.graph.host` appears only as the
  generator's *execution* target. It re-emits every option name, value,
  enabled-or-disabled decision and their order from this package's own copy of
  upstream's header, so the generated file can be read beside upstream's and a
  changed decision is a changed line. Upstream's documentation comments are
  dropped — the generated header is an input to a C compiler, and carrying 4 000
  lines of prose into every build's output would bury the four decisions that
  actually differ. The four decisions are `MBEDTLS_AESNI_C`
  (`aesni.h:23-24`), `MBEDTLS_AESCE_C` (`aesce.h:23-26`), `MBEDTLS_PADLOCK_C`
  (`padlock.h:33-36`) and `MBEDTLS_NET_C` (`net_sockets.c:22-24` with
  `common.h:34-46`), each written into the generated banner so the reason
  travels with the option.
* **The name.** The generated file is `mbed_tls_target_config.h`, reached
  through `-DMBEDTLS_CONFIG_FILE`. It deliberately is **not**
  `mbedtls_config.h`, because `build_info.h` reaches that name with a *quoted*
  include at `src/include/mbedtls/build_info.h:112-116`, which resolves beside
  `build_info.h` before any `-I` directory is consulted — a file of that name on
  the include path would never be found, and the build would silently use
  upstream's default configuration instead. The hook is upstream's own, and
  using it means the generated header cannot shadow anything.
* **Both lines, not one.** The generated directory is on the include path of
  **both** the C compile line and the `translate-c` line, and
  `generated.header.addStepDependencies(&lib.step)` makes the step that writes
  the header a dependency of every step that reads it. An installed header is
  not on the compile line: a path without the edge would let the archive be
  served from the build cache out of a run in which a different target had
  written that directory.
* **One generated file is installed, and it is the one upstream's own install
  rule wants.** `include/mbedtls/mbedtls_config.h` is the generated header under
  the name the headers reach it by, so a dependent needs **no compile macro at
  all**. The failure this rules out by name is a consumer compiling against a
  configuration that describes a different feature set than the library it
  links.
* **Targets bound.** Bounded to this package's `zig/config_gen.zig` and the four
  decisions above, against the four upstream lines named. A re-sync within the
  3.6 LTS line keeps the same three upstream anchors; a re-sync to 4.x changes
  them and re-opens this entry.

## 3. The runtime route classifies by prefix, and an exclusion list would have a failure mode a prefix rule cannot have

* **Condition.** `zig/translate.h` reaches eighty public headers, whose include
  closure drags in the C library's `stdio`, `time`, `socket` and `string`
  surface. A runtime-loaded build must route Mbed TLS's own declarations through
  the loader and keep the C library's direct — a C-library symbol must never be
  resolved out of the provider, because the provider *depends* on the C library.
* **Symptom (the trap).** The obvious implementation is an exclusion list: name
  every libc symbol the translation reaches through the headers' include
  closure, and treat the rest as the provider's. That list depends on the libc
  family, on `_FORTIFY_SOURCE`, and on which fortified aliases that libc version
  declares — none of which this package controls and all of which change with the
  target. **A name missing from such a list is not cosmetic**: it is routed, the
  provider never owed it, and every single load then fails with `MissingSymbol`
  on a name the consumer never intended to ask a TLS library for. The failure
  would appear as "Mbed TLS cannot load", which points at the wrong thing
  entirely.
* **Fix.** `provider_prefix = "mbedtls_,psa_"`
  (`runtime/graph.zig:94`) and `libc_noise = ""` (`:104`). A declaration is
  routed when its name starts with one of the listed prefixes and **kept direct
  otherwise**, so the C-library half is direct by construction rather than by
  being named somewhere that can fall out of step. A prefix rule has no
  "forgot to add it" failure mode.
* **`--prefix` is an option this package's generator needed and the shared shape
  did not have.** It makes the routed set a *positive* rule. The
  `provider_optional` and `provider_excluded` lists are both **empty** and are
  written out rather than omitted, so adding a header with an optional or
  deliberately-direct entry point is a change in that file with a name in it.
* **`RTLD_LOCAL` is part of the same reasoning.** The loader opens with
  `.{ .NOW = true, .GLOBAL = false }` (`runtime/loader.zig:579-584`): `NOW` so a
  provider with missing dependencies fails where the failure can be reported
  rather than at the first call, and `GLOBAL = false` so loading a provider does
  not add its symbols to the global namespace, where a second SDK's lookup could
  find them.
* **Targets bound.** Bounded to `runtime/graph.zig`'s classification for this
  SDK. It is reusable for any SDK whose public API is a name prefix, which is
  most of them; it does not apply to a library whose exported names are not
  prefix-distinguishable, and that case needs a different rule with the same
  discipline about stating it.

## 4. No system-library mode, and the refusal is a panic rather than a fallback

* **Condition.** AGENTS.md §4 requires system mode to use the **real selected
  system headers**, or an explicitly required and verified identical header and
  ABI version, and forbids bundling new-release headers against an older
  installed library. It also requires recording a fork with no system mode as
  **vacuous, not satisfied**.
* **Symptom (the trap).** Mbed TLS's struct layouts and buffer sizes are
  **compile-time constants read out of the configuration header**, not
  run-time negotiation. `mbedtls_entropy_context`
  (`src/include/mbedtls/entropy.h:106-112`) holds
  `MBEDTLS_ENTROPY_MAX_SOURCES` sources (20 at `:58`); `mbedtls_ssl_context`
  (`ssl.h:1731`) is a large struct whose field types are
  configuration-dependent. A system library built with a different
  `mbedtls_config.h` has a **different struct under the same name**, and every
  offset the C code reads through them is wrong — a silent memory-corruption
  class, not a link error. So the obvious "let me try a system build" is a mode
  that can only be wrong in the most expensive way.
* **Fix.** There is no system mode in this package. `-Dsystem=true` and
  `-fsys=mbedtls` both resolve through `b.systemIntegrationOption("mbedtls", …)`
  and then **panic at configure time** with that reason
  (`build.zig:1159-1167`). The refusal is *before* any graph is built, so a
  system-mode spelling can never quietly produce a bundled library.
* **The `consumer` step resolves the mode too**, so
  `zig build consumer -fsys=mbedtls` reaches the same refusal rather than
  silently proving the bundled graph a second time under a system-mode name
  (`consumer/build.zig:59-73`, and the `Graph`-sharing comment there for why
  the flag reaches a dependency unchanged).
* **What a future system mode would owe, if one is ever wanted:** the *real*
  installed headers on the compile line **and** the translation line, a
  configuration header that is the installed library's own rather than a
  generated one, a version-and-layout check that refuses a configuration this
  graph did not describe, and a recorded ABI family. It is not a `-D` flag; it
  is a second build graph. The vacuity of the rule is recorded here rather than
  presented as compliance.
* **Targets bound.** Bounded to this package. The rule is general: any C library
  whose public structs are layout-dependent on its configuration header cannot
  have a system mode that translates bundled headers.

## 5. The external ABI a loaded provider must satisfy, and what is not checked

* **Condition.** Resolving the symbols proves the provider has those names. It
  says nothing about whether the consumer and the provider agree about anything
  else, and Mbed TLS's answer to "which options were you built with" is a
  run-time query (`mbedtls_version_check_feature`) rather than a layout
  negotiation.
* **Symptom (the trap).** Three plausible-but-wrong ways to close this. (a) Trust
  the version string: `MBEDTLS_VERSION_STRING_FULL` is a compile-time constant
  (`build_info.h:38`), so a provider built with a *different* configuration
  reports the same string and has different struct layouts. (b) Call
  `mbedtls_psa_crypto_config_check` behind `MBEDTLS_SELF_TEST`: it is upstream's
  own check for this family, and its self-test path calls **`exit`**, so a loader
  that must answer `ValidationFailed` cannot use it — the process dies instead
  of returning an error. (c) Enumerate every layout-relevant configuration
  option to check each one: that is a second copy of a 4 446-line
  `mbedtls_config.h`, and it would be a copy that goes stale silently.
* **Fix.** Three checks, all in `runtime/library.zig:229-285`, each one whose
  failure this code can actually observe.
  1. **Family.** `mbedtls_version_get_string_full` (`version.h:51`) copies
     `MBEDTLS_VERSION_STRING_FULL` verbatim (`src/library/version.c:25-29`) and
     the result must begin `"Mbed TLS 3.6."`. The **prefix**, not the whole
     `"Mbed TLS 3.6.7"`: a patch release inside the same LTS line is the same
     ABI family, and this package is pinned to one patch, not one minor.
  2. **Layout, by allocating through it.** One `mbedtls_entropy_context` is
     allocated with **this translation's own `sizeof`** and handed to the
     provider, then destroyed. It is the first struct whose layout crosses the
     boundary, so this is a real layout check and not a formality. The free
     happens here rather than at process exit, which is what keeps the check
     from leaking if it fails.
  3. **An independent cryptographic answer.** SHA-256 of `"abc"` must equal the
     FIPS 180-4 Appendix B digest. The constant is a published standard value,
     not something this package computed, so a provider whose SHA-256 is
     broken, stubbed, or answering through a driver it does not have is refused
     **here** rather than discovered inside a caller's handshake.
* **What remains an obligation on the caller, stated as such:** the rest of the
  configuration (every other public struct's layout and every buffer size); the
  allocator, which is the provider's and which no Zig-side check can bound; and
  the callbacks, which cross in both directions and are called with the
  provider's own calling convention. `README.zig.md` §"The runtime route" lists
  all seven items.
* **Mbed TLS 4.x and 2.28 are refused by name**, before anything is published.
  4.0 moved the primitives into a separate TF-PSA-Crypto repository and removed
  the legacy `mbedtls_sha256_*`, `mbedtls_gcm_*` and `mbedtls_rsa_*` entry
  points, so a 4.x object fails on `MissingSymbol` before any check runs; 2.28
  is a different ABI because its configuration is older and it has no TLS 1.3.
* **Targets bound.** Bounded to Mbed TLS 3.6.x with the configuration
  `zig/config_gen.zig` generates, on Zig 0.16.0. A re-sync to 4.x re-opens the
  whole entry, which is why the pin is a branch and not just a tag.

## 6. The `mbedtls-framework` submodule is absent, and the tree says so instead of faking it

* **Condition.** The release tarball does not carry the `mbedtls-framework`
  Git submodule. Upstream's own words at `README.upstream.md:57`: it "is not
  needed to consume a release archive (zip or tar)".
* **Symptom (the trap).** With no `framework/` directory, upstream's
  `src/library/Makefile:12-23` **refuses to build** — it looks for
  `$(MBEDTLS_PATH)/framework/exported.make` and errors when it is missing. That
  reads like a broken vendored tree. A plausible "fix" is to vendor a stub
  `framework/`, which would be inventing upstream material.
* **Fix.** Vendored nothing that is not in the tarball, and recorded the absence
  three ways: `UPSTREAM.md` names what the archive does not bring; `CHANGELOG.md`
  entry 1 records it; and `build.zig` never runs that makefile, so its guard is
  upstream's own and is never reached. There is no `framework/`, no `scripts/`
  and no `programs/` here, and the example programs the upstream README refers
  to are not in the release archive.
* **The related fact, which is the same shape:** five files are named
  `GENERATED_FILES` at `src/library/Makefile:5-9` and upstream's own build can
  regenerate them with Perl and Python. **All five ship pre-generated in the
  release tarball** (`README.upstream.md:61`) and are vendored verbatim, so no
  generator runs here and none is vendored — because none is in the tarball. The
  one file this build *does* generate is the configuration header, and that is a
  different thing with a different reason (§2).
* **Targets bound.** Bounded to the `mbedtls-3.6.7` release tarball. A
  development-branch import would carry neither the submodule nor the
  pre-generated files, and both absences would then be defects rather than
  facts.

## 7. Why 3.6 and not 4.x, and why the pin is a branch

* **Condition.** The project has split: cryptography moved to a separate
  TF-PSA-Crypto repository that Mbed TLS consumes as a submodule, and "Mbed TLS
  has been split between two products: TF-PSA-Crypto for cryptography, and Mbed
  TLS for X.509 and (D)TLS". With the split, "most legacy cryptography APIs
  have been removed", and CMake became the only supported build system with the
  GNU Make and Visual Studio project builds removed. Read from
  `docs/4.0-migration-guide.md` on upstream's `development` branch,
  2026-10-05, and recorded in [`UPSTREAM.md`](UPSTREAM.md).
* **Symptom.** A "newest release" import would be a **different ABI and a
  different archive layout** than the one every existing consumer links. A 4.x
  object does not export most of what these headers declare, so a 4.x tree
  under this package's name would fail on `MissingSymbol` — or worse, compile
  and then disagree about struct layouts.
* **Fix.** Pin the `mbedtls-3.6` LTS line, at tag `mbedtls-3.6.7`, and say why.
  A 3.6 consumer keeps the `mbedtls_*` legacy crypto entry points, the PSA entry
  points, and the `mbedcrypto` / `mbedx509` / `mbedtls` archive names it already
  links against. Pinning the LTS line also gives the pin a maintenance horizon:
  bug and security fixes "until at least March 2027" per the release body.
* **The pin is recorded with its identity**: tag object
  `627361b09e6f6e3eac756297a370a591cf310ab9`, commit
  `068ff080b369adfac81509f9b57b2afabaf82dc5`, released 2026-07-07, artifact
  `mbedtls-3.6.7.tar.bz2`, 5 473 689 bytes, sha256
  `a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6`,
  cross-checked against upstream's own published `mbedtls-3.6.7-sha256sum.txt`.
  The tag object is **unsigned** — `verification.reason` is `unsigned` — which
  is a fact about the tag, not a defect in this import, and is recorded rather
  than omitted.
* **Targets bound.** Bounded to the 3.6 LTS line. Quarterly, and on any CVE, per
  the workspace's sync rule. A re-sync within 3.6 keeps the same three artefacts
  and the same licence inventory; **a re-sync to 4.x is not a re-sync at all**.

## 8. The exported surface is a naming convention, not a catalogue

* **Condition.** The three archives export roughly 1 500 symbols, and the public
  API is exactly the names carrying `mbedtls_` or `psa_`.
* **Symptom (the trap).** A hand-maintained export list is a second copy of the
  API that can omit a declaration the installed headers carry, and the omission
  is invisible until a dependent fails to link. The mirror packages in this
  workspace that name each symbol explicitly are correct but expensive: adding a
  header upstream means editing the list in the same change, and forgetting is
  silent.
* **Fix.** On ELF, a generated version script exports `mbedtls_*`, `psa_*`,
  `PSA_*` and `MBEDTLS_*` and marks everything else `local`
  (`setVersionScript`, `build.zig:725-739`). On Windows, a generated module
  definition file states the same four patterns (`build.zig:658-667`), which is
  how a COFF export list is expressed. **Neither is a list**, so a header that
  adds a symbol needs no change to either, and the constants (`MBEDTLS_*`) ride
  in with the functions rather than being enumerated separately — the mistake a
  single-symbol list makes.
* **A capability boundary, stated rather than hidden:** on Mach-O there is no
  equivalent this build can rely on, so a shared object on Darwin also exports
  upstream's internal symbols. `Platform.describe` (`build.zig:521-529`) prints
  which route a target takes on the configure line, so `zig build` says it
  without anyone reading the graph. A caller on Darwin must therefore select by
  name rather than by "is this symbol present".
* **Targets bound.** Bounded to the ELF and COFF routes. The Darwin and COFF
  internal-export behaviour is a property of the object format and the missing
  `__declspec` split, not of this build graph.

## 9. The 53-platform matrix is not narrowed by a profile, and a failing cell is a fact to record

* **Condition.** `cross-test.profile.sh` is trusted Bash the harness sources, so
  it is settings only: no command, no compiler probe, no host path. The
  published 53-platform Zig 0.16.0 Tier 1/2 table is the matrix.
* **Symptom (the trap).** A `TARGETS` array in a profile is a quiet narrowing: it
  looks like coverage, it is a subset, and nothing in the output says which. The
  same goes for a `CROSS_MATRIX` that **replaces** the published table rather
  than adding to it. A CI job that shells out to `cross-test` and tolerates its
  absence turns a missing gate into a green one.
* **Fix.** Neither list is in the profile. `CROSS_BUILD_STEP=test` states the
  standard step explicitly and leaves runner selection to the harness, so a
  foreign target with no executor is reported as **`build_only`** — compiled,
  never executed, never a pass — rather than counted. `.github/workflows/
  verify.yml` does not invoke `cross-test` at all, and says so in its own
  header: it is a host-local tool with its own runner detection and scratch
  policy, and wrapping a job that invoked a path a GitHub runner does not have
  in an availability check would turn a missing gate green.
* **Four build jobs and a 3 600 s build timeout** are deliberate, not incidental:
  each cell compiles the whole 113-unit closure and several of those units
  (`ecp_curves.c`, `ssl_tls.c`, `psa_crypto.c`, `ssl_msg.c`) are among the
  largest C files in the tree.
* **Which platforms Mbed TLS supports is a property of this repository's own
  build graph, not of a setting.** `zig/config_gen.zig` derives `MBEDTLS_NET_C`
  from the target's OS by the same rule `src/library/common.h:34-46` applies to
  `MBEDTLS_PLATFORM_IS_UNIXLIKE` and `src/library/net_sockets.c:22-24` enforces.
  A cell that fails is a fact to diagnose and record; it is not a reason to drop
  the cell, sample the tests, or remap Debug to an optimized mode to make it
  pass.
* **Targets bound.** Bounded to Zig 0.16.0's published Tier 1/2 table and this
  package's build graph. A different toolchain version publishes a different
  table and re-opens this entry.

## 10. The allocator belongs to the C library, so the test framework is not a leak oracle

* **Condition.** `mbedtls_calloc` and `mbedtls_free`
  (`src/library/platform.c:44-55`) are libc `calloc`/`free` through
  `mbedtls_platform_set_calloc_free` (`platform.c:57-63`) unless a platform hook
  is set, and `MBEDTLS_PLATFORM_C` is enabled by the generated configuration.
* **Symptom (the trap), both directions.** Running the suite under
  `std.testing.allocator` would report the library's internal allocations as
  leaks, because those allocations never pass through the testing allocator. The
  reverse mistake is worse: installing the testing allocator and treating its
  report as covering everything would hide a real leak inside Mbed TLS itself.
  Both produce a confident wrong answer.
* **Fix.** Neither claim is made. `tests.zig`'s header says plainly that
  `testing.allocator` is not a leak oracle here, and what the suite *can*
  observe — every **ownership transition** this package's own wrappers own — is
  checked explicitly: a second `deinit` is a no-op, a closed wrapper stops
  answering, and a wrapper built from a borrowed value has **no `deinit` at
  all**. Every test that creates a context releases it on every path, including
  the failing one.
* **The public contract is guarded with an ordinary comparison, never a
  `std.debug.assert`.** `error.BadKeyLength` and `error.OutputLengthWrong` are
  error values a caller can handle, because a caller that asked for the wrong
  length has a bug that a truncated result would hide.
* **Targets bound.** Bounded to this package's tests. It is a general property
  of every C library in this workspace that owns its allocator, and it is why
  AGENTS.md §4 forbids treating the test framework as a leak oracle for memory
  that crosses into a third-party allocator.

## 11. `tests.zig` is not written for the loaded route, and that is an open item

* **Condition.** A `-Druntime=true` test binary reaches every native call through
  a table that nothing has published, and a call before `load` **panics in every
  optimization mode**, naming the symbol (`runtime/generate.zig:1019-1022`).
* **Symptom.** `tests.zig` names no `load`, no `MBED_TLS_TEST_PROVIDER` and no
  `runtime_loaded` — read out of the file, whole. A `zig build test
  -Druntime=true` would therefore reach its first `mbedtls.hash` call and stop
  there. `smoke.zig` and `consumer/src/main.zig` both handle the branch
  explicitly (`smoke.zig:101-104`, `consumer/src/main.zig:238-240`); the suite
  does not.
* **Fix, so far.** The loaded route's behavioural coverage is `smoke.zig` and
  the consumer program, and `README.zig.md` says exactly that rather than
  claiming the suite runs through the dispatch. The honest completion is for the
  suite's root to gain the same `if (comptime mbedtls.runtime_loaded)` branch the
  example and the consumer already have, with the provider named on the command
  line or in `MBED_TLS_TEST_PROVIDER`, and then for
  `zig build test -Druntime=true` to be a real gate. That is the test owner's
  change, not this file's, and it is recorded as open rather than claimed.
* **What must not happen:** a `-Druntime=true` test run must not be reported as
  a pass by skipping the suite, and the suite must not gain a branch that
  catches the load error and returns success. A missing gate is `build_only`, and
  a gate that degrades itself into a no-op is worse than one that is absent.
* **Targets bound.** Bounded to `tests.zig` in this package. A different
  toolchain version does not re-open it; a change to the pre-load panic does,
  because a build that no longer panics would fail **silently** instead of
  stopping, which is a much worse symptom to diagnose.

## 12. `runtime/loader.zig` carries `SPDX-License-Identifier: MIT`, and that is a deviation

* **Condition.** Fourteen fork-authored files carry
  `SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later` on their own first
  comment line. `runtime/loader.zig:1` reads `// SPDX-License-Identifier: MIT`.
* **Symptom.** A consumer scanning for licences reads that line and stops. MIT is
  a **smaller grant** than the one the rest of the package records, and it is
  narrower than the file's own status as fork code under this repository's
  [`FORK-LICENSE.md`](FORK-LICENSE.md) grant. A scanner would report a fact
  about the file's text, and a downstream tool that gates on SPDX identifiers
  would draw a conclusion that is wrong.
* **Fix, and it is not this file's to make.** `runtime/loader.zig` is the
  **reusable** half of the loader — the state machine and platform layer, holding
  no per-SDK name — and it is a copy that other SDKs in this workspace carry. A
  blanket rewrite of its identifier is a change to every SDK that shares the
  file, which is a decision above this package. The honest record is what
  [`NOTICE.md`](NOTICE.md) already carries: the deviation is named, the file's
  owner is identified, and **this inventory reports what the file says and does
  not edit it**. The reconciliation is a separate change with its own
  `CHANGELOG.md` entry.
* **The load-bearing part of the file is unaffected.** What the file declares is
  the loader's own contract; the grant that covers the code is this
  repository's, and it is broader than the tag on that one line.
* **Targets bound.** Bounded to `runtime/loader.zig` as shared across SDKs. If
  the shared loader's identifier is reconciled, this entry closes in the change
  that does it, together with the corresponding `NOTICE.md` paragraph.

## 13. Open items, each with what it needs

Six, in the order a later wave will hit them. None is a gate result; each is a
defect or a gap that was found by reading a file.

### 13.1 `tools/check-provenance.sh` step 3a cannot succeed against the current records

* **Found by** running `grep -m1 -oE '^[0-9a-f]{64}'` against both records, which
  is what the step does.
* **The defect.** Step 3a requires each file to open its digest material with a
  bare 64-digit line and requires the two to be equal. `UPSTREAM.sha256`'s first
  digest line is `README.upstream.md`'s; `UPSTREAM.md` records the **release**
  digest `a7e8bcbe…d11f6` in a **table row** that begins with `| sha256 |`, so
  the grep finds nothing. With `set -euo pipefail` the grep's non-zero exit ends
  the script at that line, before the `[ -n "$digest_md" ]` check can report
  anything. **The release digest does not appear in `UPSTREAM.sha256` at all** —
  that file records *vendored-file* digests, not the tarball's.
* **Already recorded.** [`UPSTREAM.md`](UPSTREAM.md), "Import mechanism", names
  this and says reconciling the two is the integrity-script owner's change. This
  entry restates it so a reader of the fork notes does not have to go looking.
* **What the fix is.** One of two honest shapes, both in the script's owner's
  files: make the step extract the release digest from `UPSTREAM.md`'s table row
  (or from a named key) rather than requiring a bare line, **or** record the
  release digest in a form both files can grep identically. Nothing in
  `UPSTREAM.md` or `UPSTREAM.sha256` should be weakened to satisfy a grep.
* **Consequence until fixed.** `tools/check-provenance.sh` is
  `PENDING-VERIFICATION` **and is expected to fail at step 3a**.
  `.github/workflows/verify.yml` asserts that documented state rather than a
  pass, which is the honest edit; it does not add `|| true`, because a tolerated
  check is not a check.
* **Targets bound.** Bounded to `tools/check-provenance.sh` and the two records.

### 13.2 `cross-test.profile.sh` says "84 translation units"; the closure is 113

* **Found by** counting the four source lists in `build.zig` against
  `src/library/CMakeLists.txt`.
* **The defect.** The profile's comment says "the 84 translation units of
  `src/library/CMakeLists.txt`'s `src_crypto`, `src_x509` and `src_tls` lists,
  plus the five `3rdparty` units". The real counts are **81** `src_crypto`,
  **9** `src_x509`, **18** `src_tls` — 108 for the three lists, and **113** for
  the whole closure including the five `3rdparty` units. "84" matches nothing in
  this tree. It is a comment, so it changes no behaviour, but it is the number a
  reader uses to size a cell.
* **The fix.** Correct the comment to 113 (or 108 for the three lists and state
  the five separately). The profile is the cross-test owner's file; it is not
  edited here.
* **Targets bound.** Bounded to that one comment. It is re-checked on any re-sync,
  because a re-sync within 3.6 keeps the same three lists and a 4.x re-sync
  changes them entirely.

### 13.3 `build.zig`'s module comment describes three published modules; one is published

* **Found by** reading `build.zig`'s module doc against its own
  `addGraph`.
* **The defect.** The module header at `build.zig:20-24` says "Three facade
  modules - `mbedcrypto`, `mbedx509`, `mbedtls`" and suggests a dependent ask
  for `dep.module("mbedcrypto")` for the primitives. The code registers **one**
  module by name when `public` — `b.addModule(tls_name, …)` at `build.zig:811` —
  and the comment immediately above it says so: "Only the fully layered one is
  registered by name when `public`". `CHANGELOG.md` entry 4 repeats the
  three-module claim.
* **What is true.** `dep.module("mbedtls")` is the one published module; the
  three **artifacts** are separately addressable as `dep.artifact("mbedcrypto")`,
  `dep.artifact("mbedx509")` and `dep.artifact("mbedtls")`. A dependent that
  wants only the primitives links the `mbedcrypto` artifact, or writes its own
  one-line module over it. `README.md` and `README.zig.md` state the true shape.
* **The fix.** Correct the two comments. It is a documentation change in files
  this slice does not own.
* **Why it matters beyond tidiness.** A dependent that follows the module
  comment writes `dep.module("mbedcrypto")` and gets a build error naming a
  module that does not exist — which is at least loud, but the fix is not
  obvious from the error.
* **Targets bound.** Bounded to the two comments.

### 13.4 `tools/check-provenance.sh` step 3b compares `README.upstream.md` with itself

* **Found by** reading the step.
* **The defect.** Step 3b runs
  `cmp -s README.upstream.md src/../README.upstream.md`. Both paths resolve to
  the same file — `src/../README.upstream.md` is the repository root's copy — so
  the comparison is a tautology that cannot fail. Its stated purpose is "the
  preserved upstream README is byte-identical to the imported one", and as
  written it checks nothing.
* **What actually covers the bytes.** Step 1, `sha256sum -c UPSTREAM.sha256`,
  does cover them: `UPSTREAM.sha256:4` records
  `6ea15aafaf9765a730b651eeb5376bf54b646c5ee5fcc6b7c80d6d0d209a3fb4` for
  `README.upstream.md`, and a checksum run fails on a changed file. So the
  coverage exists; the step is a redundant no-op wearing a comment that claims
  otherwise.
* **The fix.** Either delete step 3b and let step 1 carry the claim, or give it
  a second real path to compare against. What must not happen is leaving a check
  that reads as a guarantee and is not one.
* **Targets bound.** Bounded to `tools/check-provenance.sh`.

### 13.5 `build.zig.zon` still cites the old line range for the version macros

* **Found by** reading `build.zig.zon` against `src/include/mbedtls/build_info.h`.
* **The defect.** The manifest's comment at `build.zig.zon:12` cites
  `build_info.h:22-27` for the version macros. The real lines are **`:27-29`**
  (`MBEDTLS_VERSION_MAJOR`, `_MINOR`, `_PATCH`), which is what
  `CHANGELOG.md` entry 7 already corrected elsewhere in the tree and what
  `build.zig:103-104` cites. One comment still carries the pre-correction range.
* **Consequence.** None: a comment cannot misconfigure anything, and the
  configure-time check in `build.zig` compares against the values, not the
  comment.
* **The fix.** Update the comment. The provenance owner's file.
* **Targets bound.** Bounded to that comment.

### 13.6 Whether `sha256sum -c UPSTREAM.sha256` tolerates the manifest's comment lines is unobserved

* **Found by** reading the manifest, not by running the command.
* **The question.** `UPSTREAM.sha256` opens with three `#` comment lines
  (`:1-3`) and its digest lines follow. Whether `sha256sum -c` treats those
  comment lines as ignorable or as improperly formatted is a property of the
  tool on the host, and **this package has not run it**. With GNU coreutils a
  non-`--strict` run ignores improperly formatted lines with a warning, but
  that is a statement about the tool's documented behaviour, not an observation
  here, and a different `sha256sum` need not behave the same way.
* **Why it is recorded.** `tools/check-provenance.sh` step 1 is
  `sha256sum -c --quiet UPSTREAM.sha256 || fail …`. If a host's `sha256sum`
  treats a comment line as an error, step 1 fails on a **pristine** tree, which
  would look exactly like a provenance defect and is not one. The first observed
  run settles it either way.
* **The fix, if it is needed.** Strip comments before the check, or generate the
  manifest without them. Not this slice's file.
* **Targets bound.** Bounded to the first run of the provenance gate on a
  particular host's coreutils.


### 13.7 Four files cite `build_info.h:96-100` for the `MBEDTLS_CONFIG_FILE` hook; the real lines are `:112-116`

* **Found by** reading the quoted include out of
  `src/include/mbedtls/build_info.h` directly.
* **The defect.** The hook this package's whole generated-configuration design
  rests on is at `build_info.h:112-116`:

      #if !defined(MBEDTLS_CONFIG_FILE)
      #include "mbedtls/mbedtls_config.h"
      #else
      #include MBEDTLS_CONFIG_FILE
      #endif

  Four places cite `:96-100` for it: `build.zig:40` (the module doc),
  `zig/config_gen.zig:70` (the module doc) and `:372` (the generated header's
  own banner, which is the one place it ships to every build's output), and
  `CHANGELOG.md` entry 3. Lines 96-100 of that file are an unrelated block that
  defines `inline` for ARMCC and MSVC.
* **Why it matters more than a stale comment elsewhere.** The generated
  header's banner is a build artefact: it is written into the build cache on
  every compile of every target, and a reader who follows its citation to
  `:96-100` finds text that has nothing to do with the hook. `translate.h:23`
  has the same shape one level out, citing `:96-146` for the whole
  configuration-reading span, which actually runs to `:192`.
* **Consequence for the build.** None. Nothing parses these citations; the
  hook is found by name at preprocessor time and `build.zig` passes the macro
  regardless.
* **The fix.** Correct the five ranges. Two are in the configuration
  generator's owner, one in the build graph's, one in the changelog; the
  banner's is the one worth doing first because it ships.
* **Targets bound.** Bounded to those five citations, and to any re-sync that
  moves the hook — which a 4.x import certainly would, since that release
  restructured the configuration system entirely.

## 14. Four corrections found by reading files, and what each cost

Recorded in [`CHANGELOG.md`](CHANGELOG.md) entry 7. Listed here with the shape
of the mistake, because the shape recurs.

1. **`Certificate.subject`/`issuer` called `c.mbedtls_dn_gets`, which no
   vendored header declares.** The declared name is `mbedtls_x509_dn_gets`
   (`src/include/mbedtls/x509.h:323`). *Cost:* a compile error, which is the
   cheap kind. *Shape:* a name remembered from an earlier Mbed TLS version
   rather than read out of the header in this tree.
2. **`pkcs7.c` was in the `src_crypto` list.** Upstream lists it first in
   `src_x509` (`src/library/CMakeLists.txt:97-107`). *Cost:* the same file
   compiled into the wrong archive, which links because both archives are on the
   line — a silent layering error that upstream's own `library/Makefile` order
   would have caught. *Shape:* a list transcribed by hand from the wrong
   direction. The fix that catches it is mechanical: diff all three lists
   against `CMakeLists.txt`, which is what was done.
3. **`Certificate.serial`'s documentation said lower-case hex.** Upstream writes
   `%02X` (`src/library/x509.c:962`), so it is upper case. *Cost:* a wrong
   documented value, found by reading `x509.c` rather than trusting the header's
   silence. *Shape:* a claim about behaviour with no `file:line` behind it. Every
   behaviour claim in `zig/root.zig` now carries one.
4. **`add_install` called `Step.InstallFile.step.dependOn(install_step)`, which
   is the dependency backwards**, and `GeneratedConfig` was not returned out of
   `addGraph`, so the install step had no header to install and a second
   generator run would have written a second cache directory. *Cost:* a missing
   installed header and a duplicated generation, both silent. *Shape:* an API
   whose return value is the whole effect, dropped. `addInstallFileWithDir`
   *creates* a step and nothing more; dropping the result builds nothing and
   installs nothing, with no error. That is now written out at the three call
   sites.

## 15. What this package deliberately does not have

Each is a gap with a reason, listed so a reader does not have to infer it from
an absence.

* **No system-library mode.** §4. Refused at configure time, not absent by
  oversight.
* **No typed PSA Crypto key lifecycle.** `psa_crypto_init`, the key slots, the
  secure-element drivers and `psa/crypto_se_driver.h` are in the translation and
  reachable through `c`. A PSA key is owned by a slot table inside the library,
  so a wrapper whose `deinit` could be skipped would leak a **slot**, not a
  pointer. No wrapper is offered whose failure mode is undocumented.
* **No typed DTLS.** The DTLS configuration and timer entry points are
  reachable through `c`. No wrapper claims DTLS, and `Socket` is a stream
  transport only.
* **No upstream test suite, and none is fetched to fake one.** The release
  tarball does not carry `framework/`, so it carries no suite either. This
  package's own `tests.zig` is 27 tests measured against published standard
  vectors and upstream's published certificates, and it is the only suite here.
  Upstream's suite is never deleted or replaced; there is nothing to delete.
* **No Nix build published for `x86_64-windows`.** `package.nix`'s
  `meta.platforms` names Windows because the source and the build graph compile
  for it, but `flake.nix` publishes only five Unix systems. Exposing a system is
  a claim that a Nix build succeeds there, and no such build has been observed.
  The gate is named rather than worked around.
* **No `.fingerprint` in either manifest.** A package fingerprint is an
  identifier the Zig toolchain *derives* for a named package; deriving one means
  running the compiler, and no gate has been run. Any value written now would be
  an invented identifier. The first observed `zig build` reports the value the
  toolchain computes for `.mbed_tls`; the driver records it in the same change.
  Nothing in this package's source, build graph or tests reads it.
* **No `devenv.lock` and no `flake.lock` in `build.zig.zon` `.paths`.** Both are
  driver-owned, and naming a path that is not there would make `zig fetch` hash a
  missing entry. `flake.lock` is present in the tree; `devenv.lock` is not, and
  its absence is why `.paths` does not name it.

## 16. What a later wave must re-check

* **Every re-sync**, quarterly and on any CVE: download the new tarball, verify
  its published sha256 against upstream's own checksum asset, replace the
  imported files, and update `UPSTREAM.sha256`, `UPSTREAM.md`, `NOTICE.md` and
  `README.md` with a numbered `CHANGELOG.md` entry **in one change**. A re-sync
  within 3.6 keeps the same three artefacts and the same licence inventory.
* **The four licence exceptions**, on every re-sync: the Everest subtree's
  Apache-2.0-only notice, `crypto_config_profile_medium.h`'s BSD-3-Clause line,
  `tfm_mbedcrypto_config_profile_medium.h`'s Apache-2.0 line, and the sixteen
  untagged Everest sources. `NOTICE.md` is an inventory and has to be re-read
  whenever the file set changes.
* **The 113-unit count**, if the lists move.
* **The four `config_gen` decisions**, against their four upstream anchors.
* **The three test ports** (`39443`, `39445`, and the example's `39501`), if a
  test needs a new one: a port collision is a non-zero exit with no retry, which
  is deliberate.
* **The namespace prefix** `mbedtls_rt` in two spellings — `runtime/graph.zig:83`
  names it and `:217` passes it as a macro, and a build where they disagree does
  not link, which is the whole error report.
* **The FreeBSD `-D__BSD_VISIBLE=1`** (§17) against the pinned compiler's own
  `generic-freebsd/sys/_visible.h`: if a future Zig re-sync changes which
  branch defines `__BSD_VISIBLE`, the define becomes either redundant or
  wrong, and the FreeBSD cells are what say so.

## 17. A vendored unit's own feature-test define can hide the libc declaration it then calls

* **Condition.** `src/library/platform_util.c:14-16` defines
  `_POSIX_C_SOURCE 200112L` itself — except on OpenBSD — to keep `gmtime_r`
  alive under `-std=c11`. `:43-45` then turns
  `MBEDTLS_PLATFORM_HAS_EXPLICIT_BZERO` on wherever the target advertises the
  function, and `:98` calls it. On glibc `_POSIX_C_SOURCE` and `_GNU_SOURCE`
  cooperate and `<string.h>` declares `explicit_bzero`; on FreeBSD the same
  `_POSIX_C_SOURCE` is what *removes* the declaration.
* **Symptom.** `error: call to undeclared function 'explicit_bzero'`, one line
  in, on FreeBSD only. Nothing in the message names the feature-test macro, and
  the define sits 80 lines above the call inside a vendored file that must not
  be edited — so the obvious reading ("upstream bug, patch upstream") is both
  forbidden here and unnecessary.
* **Fix.** Restate the declaration environment the target's headers narrowed:
  `-D__BSD_VISIBLE=1` on FreeBSD (`build.zig:301-343`, `cFlags` at
  `build.zig:356-361`). Read out of the compiler's own headers:
  `generic-freebsd/strings.h:53-54` gates the prototype on `__BSD_VISIBLE`, and
  `generic-freebsd/sys/_visible.h:123-166` shows that the `_POSIX_C_SOURCE`
  branch never defines it while `:203-209` ("default environment: show
  everything") defines it to 1. Verified against the pinned compiler:
  `-D_DEFAULT_SOURCE` still leaves it undefined; `-D__BSD_VISIBLE=1` compiles.
* **Targets bound.** FreeBSD, and any other libc that gates a non-POSIX
  declaration behind an internal `__*_VISIBLE` macro while a vendored unit
  defines `_POSIX_C_SOURCE` first. OpenBSD is explicitly *not* in scope —
  `platform_util.c:14` already carves it out, and its `sys/cdefs.h:430-431`
  defaults the macro to 1, which is why those cells compiled while the FreeBSD
  ones did not. The general lesson: **a vendored unit that sets a feature-test
  macro itself can make a later line in the same file uncompilable on one libc
  and fine on another, and the error names the function, never the macro.**
## 18. A fixed test port makes `cross-test --jobs N` fail cells that pass alone

* **Condition.** `tests.zig:734` fixes the handshake test's port at `39443`
  and `tests.zig:1029` fixes a second at `39445`. There is no per-target
  offset, because the ports are part of what the test asserts (the client in
  `tests.zig:878` connects to `localhost:39443`), so they cannot simply vary
  per process.
* **Symptom.** With `cross-test --jobs 8`, four cells
  (`armeb-linux`, `mips64-linux`, `riscv32-linux`, `riscv64-linux`) report
  `tests_failed` and the *only* failing test is the handshake, failing at
  `tests.zig:762` `Socket.bindAll(test_port)` — a bind, not a handshake. The
  other 24-27 tests in the same binary pass, so the library is fine and the
  port is not. Read alone, this looks like an endianness or QEMU bug on those
  four architectures, and it is not one.
* **Fix.** None in this tree, deliberately. Each of the four exits **0** when
  re-run one at a time against the same cache and the same compiler, which is
  what identifies it as contention rather than a defect. The honest fix is in
  the harness's cell scheduling, or a per-target port derived from the target
  name. Making `netOk` tolerate `EADDRINUSE`, or dropping the test under
  concurrency, would convert a scheduling fact into a silent pass and is
  exactly what this package does not do.
* **Targets bound.** Any run with `CROSS_JOBS > 1` on a host where the
  emulated cells share a network namespace with each other. A single-cell run
  (`--targets armeb-linux`) cannot show it, and a `--jobs 1` run cannot either.

## 19. Three more lessons from the same run, none of them duplicated by §18

**Recorded 2026-10-05 from one run**, `cross-test --jobs 8 --build-jobs 8`, run
id `20261005-202203-22837-9367`, harness exit 1 over 53 cells. Receipts under
`<scratch>/foundation-libs/cross/mbed-tls/`. Nothing in §19 changed a source
file. §18 already covers the fixed-port contention and is not repeated here.

### 19.1 A concurrent editor invalidates a matrix receipt; wait for stability, do not re-run faster

* **Condition.** `cross-test` reads the tree it runs from, once per cell, over
  about eight minutes. Another worker holds write access to the same tree.
* **Symptom.** Three full matrices were run here and all three were discarded.
  Run 1 had `zig/config_gen.zig` change at 21:34:37, splitting 13 cells from 40.
  Run 2 had it change again at 21:48:02, splitting them a second time. The
  visible damage is a summary whose cells describe *two different programs*. The
  subtler damage is that the stale cells look like real findings: run 1's
  `MBEDTLS_NO_PLATFORM_ENTROPY` `UnparseableDirective` on riscv32/riscv64/s390x
  was a stale-source artefact that the concurrent edit fixed, so recording it as
  a defect would have been a fabricated finding.
* **Fix.** Hash the fork-owned files before and after the run and compare, then
  gate the run on a stability window rather than on a clock: poll a digest of
  the fork's own sources until it is unchanged for ten consecutive minutes, and
  start only then. Confirm afterwards that the last cell log predates the next
  edit. `build.zig` and `zig/config_gen.zig` were the files that moved;
  hashing every fork-owned file costs nothing and catches the next one.
* **Targets bound.** Any matrix, test or smoke run over a tree another agent is
  editing. The rule is not "re-run": a second run over a still-moving tree yields
  a third unusable receipt. The stability window also tells the driver when the
  tree is actually ready to gate.

### 19.2 "The compiler said so" is not a boundary

* **Condition.** 27 cells failed to build. Three causes, and the tempting move is
  to file all of them as platform boundaries because each ends in a toolchain or
  a linker.
* **Symptom.** Only 12 of the 27 are boundaries of the pinned toolchain. Thirteen
  are this fork's own `zig/config_gen.zig` refusing to generate a configuration
  for an architecture its `Params.known` list (`config_gen.zig:102-106`) does not
  name, erroring at `config_gen.zig:245`. Two more are this fork's own link line:
  `build.zig:771-772` links only `m` and `dl`, while upstream's own
  `src/library/CMakeLists.txt:225-227` sets `ws2_32 bcrypt` on WIN32, leaving the
  entire Winsock2 import set and `BCryptGenRandom` undefined. Filing these as
  boundaries would have turned 15 fixable gate failures into permanent, named
  and false excuses.
* **Fix.** For each failure, follow the first `error:` back to the file that owns
  the decision and ask *whose* decision it is. `error.UnknownArchitecture` from a
  file inside `zig/` is this fork refusing, not the platform. An
  `lld-link: undefined symbol` for a library upstream's own build lists at
  `CMakeLists.txt:226` is this fork's link line, not the platform's. Only
  failures landing inside `lib/libc/include/` or `lib/compiler/aro/` are the
  toolchain's, and those are named at the toolchain's own line:
  `generic-netbsd/sys/endian.h:74`, `generic-openbsd/time.h:61`,
  `any-windows-any/malloc.h:193,221`.
* **Targets bound.** Every cross-target gate in every tree. The general lesson:
  **a boundary is a cause that lives in a file this fork does not own, named at
  that file's line.** The discipline the workspace applies to a user-reported
  error applies equally to a red matrix cell.

### 19.3 An expected failure is a hypothesis until a run contradicts it

* **Condition.** [`README.md`](README.md) "The six compile targets" recorded that
  `wasm32-wasi` was expected to refuse compilation with a `setjmp.h` diagnostic,
  and the same expectation reached this tree's wave brief.
* **Symptom.** `wasm32-wasi` compiled all 113 translation units with the run step
  `skipped` and no error, and `build-wasm32-wasi.log` contains no `setjmp`
  message at all. The expectation came from reading `src/library/sha256.c:170-172`
  and `sha512.c:160-163`, where `setjmp.h` is included under
  `#elif defined(__unix__) && defined(SIG_SETMASK)` — but the configuration
  generated for that target does not select that arm, so the header is never
  reached.
* **Fix.** Read the generated configuration, not the vendored source, when
  predicting what a target compiles. The generator's own output decides which arm
  of an `#elif` runs.
* **Targets bound.** `wasm32-wasi`, and any prediction made from a vendored
  `#if`/`#elif` chain whose selected arm is chosen by a generated header. The
  general lesson: **a source-reading prediction about a
  configuration-dependent arm is a `HYPOTHESIS`; only the gate moves it, and a
  gate that contradicts it retracts it rather than explaining it away.**
