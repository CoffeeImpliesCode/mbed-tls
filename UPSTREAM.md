# Upstream

Which upstream this SDK is built from, what was taken from it byte for byte,
and what was not taken at all.

## Canonical source

| | |
|---|---|
| Project | Mbed TLS, Arm / Trusted Firmware group |
| Authoritative site | <https://mbed-tls.readthedocs.io/> |
| Repository | <https://github.com/Mbed-TLS/mbedtls> |
| Branch | `mbedtls-3.6` — the long-term-support branch, "supported with bug-fixes and security fixes until at least March 2027" per the release body |
| Tag | `mbedtls-3.6.7` |
| Annotated tag object | `627361b09e6f6e3eac756297a370a591cf310ab9` |
| Commit | `068ff080b369adfac81509f9b57b2afabaf82dc5` |
| Released | 2026-07-07 |
| Artifact | `mbedtls-3.6.7.tar.bz2` |
| Size | 5473689 bytes |
| URL | <https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2> |
| sha256 | `a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6` |
| Digest cross-check | matched against upstream's own published `mbedtls-3.6.7-sha256sum.txt` asset |

`SOURCE-CONFIRMED`: every value in that table was read out of a file or a
primary-source page, not inferred.

* The tag object `627361b09e6f6e3eac756297a370a591cf310ab9` is GitHub's tag
  object for `mbedtls-3.6.7`, message `Mbed TLS mbedtls-3.6.7`, tagger Minos
  Galanakis `<minos.galanakis@arm.com>` dated `2026-07-01T13:47:10Z`, and its
  `object` is the commit `068ff080b369adfac81509f9b57b2afabaf82dc5`
  (`api.github.com/repos/Mbed-TLS/mbedtls/git/tags/627361b…`, read
  2026-10-05). That object is unsigned — `verification.reason` is `unsigned` —
  which is a fact about the tag, not a defect in this import.
* The release date, the LTS sentence, the artifact name and the sha256 are all
  printed in the release body at
  `<https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-3.6.7>`
  (read 2026-10-05). The same page states that `mbedtls-3.6.7.tar.bz2` is the
  official release file and that the automatic `source.tar.gz` / `source.zip`
  snapshots "do not include submodules or generated files".
* The sha256 was checked against the separate `mbedtls-3.6.7-sha256sum.txt`
  asset published alongside the release, and the two agree.

The version this tree carries is the version upstream's own headers declare, at
`src/include/mbedtls/build_info.h:27-29` and `:36-38`:

```c
#define MBEDTLS_VERSION_MAJOR  3
#define MBEDTLS_VERSION_MINOR  6
#define MBEDTLS_VERSION_PATCH  7
#define MBEDTLS_VERSION_NUMBER         0x03060700
#define MBEDTLS_VERSION_STRING         "3.6.7"
#define MBEDTLS_VERSION_STRING_FULL    "Mbed TLS 3.6.7"
```

That is a claim about bytes, not about a build: nothing here has been compiled
or executed for this package. `build.zig` asserts the same numbers at
configure time from these macros and fails if they move.

## What upstream is

A C library that implements cryptographic primitives — including the PSA
Cryptography API — X.509 certificate manipulation, and the SSL/TLS and DTLS
protocols (`README.upstream.md:4`), packaged as three archives: `mbedtls`,
`mbedx509` and `mbedcrypto`. Upstream's own repository description calls it
"an open source, portable, easy to use, readable and flexible TLS library, and
reference implementation of the PSA Cryptography API".

**The licence is dual and the tree is not one label.** The blanket term is
`Apache-2.0 OR GPL-2.0-or-later`: "Unless specifically indicated otherwise in a
file, Mbed TLS files are provided under a dual Apache-2.0 OR GPL-2.0-or-later
license" (`README.upstream.md:317`), and `src/LICENSE:1-6` carries the same
statement plus the full text of both licences. 285 files in this tree repeat
that term as `SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later`. Four
do not, and they are the reason `NOTICE.md` is an inventory rather than a
sentence: the bundled Everest subtree is Apache-2.0 only, one
`configs/ext/` profile is BSD-3-Clause and another is Apache-2.0. See
`NOTICE.md`, "Per-file exceptions", which names each of the four.

**This package pins the 3.6 LTS line and not 4.x, and that is a decision with a
reason.** Mbed TLS 4.0 split the project in two: cryptography moved to a
separate TF-PSA-Crypto repository that Mbed TLS consumes as a submodule, and
"Mbed TLS has been split between two products: TF-PSA-Crypto for cryptography,
and Mbed TLS for X.509 and (D)TLS"; with that split "The cryptography API is
now mostly the PSA API: most legacy cryptography APIs have been removed", and
CMake became the only supported build system with the GNU Make and Visual
Studio project builds removed. That is upstream's own summary, read from
`docs/4.0-migration-guide.md` on the `development` branch
(`raw.githubusercontent.com/Mbed-TLS/mbedtls/development/docs/4.0-migration-guide.md`,
read 2026-10-05). A consumer of the 3.6 line keeps the `mbedtls_*` legacy
crypto entry points, the PSA entry points and the `mbedcrypto` / `mbedx509` /
`mbedtls` archive names it already links against; a 4.x import would remove
the first of those, rename the third, and drop the make-based build this tree's
upstream files are organised around. Pinning the LTS line also means the pin
has a maintenance horizon: bug and security fixes until at least March 2027.

Upstream's own build system is a top-level `Makefile` plus `library/Makefile`,
and a CMake tree. This SDK uses neither, and no upstream `Makefile` or
`CMakeLists.txt` is executed by it. `build.zig` compiles the same source list;
the vendored `src/library/CMakeLists.txt` is present only because it is the
record of that list, and it is quoted below.

## The preserved upstream README

The release tarball ships a file called `README.md`, which is upstream's own
project README and **not** a fork README. It is preserved here unaltered under
the name this repository uses for a preserved upstream README:

* `README.upstream.md` — the imported original, exactly as the tarball carries
  it, 336 lines. There is no second copy under the name `README.md`: upstream's
  `README.md` is this repository's `README.md`'s upstream counterpart, and the
  two must not collide. The canonical fork document is
  [`README.md`](README.md).

`UPSTREAM.sha256:4` records its digest as
`6ea15aafaf9765a730b651eeb5376bf54b646c5ee5fcc6b7c80d6d0d209a3fb4`, and
`tools/check-provenance.sh` re-hashes it with the rest of the vendored set, so
the copy cannot drift without the gate failing.

## What is vendored

335 files across `src/` and `fixtures/`, plus the preserved upstream README:
336 digested entries in total, of which 3 lines of `UPSTREAM.sha256` are
comments. The whole of the release archive's compiled material is imported;
nothing is dropped for size, and nothing is dropped for being uncompiled by this
fork.

| Path | Files | What it is |
|---|---:|---|
| `src/include/` | 99 | the public headers: 74 `mbedtls/*.h` and 23 `psa/*.h`, plus upstream's own `CMakeLists.txt` and `.gitignore` |
| `src/library/` | 177 | the implementation: 109 translation units and 65 private headers, plus upstream's own `CMakeLists.txt`, `Makefile` and `.gitignore` |
| `src/3rdparty/` | 38 | two bundled third-party crypto implementations — Everest (26 files) and p256-m (9 files) — plus upstream's own `CMakeLists.txt`, `Makefile.inc` and `.gitignore` |
| `src/configs/` | 14 | 8 example configuration profiles, 5 files under `configs/ext/` and upstream's `README.txt` |
| `src/LICENSE` | 1 | the dual term in force, with the full text of both licences |
| `src/framework-LICENSE` | 1 | the same dual term, worded for the `mbedtls-framework` submodule's files, which are not vendored |
| `src/ChangeLog` | 1 | upstream's own release history, newest first |
| `src/SECURITY.md` | 1 | upstream's vulnerability-reporting process |
| `fixtures/` | 3 | upstream's own handshake certificate, key and CA; see below |

Per-file digests are in [`UPSTREAM.sha256`](UPSTREAM.sha256), which is the
complete set and not a selection.

**What the archive does not bring, and this tree does not fake.** The
`mbedtls-framework` Git submodule is absent, upstream's own words at
`README.upstream.md:57`: the submodule "is not needed to merely compile the
library at a release tag" and "is not needed to consume a release archive (zip
or tar)". So there is no `framework/` directory here, no `scripts/` directory,
and no example programs (`programs/ssl/ssl_server2.c` and the rest) — they are
not in the release archive. `src/library/Makefile:12-23` therefore refuses to
build in this tree, which is upstream's own guard, not a fork edit: it looks
for `$(MBEDTLS_PATH)/framework/exported.make` and errors out when it is
missing. This SDK does not run that makefile.

## The core closure, as upstream lists it

`src/library/CMakeLists.txt` is the record, and it is read out of upstream
rather than derived. `set(src_crypto …)` at lines 13-95, `set(src_x509 …)` at
lines 97-107 and `set(src_tls …)` at lines 109-128 name **108** translation
units in all: **81** crypto, **9** X.509 and **18** TLS. Every one of the 108
is present in `src/library/`.

* **Crypto** (`src_crypto`, 81): `aes aesni aesce aria asn1parse asn1write
  base64 bignum bignum_core bignum_mod bignum_mod_raw block_cipher camellia
  ccm chacha20 chachapoly cipher cipher_wrap constant_time cmac ctr_drbg des
  dhm ecdh ecdsa ecjpake ecp ecp_curves entropy entropy_poll error gcm hkdf
  hmac_drbg lmots lms md md5 memory_buffer_alloc nist_kw oid padlock pem pk
  pk_ecc pk_wrap pkcs12 pkcs5 pkparse pkwrite platform platform_util poly1305
  psa_crypto psa_crypto_aead psa_crypto_cipher psa_crypto_client
  psa_crypto_driver_wrappers_no_static psa_crypto_ecp psa_crypto_ffdh
  psa_crypto_hash psa_crypto_mac psa_crypto_pake psa_crypto_rsa
  psa_crypto_random psa_crypto_se psa_crypto_slot_management
  psa_crypto_storage psa_its_file psa_util ripemd160 rsa rsa_alt_helpers sha1
  sha256 sha512 sha3 threading timing version version_features`
* **X.509** (`src_x509`, 9): `pkcs7 x509 x509_create x509_crl x509_crt x509_csr
  x509write x509write_crt x509write_csr`
* **TLS** (`src_tls`, 18): `debug mps_reader mps_trace net_sockets ssl_cache
  ssl_ciphersuites ssl_client ssl_cookie ssl_debug_helpers_generated ssl_msg
  ssl_ticket ssl_tls ssl_tls12_client ssl_tls12_server ssl_tls13_keys
  ssl_tls13_server ssl_tls13_client ssl_tls13_generic`

The 109th `.c` file in `src/library/` is `ecp_curves_new.c`, and upstream says
why in the file itself: "This file used to be non-empty. It's kept only for
compatibility with custom build systems in LTS branches" — its whole body is
`typedef int iso_c_forbids_an_empty_translation_unit;`. It is vendored, digested
and not compiled.

The two `3rdparty/*/Makefile.inc` files, pulled in by
`src/3rdparty/Makefile.inc`, add **five** more units:

* **Everest** (`src/3rdparty/everest/Makefile.inc`): `library/everest.o`,
  `library/x25519.o`, `library/Hacl_Curve25519_joined.o`
* **p256-m** (`src/3rdparty/p256-m/Makefile.inc`):
  `p256-m_driver_entrypoints.o`, `p256-m/p256-m.o`

113 translation units is the closure. The other everest and p256-m sources in
the tree — `Hacl_Curve25519.c`, the KreMLin support units, the `legacy/`
variant, `vs2013/Hacl_Curve25519.h` — are upstream alternatives that this
closure selects against, and they are vendored and digested like everything
else.

## Nothing is generated at build time except the configuration header

Upstream ships five files that its own build can regenerate. They are named
`GENERATED_FILES` at `src/library/Makefile:5-8`:

```
GENERATED_FILES := \
   error.c version_features.c \
   ssl_debug_helpers_generated.c \
   psa_crypto_driver_wrappers.h \
   psa_crypto_driver_wrappers_no_static.c
```

**All five are shipped pre-generated in the release tarball and are vendored
here verbatim**, so no Perl and no Python generator runs in this package's
build. That is upstream's own statement, not an inference: at
`README.upstream.md:61`, "The source code of Mbed TLS includes some files that
are automatically generated by scripts … These files are not included in the
development branch of Mbed TLS, but the generated files are included in
official releases", and the release body adds that it is
`mbedtls-3.6.7.tar.bz2` that is the official release file, while the automatic
`source.tar.gz` / `source.zip` snapshots "do not include submodules or
generated files". Three independent facts in this tree agree: the five files
are present in `src/library/`, they are members of the `src_crypto` and
`src_tls` lists that `CMakeLists.txt` uses whether or not `GEN_FILES` is on,
and each carries the `Apache-2.0 OR GPL-2.0-or-later` tag with a
`Copyright The Mbed TLS Contributors` line as any other source file does.
`ssl_debug_helpers_generated.c:1` still says "Automatically generated by
generate_ssl_debug_helpers.py. DO NOT EDIT.", and `psa_crypto_driver_wrappers.h`
and `psa_crypto_driver_wrappers_no_static.c` still say "Warning: This file is
now auto-generated" — upstream's marks, preserved.

For the record, the generators this build therefore never invokes are
`scripts/generate_errors.pl` and `scripts/generate_features.pl` (Perl), and
`framework/scripts/generate_ssl_debug_helpers.py` and
`scripts/generate_driver_wrappers.py` (Python) — `src/library/CMakeLists.txt:130-203`,
the whole `if(GEN_FILES)` block. None of those scripts is vendored, because
none of them is in the release archive.

**The one thing this build does generate is the configuration header**, and it
generates it per target. `zig/config_gen.zig` runs on the build machine with the
resolved target's facts as arguments, reads this package's own copy of
upstream's `src/include/mbedtls/mbedtls_config.h`, and writes one complete
configuration header for the target being built. `build.zig` reaches it with
`-DMBEDTLS_CONFIG_FILE='"mbed_tls_target_config.h"'` and the generated
directory on the include path, and installs it under the canonical name
`include/mbedtls/mbedtls_config.h`. That is the target-dependent generation
this workspace requires, and `zig/config_gen.zig` never asks what machine it is
running on: `builtin.target` appears nowhere in it.

So the honest summary is: one generated file, for the target being built, and
five upstream files that could be generated and are not.

## The handshake fixture

Three files, all upstream's own published test data, taken from the
`framework/data_files/` directory inside the release tarball:

| File | sha256 | What it is |
|---|---|---|
| `fixtures/test-ca.crt` | `2e51a78cdd32c9a83407fb2053cf0436a570e22a0bedd59a1adc4b29d06222fa` | the PolarSSL test CA |
| `fixtures/server2.crt` | `fa79509dfeee01f07bae293374f6e85754489a9e2b10411b94b436dd7121e750` | an RSA-2048 leaf certificate for `localhost`, signed by that CA |
| `fixtures/server2.key` | `5d061d8e92c246e465654ea6eef75b0667cc49cfb8f76d3b4c2f2517861f8b1e` | the matching private key, PKCS#1 (`BEGIN RSA PRIVATE KEY`) |

`SOURCE-CONFIRMED`, read out of the files themselves with OpenSSL 3.5.0
(2026-10-05):

* `test-ca.crt` — subject and issuer both `C=NL, O=PolarSSL, CN=PolarSSL Test
  CA`; serial `03`; valid `Feb 10 14:44:00 2019 GMT` to `Feb 10 14:44:00 2029
  GMT`.
* `server2.crt` — subject `C=NL, O=PolarSSL, CN=localhost`, issuer
  `C=NL, O=PolarSSL, CN=PolarSSL Test CA`; serial `02`; valid `Feb 10 14:44:06
  2019 GMT` to `Feb 10 14:44:06 2029 GMT`; RSA 2048 bit, two primes.
* `server2.key` — `-----BEGIN RSA PRIVATE KEY-----`, 2048-bit RSA, two primes.
* The chain verifies: `openssl verify -CAfile fixtures/test-ca.crt
  fixtures/server2.crt` printed `fixtures/server2.crt: OK`.

This is an inspection of upstream's data by a third-party tool, not a gate of
this package and not a Mbed TLS operation: no Mbed TLS code has been compiled
or run here. It is recorded because the fixture's value is that it is an
independent known answer — a certificate chain that a reference implementation
accepts — and a chain this package generated for itself would prove nothing.

The `framework/` directory these files came from is not vendored, so the
`framework/data_files/` path is upstream's layout rather than a path readable
in this tree. What this tree does record is exact: the three file names, their
subjects, serials and validity windows as read above, and their digests in
`UPSTREAM.sha256:5-7`. `tools/check-provenance.sh` fails if any of the three
names is missing, undigested, or unrecorded here.

## Import mechanism

A release tarball, imported whole. There is no upstream Git history in this
tree and no patch series: the tree either matches the tarball or a deviation is
recorded. `UPSTREAM.sha256` is the check that it does — every file under
`src/` and `fixtures/` plus `README.upstream.md`, 336 entries — and
`tools/check-provenance.sh` adds the exact-file-set comparison a checksum run
cannot do, so an added or renamed file fails as loudly as an edited one.

One thing about that gate does not line up yet, and it is recorded here rather
than left for a reader to discover. `tools/check-provenance.sh` step 3a takes
`grep -m1 -oE '^[0-9a-f]{64}'` of `UPSTREAM.md` and of `UPSTREAM.sha256` and
requires the two to be equal, so it expects each file to open its digest
material with a bare 64-digit line. `UPSTREAM.sha256` has no such line for the
release: its first digest line is `README.upstream.md`'s, and the release
digest `a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6` does
not appear in it at all — that file records *vendored-file* digests, not the
tarball's. This document records the release digest in a table row, which is
not a bare line and therefore not what that grep matches. Reconciling the two
is the integrity-script owner's change, not a change to this record and not a
change to any upstream byte; this paragraph is a statement about what the two
files contain, read out of them, and no gate has been run.

If a future wave re-syncs to another release, the correct sequence is: download
the new tarball, verify its published sha256, replace the imported files, update
`UPSTREAM.sha256`, `UPSTREAM.md`, `NOTICE.md` and `README.md`, and add a
numbered `CHANGELOG.md` entry — in one change. Note that a re-sync within the
3.6 LTS line keeps the same three artefacts and the same licence inventory; a
re-sync to 4.x is not a re-sync at all, and is the reason the pin is a branch
and not just a tag.

## Third-party material in this repository

Two upstream-bundled third-party projects, both under `src/3rdparty/`, both
described by upstream at `README.upstream.md:319-323`.

* **`src/3rdparty/everest/`** — 26 files, "Files stem from Project Everest and
  are distributed under the Apache 2.0 license" (`README.upstream.md:323`,
  `src/3rdparty/everest/README.md:1`). A formally verified Curve25519
  implementation, derived from the F\* original through KreMLin. **Apache-2.0
  only**: no GPL alternative is offered, and Everest's own notice says so. Six
  files carry `SPDX-License-Identifier: Apache-2.0`; sixteen carry only the two
  prose lines `Copyright (c) INRIA and Microsoft Corporation. All rights
  reserved.` / `Licensed under the Apache 2.0 License.` with no tag at all.
  `NOTICE.md` names all sixteen.
* **`src/3rdparty/p256-m/`** — 9 files, "Files within the `p256-m/`
  subdirectory originate from the p256-m GitHub repository. They are
  distributed here under a dual Apache-2.0 OR GPL-2.0-or-later license. They
  are authored by Manuel Pégourié-Gonnard" (`src/3rdparty/p256-m/README.md:1`).
  Upstream is Apache-2.0; the dual distribution in Mbed TLS is "with permission
  from the author" (`README.upstream.md:323`). Four source files carry the dual
  tag; the five build and documentation files carry no notice.

Nothing was fetched from outside the tarball to make this tree, and no
downloaded header or generated table is checked in here. Every file outside the
inventory above was written for this fork; [`FORK-LICENSE.md`](FORK-LICENSE.md)
covers those, and [`NOTICE.md`](NOTICE.md) lists them.
