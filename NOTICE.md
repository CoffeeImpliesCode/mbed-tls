# Notice

Two separate things are recorded here: what the canonical native source is and
which grant covers each of its files, and what this fork wrote on top of it.
[`FORK-LICENSE.md`](FORK-LICENSE.md) carries the grant for the second group.

## The upstream term

Mbed TLS is dual-licensed, `Apache-2.0 OR GPL-2.0-or-later`, and the choice is
the recipient's: "This means that users may choose which of these licenses they
take the code under" (`src/LICENSE:3-4`). The authoritative statements of that
term in this tree are three, and they agree:

* `src/LICENSE:1-6` — the dual statement, and the promise that "The full text of
  each of these licenses is given below".
* `src/LICENSE:9-209` — the full Apache License, Version 2.0, January 2004.
* `src/LICENSE:215-553` — the full GNU General Public License, Version 2,
  June 1991.
* `README.upstream.md:317` — upstream's own blanket rule: "Unless specifically
  indicated otherwise in a file, Mbed TLS files are provided under a dual
  Apache-2.0 OR GPL-2.0-or-later license", pointing at `LICENSE` for the full
  text.

That blanket rule is what covers the files with no notice of their own, and it
is why a file with no SPDX tag is not an unlicensed file here. What it does not
do is reach a file that says otherwise, and four in this tree do — see
"Per-file exceptions".

`src/framework-LICENSE` is the same dual grant with one word changed: it opens
"mbedtls-framework files are provided under a dual Apache-2.0 OR
GPL-2.0-or-later license", and it governs the `mbedtls-framework` Git submodule.
That submodule is **not** vendored — upstream states the submodule "is not
needed to consume a release archive" (`README.upstream.md:57`) — so this file
covers no file in `src/` today. It is carried because it is in the release
archive, digested and unmodified.

Upstream's one obligation in prose is the Apache `NOTICE` mechanism plus keeping
the notice with copies. Nothing here narrows it.

## Inventory of the upstream files

336 files, digests in [`UPSTREAM.sha256`](UPSTREAM.sha256): 332 under `src/`,
3 under `fixtures/`, and the preserved `README.upstream.md`. The counts below
were counted on disk and the terms were read out of the files; none is assumed
from the project's overall label.

| Path | Count | Term | Notice in the file |
|---|---:|---|---|
| `src/include/mbedtls/*.h` | 74 | Apache-2.0 OR GPL-2.0-or-later, The Mbed TLS Contributors | `SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later` under a `Copyright The Mbed TLS Contributors` line |
| `src/include/psa/*.h` | 23 | Apache-2.0 OR GPL-2.0-or-later, The Mbed TLS Contributors | as above |
| `src/include/CMakeLists.txt`, `src/include/.gitignore` | 2 | Apache-2.0 OR GPL-2.0-or-later, The Mbed TLS Contributors | **none in the file** — covered by the blanket statement at `README.upstream.md:317` |
| `src/library/*.c` | 109 | Apache-2.0 OR GPL-2.0-or-later, The Mbed TLS Contributors | as above |
| `src/library/*.h` | 65 | Apache-2.0 OR GPL-2.0-or-later, The Mbed TLS Contributors | as above |
| `src/library/CMakeLists.txt`, `src/library/Makefile`, `src/library/.gitignore` | 3 | Apache-2.0 OR GPL-2.0-or-later, The Mbed TLS Contributors | **none in the file** — covered by the blanket statement |
| `src/configs/*.h` | 8 | Apache-2.0 OR GPL-2.0-or-later, The Mbed TLS Contributors | as above |
| `src/configs/ext/config_tfm.h`, `src/configs/ext/mbedtls_entropy_nv_seed_config.h` | 2 | Apache-2.0 OR GPL-2.0-or-later, The Mbed TLS Contributors | as above |
| `src/configs/ext/crypto_config_profile_medium.h` | 1 | **BSD-3-Clause, Arm Limited** | `Copyright (c) 2018-2023, Arm Limited. All rights reserved.` and `SPDX-License-Identifier: BSD-3-Clause` at lines 2-4 |
| `src/configs/ext/tfm_mbedcrypto_config_profile_medium.h` | 1 | **Apache-2.0, ARM Limited** | `Copyright (C) 2006-2023, ARM Limited, All Rights Reserved` and `SPDX-License-Identifier: Apache-2.0`, with the full Apache boilerplate, at lines 9-24 |
| `src/configs/README.txt`, `src/configs/ext/README.md` | 2 | Apache-2.0 OR GPL-2.0-or-later, The Mbed TLS Contributors | **none in either file**; `ext/README.md` makes a claim about the two files above it, recorded under exceptions 2 and 3 |
| `src/3rdparty/p256-m/p256-m_driver_entrypoints.c`, `src/3rdparty/p256-m/p256-m_driver_entrypoints.h`, `src/3rdparty/p256-m/p256-m/p256-m.c`, `src/3rdparty/p256-m/p256-m/p256-m.h` | 4 | Apache-2.0 OR GPL-2.0-or-later, The Mbed TLS Contributors | `SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later`; dual distribution authorised by the author, see `src/3rdparty/p256-m/README.md:1` |
| `src/3rdparty/p256-m/README.md`, `src/3rdparty/p256-m/p256-m/README.md`, `src/3rdparty/p256-m/CMakeLists.txt`, `src/3rdparty/p256-m/Makefile.inc`, `src/3rdparty/p256-m/.gitignore` | 5 | Apache-2.0 OR GPL-2.0-or-later, The Mbed TLS Contributors | **none in the file** — covered by the blanket statement; the two READMEs state the author's permission in prose |
| `src/3rdparty/everest/` — 6 tagged sources | 6 | **Apache-2.0 only, INRIA and Microsoft Corporation** | `SPDX-License-Identifier: Apache-2.0` with `Copyright 2016-2018 INRIA and Microsoft Corporation` and the full Apache boilerplate: `include/everest/everest.h`, `include/everest/kremlib.h`, `include/everest/x25519.h`, `library/everest.c`, `library/Hacl_Curve25519_joined.c`, `library/x25519.c` |
| `src/3rdparty/everest/` — 16 untagged sources | 16 | **Apache-2.0 only, INRIA and Microsoft Corporation** | **no SPDX tag at all**; the two prose lines `Copyright (c) INRIA and Microsoft Corporation. All rights reserved.` / `Licensed under the Apache 2.0 License.` and nothing else. All sixteen are named under exception 4 |
| `src/3rdparty/everest/CMakeLists.txt`, `src/3rdparty/everest/Makefile.inc`, `src/3rdparty/everest/README.md`, `src/3rdparty/everest/.gitignore` | 4 | **Apache-2.0 only, INRIA and Microsoft Corporation** | **none in the file**; the README states the term in prose at line 1, and the build files inherit it |
| `src/3rdparty/CMakeLists.txt`, `src/3rdparty/Makefile.inc`, `src/3rdparty/.gitignore` | 3 | Apache-2.0 OR GPL-2.0-or-later, The Mbed TLS Contributors | **none in the file** — covered by the blanket statement |
| `src/LICENSE` | 1 | Apache-2.0 OR GPL-2.0-or-later | the dual statement and **both full licence texts**, `src/LICENSE:9-209` and `:215-553` |
| `src/framework-LICENSE` | 1 | Apache-2.0 OR GPL-2.0-or-later, for the `mbedtls-framework` submodule's files | the same dual statement and both full texts, for a submodule this tree does not vendor |
| `src/ChangeLog` | 1 | Apache-2.0 OR GPL-2.0-or-later, The Mbed TLS Contributors | **none in the file** — a 375552-byte changelog; covered by the blanket statement |
| `src/SECURITY.md` | 1 | Apache-2.0 OR GPL-2.0-or-later, The Mbed TLS Contributors | **none in the file** — covered by the blanket statement |
| `fixtures/test-ca.crt`, `fixtures/server2.crt`, `fixtures/server2.key` | 3 | Apache-2.0 OR GPL-2.0-or-later, The Mbed TLS Contributors | **no notice in any of the three** — upstream's own published test data, carried whole; covered by the blanket statement |
| `README.upstream.md` | 1 | Apache-2.0 OR GPL-2.0-or-later, The Mbed TLS Contributors | **no SPDX tag**; the dual term in prose at `README.upstream.md:317`, and the third-party statement at `:319-323` |

The counts add up: 74 + 23 + 2 + 109 + 65 + 3 + 8 + 2 + 1 + 1 + 2 + 4 + 5 + 6
+ 16 + 4 + 3 + 1 + 1 + 1 + 1 + 3 + 1 = **336**, which is every line of
`UPSTREAM.sha256` that is not a comment.

Two counts are worth stating plainly, because a scanner gets them wrong:

* **Of the 336 files, 285 carry `SPDX-License-Identifier: Apache-2.0 OR
  GPL-2.0-or-later`, 8 carry a different identifier, and 43 carry no SPDX tag
  at all.** The 8 are the six tagged Everest sources (`Apache-2.0`),
  `src/configs/ext/tfm_mbedcrypto_config_profile_medium.h` (`Apache-2.0`) and
  `src/configs/ext/crypto_config_profile_medium.h` (`BSD-3-Clause`). The 43
  are the 39 files under `src/` with no tag, the three `fixtures/` files and
  `README.upstream.md`. Every one of the 43 is named in this table, and "no
  tag" is not "no grant": each is either covered by the blanket statement at
  `README.upstream.md:317` or carries the prose notice named in its row.
* **The Everest subtree is not dual-licensed.** 26 files, Apache-2.0 only.
  Restating them as part of the Mbed TLS dual grant would be wrong, and
  `tools/check-provenance.sh` fails if Everest's own Apache-2.0 notice ever
  disappears from `src/3rdparty/everest/library/Hacl_Curve25519.c`.

`README.upstream.md` is upstream's `README.md` under this repository's naming
convention, byte for byte, and it is deliberately a digested entry in its own
right rather than an undigested copy: `UPSTREAM.sha256:4` records
`6ea15aafaf9765a730b651eeb5376bf54b646c5ee5fcc6b7c80d6d0d209a3fb4`, and the
provenance script re-hashes it. There is no second copy of it under the name
`README.md`, because `README.md` is this fork's own document.

## Per-file exceptions

**Four**, and this tree is not one label. Each is read out of the file it names.

1. **`src/3rdparty/everest/` — Apache-2.0 only, and not a fork choice.** All 26
   files of the bundled Everest subtree are under Apache 2.0, Copyright (c)
   INRIA and Microsoft Corporation. Upstream says so at `README.upstream.md:323`
   ("distributed under the Apache 2.0 license") and in the subtree's own
   `README.md:1`. There is no GPL alternative for this material and none is
   implied by the dual term that governs the rest of the tree: the grant
   applies per file, and this subtree's files name their own. Six carry an SPDX
   tag; twenty carry no tag at all, of which sixteen carry the two-line prose
   notice and four are build or documentation files.

2. **`src/configs/ext/crypto_config_profile_medium.h` — BSD-3-Clause, Arm
   Limited.** Lines 2-4 of the file: `Copyright (c) 2018-2023, Arm Limited. All
   rights reserved.` and `SPDX-License-Identifier: BSD-3-Clause`. This is the
   only BSD-licensed file in the tree. It was taken verbatim from TF-M, where
   `src/configs/ext/README.md:20` records that "In TF-M, they are distributed
   under a 3-Clause BSD license, as noted at the top of the files."

3. **`src/configs/ext/tfm_mbedcrypto_config_profile_medium.h` — Apache-2.0, ARM
   Limited.** Lines 9-24: `Copyright (C) 2006-2023, ARM Limited, All Rights
   Reserved`, `SPDX-License-Identifier: Apache-2.0`, and the full Apache 2.0
   boilerplate. Apache-2.0 only; not the dual term.

   **A conflict inside the tree, recorded rather than resolved.** Upstream's
   `src/configs/ext/README.md` says the opposite about both files: at lines
   9-10 "are copyright The Mbed TLS Contributors, and are distributed under the
   license normally used by Mbed TLS: a dual Apache 2.0 or GPLv2-or-later
   license", and at line 22 "In Mbed TLS, with permission from the TF-M project,
   they are distributed under a dual Apache-2.0 OR GPL-2.0-or-later license,
   with copyright assigned to The Mbed TLS Contributors." The files themselves
   carry the Arm copyright and a different, single licence each, and the same
   README says at its own end: "We only retain the note at the top of the files
   because we are taking the files verbatim." This inventory reports what the
   files say, which is what a licence scanner reads and what a distributor
   owes; the README's contrary claim is recorded here so the disagreement is
   visible rather than silently resolved in either direction. **Not resolved by
   this fork**, which edits no upstream file.

4. **Sixteen Everest sources with a prose notice and no SPDX tag.** These are
   named rather than left for a scanner to read as unlicensed:

   * `src/3rdparty/everest/include/everest/Hacl_Curve25519.h`
   * `src/3rdparty/everest/include/everest/kremlib/FStar_UInt128.h`
   * `src/3rdparty/everest/include/everest/kremlib/FStar_UInt64_FStar_UInt32_FStar_UInt16_FStar_UInt8.h`
   * `src/3rdparty/everest/include/everest/kremlin/c_endianness.h`
   * `src/3rdparty/everest/include/everest/kremlin/internal/builtin.h`
   * `src/3rdparty/everest/include/everest/kremlin/internal/callconv.h`
   * `src/3rdparty/everest/include/everest/kremlin/internal/compat.h`
   * `src/3rdparty/everest/include/everest/kremlin/internal/debug.h`
   * `src/3rdparty/everest/include/everest/kremlin/internal/target.h`
   * `src/3rdparty/everest/include/everest/kremlin/internal/types.h`
   * `src/3rdparty/everest/include/everest/kremlin/internal/wasmsupport.h`
   * `src/3rdparty/everest/include/everest/vs2013/Hacl_Curve25519.h`
   * `src/3rdparty/everest/library/Hacl_Curve25519.c`
   * `src/3rdparty/everest/library/kremlib/FStar_UInt128_extracted.c`
   * `src/3rdparty/everest/library/kremlib/FStar_UInt64_FStar_UInt32_FStar_UInt16_FStar_UInt8.c`
   * `src/3rdparty/everest/library/legacy/Hacl_Curve25519.c`

   Each begins with exactly two prose lines and nothing else:
   `Copyright (c) INRIA and Microsoft Corporation. All rights reserved.` and
   `Licensed under the Apache 2.0 License.` The same two lines appear in all 16,
   and `Licensed under the Apache 2.0 License` is what
   `tools/check-provenance.sh` greps for as the witness that this material was
   not restated under the dual grant.

   The six Everest files that *do* carry a tag use a different, fuller notice —
   `Copyright 2016-2018 INRIA and Microsoft Corporation`, the SPDX line and the
   full Apache boilerplate — and are listed in the inventory table above.

## What this fork changed in upstream files

**Nothing.** No file under `src/`, no file under `fixtures/`, and not one byte
of `README.upstream.md` has been edited. Every vendored byte is upstream's,
digested line by line in `UPSTREAM.sha256` and checked by
`tools/check-provenance.sh`, which does two things a plain checksum run cannot:
it compares the recorded path list against what is on disk, so an added,
removed or renamed file fails as loudly as an edited one, and it re-reads the
grant itself — `src/LICENSE`'s dual statement, this file's Everest copyright
line, and the three fixture names in both this record and
`UPSTREAM.sha256`.

The only fork-authored files are outside `src/`: the Zig build graph, the typed
facade, the translation header, the per-target configuration generator, the
runtime route, the consumer package, the integrity script, the ignore file and
the documentation. They are listed in full below, and `FORK-LICENSE.md` carries
their grant.

`STATUS`: `SOURCE-CONFIRMED` from the recorded digests and from what this file
asserts about them. That is a claim about bytes and about this inventory's
accuracy, not about a build: no gate has run for this package and no result is
recorded here. The observed runs belong to the README and its receipts, and
this inventory neither restates nor extends them.

## Fork-specific notice

Every file below was written for this fork. None of it carries an upstream
copyright, no upstream permission is claimed over it, and it is released under
the dual `Apache-2.0 OR GPL-2.0-or-later` term recorded in
[`FORK-LICENSE.md`](FORK-LICENSE.md), which reproduces both licence texts in
full:

* `build.zig` — the build graph: the three archives, the three modules, the six
  cross targets, the install and licence-record rules
* `build.zig.zon` — the package manifest
* `cross-test.profile.sh` — the settings profile the cross-test harness sources
* `tools/check-provenance.sh` — the provenance gate described above
* `zig/root.zig` — the typed facade over the translated public headers
* `zig/translate.h` — the aggregate translation header this build runs
  `translate-c` over
* `zig/config_gen.zig` — the per-target configuration-header generator; the one
  file this build generates is its output, into the build cache
* `consumer/build.zig`, `consumer/build.zig.zon`, `consumer/src/main.zig` — the
  materialised consumer package the `consumer` step runs
* `runtime/loader.zig`, `runtime/library.zig`, `runtime/graph.zig`,
  `runtime/generate.zig`, `runtime/sync.c`, `runtime/sync.h` — the six files of
  the load-at-runtime route. `loader.zig` is the reusable state machine and
  platform layer, holding no per-SDK name; `library.zig` is this SDK's
  descriptor and the namespaced synchronization binding; `graph.zig` is the
  build half that wires them together; `generate.zig` is the build-time
  generator that writes the dispatch from the real translation output for the
  target being built, through `Run.addOutputFileArg`, so the generated file
  lands in the build cache and this directory holds no generated source.
  `sync.c` and `sync.h` are the two C files that give the loader its
  process-global mutex, condition variable and thread identity under an
  `RT_SYNC_PREFIX` this SDK sets to `mbedtls_rt` (`runtime/graph.zig:83`,
  `runtime/graph.zig:217`). All six are fork work under this grant; none is
  upstream material, and `sync.c` is not a substitute for any upstream unit.
* `.gitignore` — upstream's own ignore conventions kept verbatim in its first
  block, then this fork's, with no upstream entry removed to make room
* `README.upstream.md` — the preserved upstream README: upstream's bytes, kept
  under this repository's naming convention, and digested as upstream material
  in the table above rather than as fork material
* `UPSTREAM.sha256` — the vendored-source digest manifest
* `UPSTREAM.md`, `NOTICE.md`, `FORK-LICENSE.md` — this provenance record, this
  inventory and the fork's own grant

The test module, the smoke example, the CI workflow and the fork's `README.md`,
`CHANGELOG.md` and `FORK-NOTES.md` are fork-authored material under the same
grant. They are named by role here rather than by path because this inventory
was written while those writers were still landing; each carries the grant, and
`NOTICE.md` is the record to re-read whenever the fork file set changes.

### Which of those files carry the SPDX tag, and which do not

Read out of the files, not assumed.

**Fourteen fork-authored files carry
`SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later` on their own first
comment line**: `build.zig.zon`, `consumer/build.zig`,
`consumer/build.zig.zon`, `consumer/src/main.zig`, `cross-test.profile.sh`,
`runtime/generate.zig`, `runtime/graph.zig`, `runtime/library.zig`,
`runtime/sync.c`, `runtime/sync.h`, `tools/check-provenance.sh`,
`zig/config_gen.zig`, `zig/root.zig` and `zig/translate.h`. That is the whole
tagged set, and it is the project's primary upstream term rather than a
fork-specific choice.

**One carries a different identifier, and it is recorded rather than tidied
away**: `runtime/loader.zig:1` reads `// SPDX-License-Identifier: MIT`. Every
other fork-authored file says `Apache-2.0 OR GPL-2.0-or-later`. `loader.zig` is
fork code under this repository's grant like the rest, so this file's grant
covers it; but a consumer scanning for licences would read that line as MIT and
stop there, which is a smaller grant than the one this file records. The line
is a deviation from the package's own SPDX convention and the file's owner
should reconcile it with `FORK-LICENSE.md`; this inventory reports what the file
says and does not edit it.

**Two are comment-capable text that carries the grant without a tag**:
`.gitignore` and `build.zig`. `build.zig` is the larger of the two and the more
consequential omission — it is the build graph every consumer runs — so it is
named explicitly here rather than left for a scanner to read as unlicensed.

**Five are prose and data with no comment position a tag is expected in**:
`README.upstream.md`, `UPSTREAM.sha256`, `UPSTREAM.md`, `NOTICE.md` and
`FORK-LICENSE.md`. `README.upstream.md` is upstream's bytes anyway and carries
upstream's dual statement in prose at its line 317. Their grant is the same dual
term.

Upstream's attribution obligation is unaffected by any of this. A consumer who
receives an Mbed TLS 3.6.7 binary, static or shared library, header, or
certificate fixture still owes The Mbed TLS Contributors' notice and the full
licence text, and a consumer who redistributes the Everest subtree still owes
INRIA's and Microsoft Corporation's Apache-2.0 notice. `share/licenses/mbed-tls/`
is where those travel: `build.zig` installs `src/LICENSE`, `NOTICE.md`,
`FORK-LICENSE.md`, `UPSTREAM.md` and `README.upstream.md` there, five files,
exactly `licence_records` at `build.zig:399-405`. The Everest notice travels
inside its own sources, which is where upstream put it.
