# Notice

## Upstream files

Unless a file states otherwise, Mbed TLS files use the dual `Apache-2.0 OR GPL-2.0-or-later` grant at the recipient's choice. `src/LICENSE` contains the grant and both full license texts; `README.upstream.md` states the same default. The Mbed TLS Contributors are the upstream attribution. Redistributions remain subject to Apache's NOTICE mechanism and preservation of notices.

`src/framework-LICENSE` states the same dual grant for the `mbedtls-framework` Git submodule. That submodule is not included in this release package, so `src/framework-LICENSE` covers no file here.

| Path | Files | Term and attribution | File notice |
|---|---:|---|---|
| `src/include/mbedtls/*.h` | 74 | Apache-2.0 OR GPL-2.0-or-later; The Mbed TLS Contributors | SPDX and `Copyright The Mbed TLS Contributors` |
| `src/include/psa/*.h` | 23 | Apache-2.0 OR GPL-2.0-or-later; The Mbed TLS Contributors | SPDX and `Copyright The Mbed TLS Contributors` |
| `src/include/CMakeLists.txt`, `src/include/.gitignore` | 2 | Apache-2.0 OR GPL-2.0-or-later; The Mbed TLS Contributors | No file notice; covered by upstream's blanket statement |
| `src/library/*.c` | 109 | Apache-2.0 OR GPL-2.0-or-later; The Mbed TLS Contributors | SPDX and `Copyright The Mbed TLS Contributors` |
| `src/library/*.h` | 65 | Apache-2.0 OR GPL-2.0-or-later; The Mbed TLS Contributors | SPDX and `Copyright The Mbed TLS Contributors` |
| `src/library/CMakeLists.txt`, `src/library/Makefile`, `src/library/.gitignore` | 3 | Apache-2.0 OR GPL-2.0-or-later; The Mbed TLS Contributors | No file notice; covered by upstream's blanket statement |
| `src/configs/*.h` | 8 | Apache-2.0 OR GPL-2.0-or-later; The Mbed TLS Contributors | SPDX and `Copyright The Mbed TLS Contributors` |
| `src/configs/ext/config_tfm.h`, `src/configs/ext/mbedtls_entropy_nv_seed_config.h` | 2 | Apache-2.0 OR GPL-2.0-or-later; The Mbed TLS Contributors | SPDX and `Copyright The Mbed TLS Contributors` |
| `src/configs/ext/crypto_config_profile_medium.h` | 1 | BSD-3-Clause; Arm Limited | `Copyright (c) 2018-2023, Arm Limited. All rights reserved.` and BSD-3-Clause SPDX |
| `src/configs/ext/tfm_mbedcrypto_config_profile_medium.h` | 1 | Apache-2.0; ARM Limited | `Copyright (C) 2006-2023, ARM Limited, All Rights Reserved`, Apache-2.0 SPDX, and full Apache boilerplate |
| `src/configs/README.txt`, `src/configs/ext/README.md` | 2 | Apache-2.0 OR GPL-2.0-or-later; The Mbed TLS Contributors | No file notice; the `ext/README.md` licensing claim conflicts with the two profile files above |
| `src/3rdparty/p256-m/p256-m_driver_entrypoints.c`, `src/3rdparty/p256-m/p256-m_driver_entrypoints.h`, `src/3rdparty/p256-m/p256-m/p256-m.c`, `src/3rdparty/p256-m/p256-m/p256-m.h` | 4 | Apache-2.0 OR GPL-2.0-or-later; The Mbed TLS Contributors, with author permission | Dual SPDX; authored by Manuel Pégourié-Gonnard |
| `src/3rdparty/p256-m/README.md`, `src/3rdparty/p256-m/p256-m/README.md`, `src/3rdparty/p256-m/CMakeLists.txt`, `src/3rdparty/p256-m/Makefile.inc`, `src/3rdparty/p256-m/.gitignore` | 5 | Apache-2.0 OR GPL-2.0-or-later; The Mbed TLS Contributors, with author permission | No file notice; the READMEs state the permission |
| `src/3rdparty/everest/` (six tagged sources) | 6 | Apache-2.0 only; INRIA and Microsoft Corporation | `Copyright 2016-2018 INRIA and Microsoft Corporation`, Apache-2.0 SPDX, and full Apache boilerplate |
| `src/3rdparty/everest/` (sixteen untagged sources) | 16 | Apache-2.0 only; INRIA and Microsoft Corporation | The two-line prose notice listed below |
| `src/3rdparty/everest/CMakeLists.txt`, `src/3rdparty/everest/Makefile.inc`, `src/3rdparty/everest/README.md`, `src/3rdparty/everest/.gitignore` | 4 | Apache-2.0 only; INRIA and Microsoft Corporation | No file notice; the README states the term |
| `src/3rdparty/CMakeLists.txt`, `src/3rdparty/Makefile.inc`, `src/3rdparty/.gitignore` | 3 | Apache-2.0 OR GPL-2.0-or-later; The Mbed TLS Contributors | No file notice; covered by upstream's blanket statement |
| `src/LICENSE` | 1 | Apache-2.0 OR GPL-2.0-or-later; The Mbed TLS Contributors | Dual grant and both full license texts |
| `src/framework-LICENSE` | 1 | Apache-2.0 OR GPL-2.0-or-later for the absent framework submodule | Dual grant; it covers no file in this package |
| `src/ChangeLog` | 1 | Apache-2.0 OR GPL-2.0-or-later; The Mbed TLS Contributors | No file notice; covered by upstream's blanket statement |
| `src/SECURITY.md` | 1 | Apache-2.0 OR GPL-2.0-or-later; The Mbed TLS Contributors | No file notice; covered by upstream's blanket statement |
| `fixtures/test-ca.crt`, `fixtures/server2.crt`, `fixtures/server2.key` | 3 | Apache-2.0 OR GPL-2.0-or-later; The Mbed TLS Contributors | Upstream test data; no individual notice, covered by the blanket statement |
| `README.upstream.md` | 1 | Apache-2.0 OR GPL-2.0-or-later; The Mbed TLS Contributors | Upstream's dual-term statement in prose |

These groups account for all 336 imported upstream files. `UPSTREAM.sha256` records their digests. The Everest subtree is Apache-2.0 only; it is not part of the dual grant.

## Per-file exceptions

1. **`src/3rdparty/everest/` — Apache-2.0 only.** All 26 files are attributed to INRIA and Microsoft Corporation. Six sources carry an Apache-2.0 SPDX tag; sixteen sources carry no tag; four build or documentation files have no individual notice. The subtree's README states the Apache-2.0 term. No GPL alternative applies to this material.

   The six tagged sources are:
   - `src/3rdparty/everest/include/everest/everest.h`
   - `src/3rdparty/everest/include/everest/kremlib.h`
   - `src/3rdparty/everest/include/everest/x25519.h`
   - `src/3rdparty/everest/library/everest.c`
   - `src/3rdparty/everest/library/Hacl_Curve25519_joined.c`
   - `src/3rdparty/everest/library/x25519.c`

2. **`src/configs/ext/crypto_config_profile_medium.h` — BSD-3-Clause, Arm Limited.** The file states: `Copyright (c) 2018-2023, Arm Limited. All rights reserved.` and `SPDX-License-Identifier: BSD-3-Clause`. It is the only BSD-licensed file in the imported tree.

3. **`src/configs/ext/tfm_mbedcrypto_config_profile_medium.h` — Apache-2.0, ARM Limited.** The file states `Copyright (C) 2006-2023, ARM Limited, All Rights Reserved`, carries `SPDX-License-Identifier: Apache-2.0`, and includes the full Apache boilerplate. `src/configs/ext/README.md` says both profile files are dual-licensed and attributed to The Mbed TLS Contributors; the files carry Arm copyrights and single-license identifiers. This notice records that conflict without changing either upstream file.

4. **Sixteen Everest sources without SPDX tags.** Each starts with these exact notices:

   `Copyright (c) INRIA and Microsoft Corporation. All rights reserved.`

   `Licensed under the Apache 2.0 License.`

   Paths:
   - `src/3rdparty/everest/include/everest/Hacl_Curve25519.h`
   - `src/3rdparty/everest/include/everest/kremlib/FStar_UInt128.h`
   - `src/3rdparty/everest/include/everest/kremlib/FStar_UInt64_FStar_UInt32_FStar_UInt16_FStar_UInt8.h`
   - `src/3rdparty/everest/include/everest/kremlin/c_endianness.h`
   - `src/3rdparty/everest/include/everest/kremlin/internal/builtin.h`
   - `src/3rdparty/everest/include/everest/kremlin/internal/callconv.h`
   - `src/3rdparty/everest/include/everest/kremlin/internal/compat.h`
   - `src/3rdparty/everest/include/everest/kremlin/internal/debug.h`
   - `src/3rdparty/everest/include/everest/kremlin/internal/target.h`
   - `src/3rdparty/everest/include/everest/kremlin/internal/types.h`
   - `src/3rdparty/everest/include/everest/kremlin/internal/wasmsupport.h`
   - `src/3rdparty/everest/include/everest/vs2013/Hacl_Curve25519.h`
   - `src/3rdparty/everest/library/Hacl_Curve25519.c`
   - `src/3rdparty/everest/library/kremlib/FStar_UInt128_extracted.c`
   - `src/3rdparty/everest/library/kremlib/FStar_UInt64_FStar_UInt32_FStar_UInt16_FStar_UInt8.c`
   - `src/3rdparty/everest/library/legacy/Hacl_Curve25519.c`

## Fork-authored material

Fork-authored files outside `src/`, `fixtures/`, and `README.upstream.md` are covered by the dual `Apache-2.0 OR GPL-2.0-or-later` grant in `FORK-LICENSE.md`; no upstream copyright is claimed over them. The fork-authored paths are:

- `build.zig`, `build.zig.zon`, `cross-test.profile.sh`, `tools/check-provenance.sh`
- `zig/root.zig`, `zig/translate.h`, `zig/config_gen.zig`
- `runtime/loader.zig`, `runtime/library.zig`, `runtime/graph.zig`, `runtime/generate.zig`, `runtime/sync.c`, `runtime/sync.h`
- `consumer/build.zig`, `consumer/build.zig.zon`, `consumer/src/main.zig`
- `tests.zig`, `smoke.zig`, `README.md`, `CHANGELOG.md`, `FORK-NOTES.md`
- `UPSTREAM.sha256`, `UPSTREAM.md`, `NOTICE.md`, `FORK-LICENSE.md`

`.gitignore` is mixed: upstream entries are retained, and appended fork build rules are covered by `FORK-LICENSE.md`. `README.upstream.md` is upstream material and is not covered by the fork grant. `runtime/loader.zig` carries an MIT SPDX header, while the fork grant covers it under the dual term; the header and repository grant differ.
