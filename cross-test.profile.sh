# cross-test settings profile for the Mbed TLS SDK.
#
# `cross-test` looks for this file at the root of the project it is run from
# (or names it with --profile; --no-profile ignores it). It is trusted Bash that
# the harness `source`s, so this file is *settings only*: ordinary variable
# assignments and nothing else. No command runs, no compiler is probed, and no
# path in here names a host.
#
# There is deliberately no CROSS_MATRIX. The published 53-platform Zig 0.16
# Tier 1/2 table is the matrix this package is checked against, and a matrix
# named here would replace it. There is no TARGETS array either, for the same
# reason: a subset selected here would narrow the run rather than add to it.
# Both belong on the command line, where --targets selects from the active
# matrix and never adds to it.
#
# CROSS_BUILD_STEP stays the standard `test` step, which is what this profile
# states explicitly. There are no `cross_build_command` / `cross_artifact`
# hooks here, so the harness keeps its standard Zig-build mode and runs
# `zig build test -Dtarget=TARGET` per target with a fresh cache. What that
# means for a given target is the harness's decision, not this package's: a
# host target runs, a foreign target runs under whatever executor the harness
# detects (QEMU user mode, Wine, wasmtime), and a foreign target with no
# executor is reported as build-only coverage -- compiled, never executed, and
# never counted as a pass. `build.zig` gives the test binary a Run step for
# every target, which is what leaves that choice open.
#
# A target graph compiles the whole upstream closure: the 108 translation units
# of `src/library/CMakeLists.txt`'s `src_crypto`, `src_x509` and `src_tls`
# lists -- 81 crypto, 9 X.509 and 18 TLS -- plus the five `3rdparty` units,
# 113 in all. Several of them are among the largest C files in the tree --
# `ecp_curves.c`, `ssl_tls.c`, `psa_crypto.c`, `ssl_msg.c`, `ssl_tls12_server.c`
# and `ssl_tls12_client.c` are all hundreds of kilobytes -- so each matrix cell
# compiles a lot of code and four build jobs is a deliberate, modest number.
#
# Nothing here narrows the gate to what is expected to work. Which platforms Mbed
# TLS supports is a property of this repository's own build graph, not of a
# setting: `zig/config_gen.zig` derives `MBEDTLS_NET_C` from the target's
# operating system, which is the same rule `src/library/common.h:34-46` applies
# to `MBEDTLS_PLATFORM_IS_UNIXLIKE` and `src/library/net_sockets.c:22-24`
# enforces. A cell that fails is a fact to record and diagnose; it is not a
# reason to drop the cell, sample the tests or remap Debug to an optimized mode
# to make it pass.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

CROSS_BUILD_STEP=test
CROSS_BUILD_JOBS=4
CROSS_BUILD_TIMEOUT=3600
CROSS_TIMEOUT=1800