# cross-test uses Zig 0.16's full Tier 1/2 matrix and standard `test` step.
# Targets without an executor are build-only; the profile sets no target subset.
# Four build jobs and bounded build/run time.
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

CROSS_BUILD_STEP=test
CROSS_BUILD_JOBS=4
CROSS_BUILD_TIMEOUT=3600
CROSS_TIMEOUT=1800