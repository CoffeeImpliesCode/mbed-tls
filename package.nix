# Source-only package derivation for the Mbed TLS SDK.
#
# One file, consumed by both flake.nix and devenv.nix, so the two entry points
# cannot describe different packages. It builds nothing but this repository: the
# native source is upstream's `src/`, which is the complete Mbed TLS 3.6.7
# release subtree -- the public headers, every translation unit of libmbedcrypto,
# libmbedx509 and libmbedtls, the bundled Everest and p256-m sources, upstream's
# configuration fragments and upstream's own build files -- imported whole from
# the `mbedtls-3.6.7` release tarball, and build.zig owns every compile flag and
# the whole installed layout. Nothing here restates a C flag, fetches a tarball,
# reaches into a sibling checkout, or installs an artifact of its own. The one
# edit it makes is the rpath of the ELF files the build installed: Zig records
# its own build cache there, and that directory does not exist once a binary is
# installed.
#
# The only build option passed through is `linkage`, plus `optimize` which Zig
# owns. The SDK's other two options (`system` and `runtime`) keep their own
# defaults on this route: system mode needs an installed Mbed TLS with its own
# headers, and runtime mode is for a dependent that loads the C library through
# a dispatch table, which a Nix package of the archives is not.
#
# No lock file is written here. `flake.lock` and `devenv.lock` belong to the
# driver.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# See FORK-LICENSE.md for what that identifier covers, and NOTICE.md for the
# per-file inventory of the upstream material in src/.

{ lib
, stdenv
, zig
, patchelf
  # Zig's own `std.builtin.LinkMode` spelling, passed straight through as
  # `-Dlinkage`. "static" and "dynamic" are two variants of one derivation, and
  # `""` passes nothing at all so the SDK's own default policy runs unchanged.
  # Mbed TLS upstream ships both a static archive and a shared object for every
  # library, so neither variant is this fork's invention; static is this fork's
  # default and `.shared` is the separate variant.
, linkage ? "static"
, optimize ? "ReleaseSafe"
}:

let
  requestedLinkage =
    if builtins.elem linkage [ "" "static" "dynamic" ] then linkage
    else throw "package.nix: linkage must be \"\", \"static\" or \"dynamic\", not ${toString linkage}";

# Everything except build outputs, version control and developer-tool state.
# Filtering by directory name rather than by an allow list means a file added
# here later is packaged without editing this file, while `.zig-cache/`,
# `zig-out/`, `.devenv/`, `.direnv/` and `result` stay out of a published output
# at any depth, including under consumer/. Upstream's `library/Makefile`,
# `library/CMakeLists.txt`, `3rdparty/` build files, `configs/` fragments,
# ChangeLog, SECURITY.md and both licence texts are deliberately kept: they are
# upstream material with digests in UPSTREAM.sha256, and the audit surface is
# the whole upstream tree.
src = lib.cleanSourceWith {
  src = ./.;
  filter = path: _type:
    let name = builtins.baseNameOf (toString path); in
    !(lib.elem name [
      ".git"
      ".direnv"
      ".devenv"
      ".zig-cache"
      "zig-cache"
      "zig-pkg"
      "zig-out"
      "result"
    ]);
};

# patchelf rewrites ELF rpaths and does not read Mach-O or PE/COFF, so the rpath
# normalisation in the install phase exists for ELF targets only, and the tool
# is a build input exactly where that code runs.
isElfTarget = !stdenv.hostPlatform.isDarwin && !stdenv.hostPlatform.isWindows;
in

# These packages build for the compiler's own native target. A cross build here
# would mean hand-building a libc-suffixed triple that has to track nixpkgs, so
# this derivation refuses one instead of silently producing a host-architecture
# library under a foreign name. The comparison is against stdenv's own
# platforms, which are pure values; `builtins.currentSystem` is not evaluable
# in a sandbox and is not used. A remote builder is unaffected: this compares
# build against host, not against any particular machine.
assert stdenv.buildPlatform.system == stdenv.hostPlatform.system;

stdenv.mkDerivation {
  pname = "mbed-tls";
  version = "3.6.7";

  inherit src;

  strictDeps = true;
  dontPatch = true;

  # The real work is one `zig build install` in installPhase below. Disabling
  # configure and build phases keeps the Zig setup hook from running a first,
  # differently-flagged build of its own; `dontInstall` is deliberately NOT set,
  # because that is what would disable the real install phase.
  dontConfigure = true;
  dontBuild = true;

  nativeBuildInputs = [ zig ] ++ lib.optional isElfTarget patchelf;

  # The C library is the whole of the native dependency closure, and that is a
  # reading of the vendored tree rather than an assumption:
  # `src/include/mbedtls/mbedtls_config.h:3787` leaves `MBEDTLS_THREADING_C`
  # commented out, so `src/library/threading.c` compiles to nothing and nothing
  # in the closure reaches for pthread; no translation unit under
  # `src/library/` includes `<math.h>`, so no libm; and the Windows sockets path
  # in `net_sockets.c` is inside the host platform's own stdenv rather than a
  # separate input. Nothing else is propagated.
  propagatedBuildInputs = [ stdenv.cc.libc ];

  # The driver owns every gate for this SDK, and a Nix build is not a
  # verification receipt. No check phase is declared here rather than a check
  # phase that runs something smaller than the real gates; the commands that do
  # verify this package are in README.md and CHANGELOG.md.
  doCheck = false;
  dontUseZigCheck = true;

  installPhase = ''
    runHook preInstall

    # Both caches go under the Nix-provided TMPDIR, outside the unpacked source
    # tree, so a build cannot write into $src and so two parallel derivations
    # cannot share state. Any caller-supplied cache variables are left alone:
    # they are the caller's scratch, not this file's to clear.
    export ZIG_LOCAL_CACHE_DIR="$TMPDIR/zig-local-cache"
    export ZIG_GLOBAL_CACHE_DIR="$TMPDIR/zig-global-cache"

    # build.zig owns the source list, the C flags, the per-target generated
    # `mbedtls_config.h`, the pkg-config file and every installed path.
    # Declaring any of them here as well would create a second place where they
    # can disagree with the build graph.
    zig build install \
      --prefix "$out" \
      -j"''${NIX_BUILD_CORES:-1}" \
      -Doptimize=${optimize} \
      ${lib.optionalString (requestedLinkage != "") "-Dlinkage=${requestedLinkage}"}

    # Zig records the build cache in the rpath of anything that links a dynamic
    # artifact it has just built (lib/std/Build/Step/Compile.zig:1192-1199), so
    # an installed library names a directory that is gone, and Nix rejects an
    # installed file that names its build directory at all. Both Zig caches above
    # are under $TMPDIR, so dropping those entries and no other removes it: the
    # $ORIGIN/../lib build.zig adds, and every store path a real dependency
    # needs, stay. Symlinks are resolved first so a soname link is rewritten
    # through to the object and never replaced by a copy of it.
    #
    # Only `$out/lib/*.so*` is walked. This package installs no program, so
    # there is no `$out/bin` to sweep, and the smoke example `build.zig` places
    # in the install graph is a build artefact rather than a delivery.
    ${lib.optionalString isElfTarget ''
      for elf in "$out"/lib/*.so*; do
        [ -f "$elf" ] || continue
        elf=$(readlink -f "$elf")
        rpath=$(patchelf --print-rpath "$elf") || rpath=""
        kept=""
        rest=$rpath
        while [ -n "$rest" ]; do
          entry="''${rest%%:*}"
          case "$entry" in
            "$TMPDIR"/*) ;;
            *) if [ -z "$kept" ]; then kept=$entry; else kept=$kept:$entry; fi ;;
          esac
          if [ "$entry" = "$rest" ]; then rest=""; else rest="''${rest#*:}"; fi
        done
        [ "$kept" = "$rpath" ] || patchelf --set-rpath "$kept" "$elf"
      done
    ''}

    runHook postInstall
  '';

  # The layout this derivation produces is the build graph's, not this file's:
  # $out/lib/libmbedcrypto.a, $out/lib/libmbedx509.a and $out/lib/libmbedtls.a
  # (or libmbedcrypto.so.16, libmbedx509.so.7 and libmbedtls.so.21, each with
  # its unversioned `.so` loader-name symlink, in the shared variant),
  # $out/include/mbedtls/ and $out/include/psa/ -- including the generated
  # $out/include/mbedtls/mbedtls_config.h under the canonical name the headers
  # reach it by, which is why a consumer needs no compile macro at all -- and
  # $out/lib/pkgconfig/mbedtls.pc. Nothing is copied or generated by hand here,
  # so `zig build install --prefix $out` and `nix build` produce one layout by
  # construction rather than two that have to be kept in agreement.

  enableParallelBuilding = true;

  meta = {
    description = "Mbed TLS 3.6.7, the portable TLS, X.509 and cryptography library, built from the pinned upstream release sources";
    longDescription = ''
      The complete Mbed TLS 3.6.7 release subtree -- the public headers, every
      translation unit of libmbedcrypto, libmbedx509 and libmbedtls, and the
      bundled Everest and p256-m sources the library compiles -- compiled from
      the tarball's own src/ directory with Zig, with no autotools, no CMake and
      no build-time download. Ships the three libraries, the public headers, the
      generated configuration header and a pkg-config file.
    '';

    # `meta.license` takes one SPDX expression, and Mbed TLS's grant is a
    # disjunction: `src/LICENSE:1-4` states "a dual [Apache-2.0] OR
    # [GPL-2.0-or-later] license. This means that users may choose which of
    # these licences they take the code under", and 285 files under src/ carry
    # the same identifier as their SPDX tag. A single label therefore cannot
    # carry the whole grant, and NOTICE.md is authoritative for what this
    # package actually ships.
    #
    # The arm recorded here is Apache-2.0, for three reasons that are all
    # statements about this tree rather than preferences. It is the permissive
    # arm, so a dependant choosing it is not obliged to release anything. It is
    # the arm this fork's own files are tagged with, matching upstream's primary
    # term. And it is compatible with the exceptions the inventory records:
    # `src/3rdparty/everest/**` is Apache-2.0 only (INRIA and Microsoft
    # Corporation), which this arm covers exactly, and
    # `src/configs/ext/crypto_config_profile_medium.h` is BSD-3-Clause (Arm
    # Limited), which no single label can describe -- which is why the label
    # below is a statement about the core library and NOT an inventory.
    license = lib.licenses.asl20;

    # Both texts of the disjunction live in this one file, so it is the file
    # that records the whole grant even though `license` names one arm.
    licenseFiles = [ "src/LICENSE" ];

    # Unix and Windows, not `lib.platforms.unix`. That is not a guess about the
    # source: `x86_64-windows-gnu` is one of the six targets `zig build check`
    # compiles, and the only platform-conditional code in the compiled closure is
    # `src/library/net_sockets.c`, whose `#error` accepts `_WIN32` as well as
    # MBEDTLS_PLATFORM_IS_UNIXLIKE (`src/library/common.h:34-46`). What has been
    # observed here is a Zig cross-compile for that target, not a Nix build on
    # `x86_64-windows`, which is why flake.nix still publishes only Unix systems.
    platforms = lib.platforms.unix ++ lib.platforms.windows;

    # No `mainProgram`: build.zig installs the three libraries, their headers
    # and the pkg-config file, and builds the smoke example without installing it
    # as a program, so this output has no executable to name.
  };
}
