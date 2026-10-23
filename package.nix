# Source-only Nix derivation for Mbed TLS 3.6.7, shared by flake and devenv.
# `build.zig` compiles and installs the vendored source; Nix fixes ELF rpaths.
# `linkage` selects static/shared; `optimize` is forwarded, other SDK options use defaults.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# See FORK-LICENSE.md for what that identifier covers, and NOTICE.md for the
# per-file inventory of the upstream material in src/.

{ lib
, stdenv
, zig
, patchelf
  # Pass linkage to build.zig; static is the default.
, linkage ? "static"
, optimize ? "ReleaseSafe"
}:

let
  requestedLinkage =
    if builtins.elem linkage [ "" "static" "dynamic" ] then linkage
    else throw "package.nix: linkage must be \"\", \"static\" or \"dynamic\", not ${toString linkage}";

# Exclude build and developer-tool state; retain the vendored source tree.
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

# patchelf is used only for ELF rpath cleanup.
isElfTarget = !stdenv.hostPlatform.isDarwin && !stdenv.hostPlatform.isWindows;
in

# This derivation builds for the host platform and refuses Nix cross builds.
assert stdenv.buildPlatform.system == stdenv.hostPlatform.system;

stdenv.mkDerivation {
  pname = "mbed-tls";
  version = "3.6.7";

  inherit src;

  strictDeps = true;
  dontPatch = true;

  # installPhase runs `zig build install`; disable the default build phases.
  dontConfigure = true;
  dontBuild = true;

  nativeBuildInputs = [ zig ] ++ lib.optional isElfTarget patchelf;

  # The C closure propagates libc only.
  propagatedBuildInputs = [ stdenv.cc.libc ];

  # Nix checks are disabled; SDK gates run separately.
  doCheck = false;
  dontUseZigCheck = true;

  installPhase = ''
    runHook preInstall

    # Keep Zig caches under TMPDIR, outside the source tree.
    export ZIG_LOCAL_CACHE_DIR="$TMPDIR/zig-local-cache"
    export ZIG_GLOBAL_CACHE_DIR="$TMPDIR/zig-global-cache"

    # build.zig owns source lists, flags, target config and installed paths.
    zig build install \
      --prefix "$out" \
      -j"''${NIX_BUILD_CORES:-1}" \
      -Doptimize=${optimize} \
      ${lib.optionalString (requestedLinkage != "") "-Dlinkage=${requestedLinkage}"}

    # Remove transient cache rpaths from installed ELF files; preserve dependencies and symlinks.
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

  # build.zig defines the library, header, configuration and pkg-config layout.

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

    # Nix selects the Apache-2.0 arm; NOTICE.md records per-file licence exceptions.
    license = lib.licenses.asl20;

    # src/LICENSE carries both licence choices.
    licenseFiles = [ "src/LICENSE" ];

    # Nix metadata includes Unix and Windows; the flake exposes Unix systems.
    platforms = lib.platforms.unix ++ lib.platforms.windows;

  };
}
