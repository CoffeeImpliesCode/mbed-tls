# Flake interface for the Mbed TLS SDK.
#
# Portable counterpart to devenv.nix. Both call ./package.nix, so the package a
# flake builds and the package devenv builds are the same derivation; this file
# only decides which systems are exposed and which variants of that derivation
# they get.
#
# Canonical development is `devenv shell` (see devenv.nix and .envrc). This
# flake exists so the SDK can be built and consumed off this host. `nix develop`
# here is parity, not the canonical entry point, and it deliberately does not
# build the SDK: entering a shell must not require building a library.
#
# flake.lock is not written here: the driver owns locks.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# See FORK-LICENSE.md for what that identifier covers, and NOTICE.md for the
# per-file inventory of the upstream material in src/.

{
  description = "Mbed TLS 3.6.7, the portable TLS, X.509 and cryptography library, packaged for Zig 0.16";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/c7def046b9a883d46974757852106483d741586f";
  };

  outputs = { self, nixpkgs }:
    let
      # The same five Unix systems every sibling SDK exposes, and the same
      # boundary package.nix asserts underneath: it builds for the compiler's
      # native target rather than hand-building a cross triple. package.nix's
      # `meta.platforms` names Windows as well, because the source and the build
      # graph compile for `x86_64-windows-gnu` -- one of the six targets `check`
      # walks, and `MBEDTLS_PLATFORM_IS_UNIXLIKE` or `_WIN32` is what
      # `src/library/net_sockets.c:22-24` accepts. No Nix build on
      # `x86_64-windows` has been observed for this package, so this flake does
      # not publish one: exposing a system is a claim that it builds, and that
      # claim needs a run. Documented in README.md, not worked around here.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
        "x86_64-freebsd"
      ];

      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs:
        let
          mk = linkage: pkgs.callPackage ./package.nix {
            inherit linkage;
            zig = pkgs.zig_0_16;
          };
        in
        {
          static = mk "static";

          # A separate variant of the same derivation, not a second SDK.
          # "shared" names the artefact; the flag it passes is Zig's own
          # `-Dlinkage=dynamic`, and the sonames it produces are upstream's own
          # ABI numbers rather than this fork's.
          shared = mk "dynamic";

          default = mk "static";
        });

      # Parity only. The canonical development environment is devenv.nix.
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [ pkgs.zig_0_16 pkgs.gnumake pkgs.pkg-config ];
        };
      });
    };
}
