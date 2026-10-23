# Flake variants for the Mbed TLS package; `package.nix` owns the derivation.
#
# Canonical development shell: `devenv.nix`.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# See FORK-LICENSE.md for what that identifier covers, and NOTICE.md for the
# per-file inventory of the upstream material in src/.

{
  description = "Mbed TLS 3.6.7, the portable TLS, X.509 and cryptography library, packaged for Zig 0.17";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/02c087f3fe673c9e317f206a627cb6b910336dbe";
  };

  outputs = { self, nixpkgs }:
    let
      # Nix exposes Unix hosts; the Zig matrix also includes x86_64-windows-gnu.
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
            zig = pkgs.zig_0_17;
          };
        in
        {
          static = mk "static";

          # Shared variant of the same derivation, with dynamic linkage.
          shared = mk "dynamic";

          default = mk "static";
        });

      # The canonical development shell is in devenv.nix.
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [ pkgs.zig_0_17 pkgs.gnumake pkgs.pkg-config ];
        };
      });
    };
}
