# Canonical development environment; its shell installs tools, not the SDK.
# Static and shared outputs reuse package.nix and build lazily.

# Tasks enter this checkout and keep Zig caches outside it.
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# See FORK-LICENSE.md for what that identifier covers, and NOTICE.md for the
# per-file inventory of the upstream material in src/.

{ pkgs, ... }:

let
  # Use the pinned Zig compiler.
  zig = pkgs.zig_0_17;

  mbed_tls = linkage: pkgs.callPackage ./package.nix {
    inherit linkage;
    zig = zig;
  };

  # Resolve this checkout from the file, independent of the caller's directory.
  sdk_root = builtins.toString ./.;

  # Preserve caller cache directories; otherwise use external defaults.
  zig_caches = ''
    if [ -z "''${ZIG_LOCAL_CACHE_DIR:-}" ]; then
      if [ -n "''${XDG_CACHE_HOME:-}" ]; then
        export ZIG_LOCAL_CACHE_DIR="$XDG_CACHE_HOME/mbed-tls/zig-local-cache"
      elif [ -n "''${TMPDIR:-}" ]; then
        export ZIG_LOCAL_CACHE_DIR="$TMPDIR/mbed-tls/zig-local-cache"
      fi
    fi
    if [ -z "''${ZIG_GLOBAL_CACHE_DIR:-}" ]; then
      if [ -n "''${XDG_CACHE_HOME:-}" ]; then
        export ZIG_GLOBAL_CACHE_DIR="$XDG_CACHE_HOME/mbed-tls/zig-global-cache"
      elif [ -n "''${TMPDIR:-}" ]; then
        export ZIG_GLOBAL_CACHE_DIR="$TMPDIR/mbed-tls/zig-global-cache"
      fi
    fi
    if [ -n "''${ZIG_LOCAL_CACHE_DIR:-}" ]; then
      mkdir -p "$ZIG_LOCAL_CACHE_DIR"
    fi
    if [ -n "''${ZIG_GLOBAL_CACHE_DIR:-}" ]; then
      mkdir -p "$ZIG_GLOBAL_CACHE_DIR"
    fi
  '';

  # Stop tasks when no external output directory is available.
  require_external_output = ''
    if [ -z "''${ZIG_LOCAL_CACHE_DIR:-}" ]; then
      echo "mbed-tls devenv: ZIG_LOCAL_CACHE_DIR, XDG_CACHE_HOME and TMPDIR are all unset," >&2
      echo "so there is nowhere outside this checkout to put build output." >&2
      echo "Export one of them at approved scratch, then run the task again." >&2
      exit 1
    fi
  '';

  # Enter this checkout before local build tasks.
  in_sdk = ''
    ${zig_caches}
    ${require_external_output}
    cd "${sdk_root}" || exit 1
  '';

  # Shared build flags; caller arguments remain last.
  native_flags = ''
    -j8 --summary all --cache-dir "$ZIG_LOCAL_CACHE_DIR/native" "''$@"
  '';

  # Give the nested consumer its own cache.
  consumer_flags = ''
    -j8 --summary all --cache-dir "$ZIG_LOCAL_CACHE_DIR/consumer" "''$@"
  '';
in
{
  packages = [
    zig
    pkgs.gnumake
    pkgs.pkg-config
    pkgs.valgrind
  ];

  assertions = [
    {
      assertion = zig.version == "0.17.0";
      message = "The Mbed TLS SDK requires Zig 0.17.0; nixpkgs resolved zig_0_17 to ${zig.version}";
    }
  ];

  # Export the same cache directories in the interactive shell.
  enterShell = ''
    ${zig_caches}
  '';

  # Lazy static/shared outputs; entering the shell builds neither.
  outputs.static = mbed_tls "static";
  outputs.shared = mbed_tls "dynamic";
  outputs.default = mbed_tls "static";

  # Use namespace:name task identifiers.
  tasks = {
    # Install under an external prefix, not in the checkout.
    "sdk:build" = {
      description = ''
        Compile the three native libraries, libmbedcrypto, libmbedx509 and
        libmbedtls (default step), and install the delivery tree under the
        external cache rather than in this checkout.
      '';
      exec = ''
        ${in_sdk}
        zig build --prefix "$ZIG_LOCAL_CACHE_DIR/prefix/static" ${native_flags}
      '';
    };

    "sdk:build:shared" = {
      description = ''
        Compile the three native libraries as shared objects instead of archives,
        and install them under their own external prefix.
      '';
      exec = ''
        ${in_sdk}
        zig build -Dlinkage=dynamic --prefix "$ZIG_LOCAL_CACHE_DIR/prefix/dynamic" ${native_flags}
      '';
    };

    # These gates run or compile and do not install.
    "sdk:test" = {
      description = "Run the behavioural tests";
      exec = ''
        ${in_sdk}
        zig build test ${native_flags}
      '';
    };

    "sdk:test:release-safe" = {
      description = "Run the behavioural tests in ReleaseSafe";
      exec = ''
        ${in_sdk}
        zig build test -Doptimize=ReleaseSafe ${native_flags}
      '';
    };

    "sdk:smoke" = {
      description = "Run the deterministic example";
      exec = ''
        ${in_sdk}
        zig build smoke ${native_flags}
      '';
    };

    "sdk:check" = {
      description = "Compile and link every public entry point for all six targets in the matrix, wasm32-wasi included, without running any of them";
      exec = ''
        ${in_sdk}
        zig build check ${native_flags}
      '';
    };

    "sdk:check:shared" = {
      description = "The same six-target compile check against the shared objects";
      exec = ''
        ${in_sdk}
        zig build check -Dlinkage=dynamic ${native_flags}
      '';
    };

    # Run the separate consumer package from its own directory.
    "sdk:consumer" = {
      description = "Build and run the separate consumer package against this SDK";
      exec = ''
        ${in_sdk}
        cd consumer
        zig build run ${consumer_flags}
      '';
    };

    # Run provenance checks against this checkout.
    "sdk:provenance" = {
      description = ''
        Check the 336 digests UPSTREAM.sha256 records, the exact native file
        set, the preserved upstream README bytes and Mbed TLS's own dual-grant
        statement. This is a source-integrity check, not a build gate.
      '';
      exec = ''
        ${in_sdk}
        bash tools/check-provenance.sh
      '';
    };

    # Nested devenv builds use the caller's project and write outputs to the Nix store.
    "sdk:package:static" = {
      description = ''
        Build the static Nix variant through devenv's own lazy output. No lock
        is needed by this path; `devenv build outputs.static` resolves the
        pinned input from devenv.lock, which the driver owns.
      '';
      exec = "devenv build outputs.static";
    };

    "sdk:package:shared" = {
      description = "Build the shared Nix variant through devenv's own lazy output";
      exec = "devenv build outputs.shared";
    };
  };
}
