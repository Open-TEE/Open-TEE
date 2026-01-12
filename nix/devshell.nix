# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  perSystem =
    {
      config,
      pkgs,
      lib,
      ...
    }:
    {
      devShells.default = pkgs.mkShell {
        name = "Open-TEE-dev-shell";
        meta.description = "Open-TEE development environment";

        packages =
          with pkgs;
          [
            # Build tools
            autoreconfHook
            autoconf
            automake
            libtool
            pkg-config
            gnumake
            gcc

            # Core dependencies
            coreutils
            curl
            fuse
            gnugrep
            gnused
            gzip
            libelf
            libuuid
            mbedtls
            openssl
            zlib

            # Development tools
            git
            gdb
            nix
            ripgrep
            reuse

            # Formatters and linters (from treefmt)
          ]
          ++ config.pre-commit.settings.enabledPackages
          ++ lib.attrValues config.treefmt.build.programs;

        shellHook = ''
          echo "🔐 Open-TEE Development Environment"
          echo "======================================"
          echo ""
          echo "Available commands:"
          echo "  - autogen.sh        : Generate autotools build files"
          echo "  - ./configure       : Configure the build"
          echo "  - make              : Build the project"
          echo "  - nix fmt           : Format code"
          echo "  - nix flake check   : Run all checks"
          echo ""

          # Install git hooks
          ${config.pre-commit.installationScript}
        '';
      };
    };
}
