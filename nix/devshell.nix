# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  perSystem = {
    pkgs,
    self',
    ...
  }: {
    devShells.default = pkgs.mkShell rec {
      name = "OpenTEE-dev-shell";

      packages = with pkgs; [
        autoreconfHook
        coreutils
        curl
        fuse
        fuse-common
        gnugrep
        gnused
        gzip
        libelf
        mbedtls
        nix
        pkg-config
        ripgrep-all
        zlib
      ];

      shellHook = ''
      '';
    };
  };
}
