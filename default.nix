# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
# SPDX-FileCopyrightText: 2020-2023 Eelco Dolstra and the flake-compat contributors
#
# SPDX-License-Identifier: MIT
# This file originates from:
# https://github.com/nix-community/flake-compat
# This file provides backward compatibility to nix < 2.4 clients
{
  system ? builtins.currentSystem,
  pkgs ?
    import <nixpkgs> {
      overlays = [];
      config = {};
      inherit system;
    },
}: let
  mbedtls-3_1_0 =
    (pkgs.callPackage "${toString pkgs.path}/pkgs/development/libraries/mbedtls/generic.nix" {
      version = "3.1.0";
      hash = "sha256-esQe1qnM1yBzNPpd+qog3/8guttt6CKUiyzIQ1nMfJs=";
    }).overrideAttrs (finalAttrs: previousAttrs: {
      doCheck = false;
      NIX_CFLAGS_COMPILE = "-Wno-calloc-transposed-args";
    });
  opentee = pkgs.stdenv.mkDerivation {
    name = "opentee";
    src = ./.;
    nativeBuildInputs = with pkgs; [
      autoreconfHook
      autoconf
      automake
      coreutils
      curl
      fuse
      gnugrep
      gnused
      gzip
      libelf
      mbedtls-3_1_0
      nix
      pkg-config
      ripgrep-all
      zlib
    ];
    installPhase = ''
      runHook preInstall
      make install

      echo -e "[PATHS]\nta_dir_path = $out/lib/TAs\ncore_lib_path = $out/lib\nsubprocess_manager = libManagerApi.so\nsubprocess_launcher = libLauncherApi.so" > /$out/opentee.conf

      runHook postInstall
    '';
    passthru = {
      inherit pkgs shell;
    };
  };
  shell = pkgs.mkShell {
    inputsFrom = [
      opentee
    ];
  };
in
  opentee
