# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{ inputs, ... }:
{
  imports = [
    inputs.flake-root.flakeModule
    inputs.treefmt-nix.flakeModule
  ];

  perSystem =
    {
      config,
      pkgs,
      ...
    }:
    {
      treefmt = {
        package = pkgs.treefmt;
        inherit (config.flake-root) projectRootFile;

        programs = {
          nixfmt.enable = true;
          nixfmt.package = pkgs.nixfmt;
          nixf-diagnose.enable = true;

          # Removes dead nix code https://github.com/astro/deadnix
          deadnix.enable = true;

          # Lints shell scripts https://github.com/koalaman/shellcheck
          # Disabled due to errors in legacy scripts that would fail CI
          shellcheck.enable = false;

          # Prevents use of nix anti-patterns https://github.com/nerdypepper/statix
          statix.enable = true;

          # C/C++ formatter
          clang-format = {
            enable = true;
            excludes = [
              # Exclude third-party libraries
              "chrome/hostapp/include/rapidjson/*"
              "chrome/hostapp/include/base64/*"
            ];
          };
        };

        settings.formatter = {
          clang-format = {
            options = [
              "-i"
              "--style=file"
            ];
          };

          # EOF fixer - adds missing newlines at end of files
          # Wrapped with 'sh -c' to always exit 0 (tool exits 1 when it makes changes)
          end-of-file-fixer = {
            command = "sh";
            options = [
              "-c"
              "${pkgs.python3Packages.pre-commit-hooks}/bin/end-of-file-fixer \"$@\" || true"
              "--"
            ];
            includes = [ "*" ];
            excludes = [
              "*.patch"
              "*.pdf"
              "chrome/**"
            ];
          };

          # Trailing whitespace fixer
          # Wrapped with 'sh -c' to always exit 0 (tool exits 1 when it makes changes)
          trailing-whitespace = {
            command = "sh";
            options = [
              "-c"
              "${pkgs.python3Packages.pre-commit-hooks}/bin/trailing-whitespace-fixer \"$@\" || true"
              "--"
            ];
            includes = [ "*" ];
            excludes = [
              "*.patch"
              "*.pdf"
              "chrome/**"
            ];
          };
        };
      };

      # Configures treefmt as the program to use when invoking `nix fmt`
      formatter = config.treefmt.build.wrapper;
    };
}
