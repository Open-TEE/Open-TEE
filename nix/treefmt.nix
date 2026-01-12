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
      treefmt.config = {
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
        };
      };

      # Configures treefmt as the program to use when invoking `nix fmt`
      formatter = config.treefmt.build.wrapper;
    };
}
