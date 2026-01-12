# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{ inputs, ... }:
{
  imports = [ inputs.git-hooks-nix.flakeModule ];

  perSystem =
    {
      config,
      lib,
      ...
    }:
    {
      # Checks are automatically provided by git-hooks-nix.flakeModule:
      # - checks.${system}.pre-commit: runs all pre-commit hooks (treefmt, reuse, etc.)
      #
      # Developer workflow:
      # - nix/devshell.nix uses config.pre-commit.installationScript to install
      #   git hooks into .git/hooks/ when entering the dev environment
      # - The hooks run automatically on `git commit` for staged files only
      #
      # CI workflow:
      # - checks.${system}.pre-commit runs all hooks on all tracked files
      # - Can be run with `nix flake check` to enforce code standards

      checks = {
        # Check that copyright headers are compliant
        # Disabled until license files are added to LICENSES/ directory
        # To enable: run `reuse download --all` first
        # reuse =
        #   pkgs.runCommandLocal "reuse-lint" {
        #     nativeBuildInputs = [pkgs.reuse];
        #   } ''
        #     cd ${../.}
        #     reuse lint
        #     touch $out
        #   '';
      }
      //
        # Merge in the package derivations to force a build of all packages during a `nix flake check`
        (with lib; mapAttrs' (n: nameValuePair "package-${n}") config.packages);

      pre-commit = {
        settings = {
          hooks = {
            treefmt = {
              enable = true;
              package = config.treefmt.build.wrapper;
              # Run on pre-commit to only check staged files
              stages = [ "pre-commit" ];
            };
            # Reuse hook disabled until license files are added
            # reuse = {
            #   enable = true;
            #   package = pkgs.reuse;
            #   # Run on pre-commit to only check staged files
            #   stages = ["pre-commit"];
            # };
            # EOF fixer enabled - with exclusions for third-party code
            end-of-file-fixer = {
              enable = true;
              # Run on pre-commit to only check staged files
              stages = [ "pre-commit" ];
              # Exclude files that should not be modified
              excludes = [
                ".*\\.patch$"
                ".*\\.pdf$"
                "^chrome/.*"
              ];
            };
            trim-trailing-whitespace = {
              enable = true;
              # Run on pre-commit to only check staged files
              stages = [ "pre-commit" ];
              # Exclude files that should not be modified
              excludes = [
                ".*\\.patch$"
                ".*\\.pdf$"
                "^chrome/.*"
              ];
            };
          };
        };
      };
    };
}
