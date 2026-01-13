# SPDX-FileCopyrightText: 2024 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{ inputs, self, ... }:
{
  imports = [
    inputs.flake-root.flakeModule
    inputs.treefmt-nix.flakeModule
  ];

  perSystem =
    { config, lib, ... }:
    {
      # Configure devenv as the default (and only) development shell
      devenv.shells.default = {
        # Import the main devenv configuration
        imports = [ ../devenv.nix ];

        # Set name for the shell
        name = "Open-TEE";

        # devenv.root is automatically set by direnv via devenv-root input
        # For non-direnv usage (e.g., nix develop --impure), use self.outPath
        devenv.root =
          let
            devenvRootFileContent = builtins.readFile inputs.devenv-root.outPath;
          in
          # If devenv-root input has content (direnv case), use it
          # Otherwise fall back to self.outPath (non-direnv case)
          lib.mkDefault (
            if devenvRootFileContent != "" then devenvRootFileContent else toString self.outPath
          );

        # Integrate git-hooks (pre-commit) from the existing checks.nix configuration
        git-hooks.hooks = {
          # Use treefmt from our treefmt.nix configuration
          treefmt = {
            enable = true;
            # Use packageOverrides to specify the treefmt wrapper
            packageOverrides.treefmt = config.treefmt.build.wrapper;
            # Pass formatter packages from treefmt configuration
            settings.formatters = lib.attrValues config.treefmt.build.programs;
          };

          # EOF fixer enabled - with exclusions for third-party code
          end-of-file-fixer = {
            enable = true;
            excludes = [
              ".*\\.patch$"
              ".*\\.pdf$"
              "^chrome/.*"
            ];
          };

          # Trim trailing whitespace
          trim-trailing-whitespace = {
            enable = true;
            excludes = [
              ".*\\.patch$"
              ".*\\.pdf$"
              "^chrome/.*"
            ];
          };
        };

        # Include packages from treefmt configuration (formatters)
        packages = lib.attrValues config.treefmt.build.programs;
      };
    };
}
