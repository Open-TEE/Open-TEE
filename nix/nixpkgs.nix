# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{ inputs, ... }:
{
  perSystem =
    {
      system,
      lib,
      ...
    }:
    {
      # Customise pkgs for Open-TEE
      _module.args.pkgs = import inputs.nixpkgs {
        inherit system;
        config = {
          allowUnfree = false;
        };
      };

      # Make custom top-level lib available to all `perSystem` functions
      _module.args.lib = lib;
    };
}
