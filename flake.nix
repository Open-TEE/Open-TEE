# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  description = "Open-TEE - GP emulator";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = {
    self,
    nixpkgs,
    ...
  }: let
    pkgs = nixpkgs.legacyPackages.x86_64-linux;
    opentee = import ./default.nix {
      inherit pkgs;
    };
    kill-opentee-sh = pkgs.writeShellScriptBin "kill-opentee" ''
      pkill -9 tee_manager
    '';
    start-opentee-sh = pkgs.writeShellScriptBin "start-opentee" ''
      pkill -9 tee_manager
      ${opentee}/bin/opentee-engine -c ${opentee}//opentee.conf
    '';
    status-opentee-sh = pkgs.writeShellScriptBin "status-opentee" ''
      printf "\n\n*Opentee status* :: If tee_manager AND tee_launcher listed --> opentee running\n\n\n"
      ps waux | grep tee_
    '';
  in {
    packages.x86_64-linux.opentee = opentee;
    devShells.x86_64-linux.default = opentee.shell;
    formatter.x86_64-linux = pkgs.alejandra;
    apps.x86_64-linux = rec {
      start-opentee = {
        type = "app";
        #program = "${self.packages.x86_64-linux.opentee}/bin/opentee-engine -c ${self.packages.x86_64-linux.opentee}/opentee.conf";
        program = "${start-opentee-sh}/bin/start-opentee";
        meta.description = "Starts opentee engine";
      };
      test-opentee = {
        type = "app";
        program = "${self.packages.x86_64-linux.opentee}/bin/conn_test";
        meta.description = "Executes opentee connection test app";
      };
      kill-opentee = {
        type = "app";
        program = "${kill-opentee-sh}/bin/kill-opentee";
        meta.description = "just for convenience";
      };
      status-opentee = {
        type = "app";
        program = "${status-opentee-sh}/bin/status-opentee";
        meta.description = "just for convenience";
      };
    };
  };
}
