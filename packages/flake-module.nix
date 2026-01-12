# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  perSystem =
    {
      pkgs,
      lib,
      self',
      ...
    }:
    {
      packages = {
        # Main Open-TEE package
        open-tee = pkgs.stdenv.mkDerivation {
          pname = "open-tee";
          version = "0.0.0";

          src = lib.cleanSource ../.;

          nativeBuildInputs = with pkgs; [
            autoreconfHook
            autoconf
            automake
            libtool
            pkg-config
          ];

          buildInputs = with pkgs; [
            fuse
            libelf
            libuuid
            mbedtls
            openssl
            zlib
          ];

          # Run autogen.sh during the configure phase
          preConfigure = ''
            ./autogen.sh
          '';

          configureFlags = [
            "--prefix=${placeholder "out"}"
          ];

          enableParallelBuilding = true;

          meta = with lib; {
            description = "An open-source GlobalPlatform TEE compliant virtual Trusted Execution Environment";
            homepage = "https://github.com/Open-TEE/Open-TEE";
            license = licenses.asl20;
            platforms = platforms.linux;
            maintainers = [ ];
          };
        };

        # Default package
        default = self'.packages.open-tee;
      };
    };
}
