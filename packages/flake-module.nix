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
        # Main Open-TEE package (CMake build)
        open-tee = pkgs.stdenv.mkDerivation {
          pname = "open-tee";
          version = "0.0.1";

          src = lib.cleanSource ../.;

          nativeBuildInputs = with pkgs; [
            cmake
            ninja
            pkg-config
            qt6.wrapQtAppsHook
          ];

          buildInputs = with pkgs; [
            fuse
            libelf
            libuuid
            mbedtls
            msgpack-cxx
            openssl
            qt6.qtbase
            zlib
          ];

          # Use CMake preset for release build
          cmakeFlags = [
            "-DCMAKE_BUILD_TYPE=Release"
            "-DOPENTEE_BUILD_TESTS=ON"
            "-DOPENTEE_BUILD_EXAMPLES=ON"
            "-DCMAKE_COLOR_DIAGNOSTICS=ON"
          ];

          # Install TAs to the correct location
          postInstall = ''
            # Ensure TA directory exists
            mkdir -p $out/lib/TAs
            # Move TAs from lib to lib/TAs if they were installed to lib
            for ta in $out/lib/lib*.so; do
              if [ -f "$ta" ]; then
                # Check if it's a TA (has TA_PLUGIN symbol or is in TAs list)
                name=$(basename "$ta")
                case "$name" in
                  libpkcs11_ta.so|libexample_ta.so|libexample_digest.so|libsign_ecdsa_256.so|\
                  libta_conn_test.so|libta2ta_conn_test.so|libta_panic_crash.so|libta_services.so|\
                  libuser_study.so|libCryptoTest.so|libStorageTest.so|libta2taTest.so)
                    mv "$ta" $out/lib/TAs/ 2>/dev/null || true
                    ;;
                esac
              fi
            done
          '';

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
