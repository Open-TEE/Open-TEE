# SPDX-FileCopyrightText: 2024 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  pkgs,
  config,
  openTeeDeps,
  ...
}:

{
  # https://devenv.sh/basics/
  env = {
    # Open-TEE socket and storage paths using devenv state directory
    OPENTEE_SOCKET_FILE_PATH = "${config.env.DEVENV_STATE}/open_tee_sock";
    OPENTEE_STORAGE_PATH = "${config.env.DEVENV_STATE}/TEE_secure_storage";

    # Build output directory
    OPENTEE_BUILD_DIR = "${config.env.DEVENV_ROOT}/build";
  };

  # https://devenv.sh/packages/
  packages = [
    # Additional development tools (not needed for building the package itself)
    pkgs.gnumake
    pkgs.gcc
    pkgs.coreutils
    pkgs.curl
    pkgs.gnugrep
    pkgs.gnused
    pkgs.gzip
    pkgs.git
    pkgs.gdb
    pkgs.ripgrep
    pkgs.reuse
  ]
  ++ openTeeDeps.nativeBuildInputs # use shared dependencies from the package
  ++ openTeeDeps.buildInputs;

  # https://devenv.sh/scripts/
  scripts = {
    # Build scripts
    opentee-build.exec = ''
      # Create build directory
      mkdir -p "$OPENTEE_BUILD_DIR"
      cd "$OPENTEE_BUILD_DIR"

      # Run autogen.sh from build directory if configure doesn't exist
      if [ ! -f "$OPENTEE_BUILD_DIR/configure" ]; then
        echo "Running autogen.sh from build directory..."
        ../autogen.sh
      fi

      # Run configure if Makefile doesn't exist
      if [ ! -f "$OPENTEE_BUILD_DIR/Makefile" ]; then
        echo "Running configure..."
        ./configure
      fi

      echo "Building Open-TEE..."
      make -j$(nproc)
      echo "✓ Build complete!"
      echo ""
      echo "Engine binary: $OPENTEE_BUILD_DIR/emulator/opentee-engine"
      echo "Test binaries: $OPENTEE_BUILD_DIR/CAs/"
      echo "Libraries: $OPENTEE_BUILD_DIR/emulator/.libs/"
      echo "TAs: $OPENTEE_BUILD_DIR/TAs/.libs/"
    '';

    opentee-clean.exec = ''
      if [ -d "$OPENTEE_BUILD_DIR" ]; then
        cd "$OPENTEE_BUILD_DIR"
        make clean
        echo "✓ Build cleaned"
      else
        echo "No build directory found"
      fi
    '';

    opentee-distclean.exec = ''
      if [ -d "$OPENTEE_BUILD_DIR" ]; then
        echo "Removing build directory: $OPENTEE_BUILD_DIR"
        rm -rf "$OPENTEE_BUILD_DIR"
        echo "✓ Build directory removed"
      else
        echo "No build directory found"
      fi
    '';

    # Test application runners
    test-conn.exec = ''
      if [ ! -f "$OPENTEE_BUILD_DIR/CAs/conn_test" ]; then
        echo "Error: conn_test not found. Run 'opentee-build' first."
        exit 1
      fi
      export LD_LIBRARY_PATH="$OPENTEE_BUILD_DIR/libtee/.libs:$LD_LIBRARY_PATH"
      "$OPENTEE_BUILD_DIR/CAs/.libs/conn_test"
    '';

    test-services.exec = ''
      if [ ! -f "$OPENTEE_BUILD_DIR/tests/services_test" ]; then
        echo "Error: services_test not found. Run 'opentee-build' first."
        exit 1
      fi
      export LD_LIBRARY_PATH="$OPENTEE_BUILD_DIR/libtee/.libs:$LD_LIBRARY_PATH"
      "$OPENTEE_BUILD_DIR/tests/.libs/services_test"
    '';

    test-sha1.exec = ''
      if [ ! -f "$OPENTEE_BUILD_DIR/CAs/example_sha1" ]; then
        echo "Error: example_sha1 not found. Run 'opentee-build' first."
        exit 1
      fi
      export LD_LIBRARY_PATH="$OPENTEE_BUILD_DIR/libtee/.libs:$LD_LIBRARY_PATH"
      "$OPENTEE_BUILD_DIR/CAs/.libs/example_sha1"
    '';

    test-pkcs11.exec = ''
      if [ ! -f "$OPENTEE_BUILD_DIR/CAs/pkcs11_test" ]; then
        echo "Error: pkcs11_test not found. Run 'opentee-build' first."
        exit 1
      fi
      export LD_LIBRARY_PATH="$OPENTEE_BUILD_DIR/libtee/.libs:$LD_LIBRARY_PATH"
      "$OPENTEE_BUILD_DIR/CAs/.libs/pkcs11_test"
    '';

    # Status and debugging
    opentee-status.exec = ''
      echo "Open-TEE Status"
      echo "==============="
      echo ""
      echo "Socket: $OPENTEE_SOCKET_FILE_PATH"
      if [ -S "$OPENTEE_SOCKET_FILE_PATH" ]; then
        echo "  ✓ Socket exists"
      else
        echo "  ✗ Socket not found (daemon not running?)"
      fi
      echo ""
      echo "Storage: $OPENTEE_STORAGE_PATH"
      if [ -d "$OPENTEE_STORAGE_PATH" ]; then
        echo "  ✓ Storage directory exists"
      else
        echo "  ⚠ Storage directory not created yet"
      fi
      echo ""
      echo "Processes:"
      ps aux | grep -E 'opentee-engine|tee_manager|tee_launcher' | grep -v grep || echo "  ✗ No processes running"
      echo ""
      if [ -d "$OPENTEE_BUILD_DIR" ]; then
        echo "Build directory: $OPENTEE_BUILD_DIR"
        echo "  ✓ Exists"
      else
        echo "Build directory: $OPENTEE_BUILD_DIR"
        echo "  ✗ Not created (run 'opentee-build')"
      fi
    '';

    opentee-logs.exec = ''
      if [ -d "$DEVENV_STATE/process-compose" ]; then
        echo "Showing Open-TEE engine logs..."
        tail -f "$DEVENV_STATE/process-compose/opentee-engine.log"
      else
        echo "No logs found. Is 'devenv up' running?"
      fi
    '';
  };

  # https://devenv.sh/processes/
  processes = {
    opentee-engine = {
      exec = ''
        # Ensure storage directory exists
        mkdir -p "$OPENTEE_STORAGE_PATH"

        # Check if build exists
        if [ ! -f "$OPENTEE_BUILD_DIR/emulator/opentee-engine" ]; then
            echo "Error: opentee-engine not found!"
            echo "Please run 'opentee-build' first to build the project."
            exit 1
        fi

        # Generate opentee.conf in the state directory
        OPENTEE_CONF="$DEVENV_STATE/opentee.conf"
        cat > "$OPENTEE_CONF" << EOF
        [PATHS]
        ta_dir_path = $OPENTEE_BUILD_DIR/TAs/.libs
        core_lib_path = $OPENTEE_BUILD_DIR/emulator/.libs
        opentee_bin = $OPENTEE_BUILD_DIR/emulator/opentee-engine
        subprocess_manager = libManagerApi.so
        subprocess_launcher = libLauncherApi.so
        EOF

        echo "Starting Open-TEE engine..."
        echo "Config: $OPENTEE_CONF"
        echo "Socket: $OPENTEE_SOCKET_FILE_PATH"
        echo "Storage: $OPENTEE_STORAGE_PATH"

        # Run opentee-engine in foreground mode with custom config
        exec "$OPENTEE_BUILD_DIR/emulator/opentee-engine" \
            --config "$OPENTEE_CONF" \
            --pid-dir "$DEVENV_STATE" \
            --foreground
      '';

      process-compose = {
        # Readiness probe to check if the socket is created
        readiness_probe = {
          exec.command = "test -S $OPENTEE_SOCKET_FILE_PATH";
          initial_delay_seconds = 2;
          period_seconds = 1;
          timeout_seconds = 30;
        };

        # Availability probe to ensure processes stay healthy
        availability = {
          restart = "on_failure";
          max_restarts = 5;
        };
      };
    };
  };

  # https://devenv.sh/tasks/
  tasks = {
    # Automatically build on enterShell if needed
    "opentee:build-check" = {
      exec = ''
        if [ ! -f "$OPENTEE_BUILD_DIR/emulator/opentee-engine" ]; then
          echo "⚠ Open-TEE not built yet."
          echo "Run 'opentee-build' to build the project before starting services."
        else
          echo "✓ Open-TEE is built and ready"
        fi
      '';
      before = [ "devenv:enterShell" ];
    };
  };

  # https://devenv.sh/pre-commit-hooks/
  # Integrate with existing git-hooks-nix configuration
  # (This will be set up in flake.nix integration)

  enterShell = ''
    echo ""
    echo "🔐 Open-TEE Development Environment"
    echo "======================================"
    echo ""
    echo "📍 Project: Open-TEE"
    echo "📂 Root: $DEVENV_ROOT"
    echo "💾 State: $DEVENV_STATE"
    echo ""
    echo "Available Commands:"
    echo "-------------------"
    echo "  Build:"
    echo "    opentee-build        - Build the entire project"
    echo "    opentee-clean        - Clean build artifacts"
    echo "    opentee-distclean    - Remove build directory"
    echo ""
    echo "  Service Management:"
    echo "    devenv up            - Start Open-TEE daemon (in foreground with TUI)"
    echo "    devenv up -d         - Start Open-TEE daemon (in background)"
    echo "    opentee-status       - Check daemon and environment status"
    echo "    opentee-logs         - View daemon logs"
    echo ""
    echo "  Test Applications:"
    echo "    test-conn            - Run connection test"
    echo "    test-services        - Run services test"
    echo "    test-sha1            - Run SHA1 example"
    echo "    test-pkcs11          - Run PKCS#11 test"
    echo ""
    echo "  Environment:"
    echo "    Socket: $OPENTEE_SOCKET_FILE_PATH"
    echo "    Storage: $OPENTEE_STORAGE_PATH"
    echo "    Build: $OPENTEE_BUILD_DIR"
    echo ""

    # Create storage directory if it doesn't exist
    mkdir -p "$OPENTEE_STORAGE_PATH"
  '';

  # https://devenv.sh/languages/
  # C development is already set up via packages

  # Optionally integrate with existing treefmt configuration
  # This would be done in the flake integration
}
