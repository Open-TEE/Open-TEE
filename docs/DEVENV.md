# Open-TEE with devenv

This document explains how to use [devenv](https://devenv.sh/) for Open-TEE development, which provides a streamlined workflow for building, running, and testing.

## What is devenv?

devenv is a developer environment tool built on Nix that provides:
- **Process management** - Start/stop services with `devenv up`
- **Reproducible environments** - All dependencies managed by Nix
- **Task automation** - Build scripts and test runners
- **Service integration** - Built-in support for databases, web servers, etc.

## Quick Start

### Prerequisites

1. Install Nix (if not already installed):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
   ```

2. Install devenv:
   ```bash
   nix profile install nixpkgs#devenv
   ```

### First-time Setup

1. Clone the repository and enter the directory:
   ```bash
   cd Open-TEE
   ```

2. Enter the devenv shell:
   ```bash
   devenv shell
   ```

3. Build Open-TEE:
   ```bash
   opentee-build
   ```

4. Start the Open-TEE daemon:
   ```bash
   devenv up
   ```

That's it! The Open-TEE daemon is now running with process supervision.

## Daily Workflow

### Building

Build the entire project:
```bash
opentee-build
```

Clean build artifacts:
```bash
opentee-clean
```

Remove build directory completely:
```bash
opentee-distclean
```

### Running the Daemon

Start in foreground with TUI (recommended for development):
```bash
devenv up
```

The TUI provides:
- Process status for `opentee-engine`, `tee_manager`, and `tee_launcher`
- Real-time log viewing
- Ability to restart individual processes
- Keyboard shortcuts (press `?` for help)

Start in background:
```bash
devenv up -d
```

Stop background processes:
```bash
devenv processes stop
```

### Running Tests

Once the daemon is running (via `devenv up`), open a new terminal and run:

Connection test:
```bash
test-conn
```

Services test:
```bash
test-services
```

SHA1 example:
```bash
test-sha1
```

PKCS#11 test:
```bash
test-pkcs11
```

### Checking Status

View comprehensive status information:
```bash
opentee-status
```

This shows:
- Socket status
- Storage directory
- Running processes
- Build directory status

View daemon logs:
```bash
opentee-logs
```

## Environment Details

### Directory Structure

devenv uses the following directories:

- **Project root**: Your Open-TEE checkout
- **Build directory**: `$DEVENV_ROOT/build` - All build artifacts
- **State directory**: `$DEVENV_STATE` - Runtime files including:
  - `open_tee_sock` - Unix socket for IPC
  - `TEE_secure_storage/` - Secure storage for TAs
  - `opentee.conf` - Auto-generated configuration
  - `process-compose/` - Process logs

### Environment Variables

The following environment variables are automatically set:

- `OPENTEE_SOCKET_FILE_PATH` - Path to the IPC socket
- `OPENTEE_STORAGE_PATH` - Path to secure storage
- `OPENTEE_BUILD_DIR` - Path to build artifacts
- `DEVENV_ROOT` - Project root directory
- `DEVENV_STATE` - Runtime state directory

### Configuration

The `opentee.conf` file is automatically generated in `$DEVENV_STATE` with the correct paths. You don't need to manually edit `/etc/opentee.conf`.

## Advantages Over Manual Setup

| Manual Setup | With devenv |
|--------------|-------------|
| Manual autotools build | `opentee-build` |
| Edit `/etc/opentee.conf` with absolute paths | Auto-generated config |
| Start daemon: `/opt/OpenTee/bin/opentee-engine` | `devenv up` |
| Monitor with `ps`, `tail -f /var/log/syslog` | TUI with live logs |
| Run tests: `/opt/OpenTee/bin/conn_test` | `test-conn` |
| Manual PID management | Automatic process supervision |
| System-wide installation in `/opt` | Isolated in project directory |
| Requires sudo for installation | No sudo required |

## Integration with Existing Tools

### With Nix Flakes

If you're using the flake-based workflow:

```bash
nix develop  # Enter the traditional dev shell
```

or:

```bash
nix develop --impure -c devenv up  # Use devenv through flake
```

### With direnv

Add to your `.envrc`:
```bash
use devenv
```

Then `cd` into the directory to automatically activate the environment.

### With IDEs

#### VS Code

Install the "Nix Environment Selector" extension and select the devenv environment.

#### CLion/IntelliJ

Configure the C/C++ toolchain to use the paths from `devenv shell`.

## Debugging

### Attach GDB to Trusted Application

1. Start the daemon in one terminal:
   ```bash
   devenv up
   ```

2. In another terminal, find the TA process:
   ```bash
   ps aux | grep tee_launcher
   ```

3. Attach GDB:
   ```bash
   gdb -ex "set follow-fork-mode child" $OPENTEE_BUILD_DIR/bin/opentee-engine $(pidof tee_launcher)
   ```

4. Run a test application in a third terminal:
   ```bash
   test-conn
   ```

### View Process Logs

All process output is captured in `$DEVENV_STATE/process-compose/`:

```bash
tail -f $DEVENV_STATE/process-compose/opentee-engine.log
```

Or use the built-in helper:
```bash
opentee-logs
```

## Troubleshooting

### "opentee-engine not found" when running `devenv up`

You need to build first:
```bash
opentee-build
```

### Socket permission errors

Check socket permissions:
```bash
ls -l $OPENTEE_SOCKET_FILE_PATH
```

The socket should be owned by your user.

### Process won't start

Check the logs:
```bash
cat $DEVENV_STATE/process-compose/opentee-engine.log
```

Verify the build completed successfully:
```bash
opentee-status
```

### Clean state and rebuild

```bash
devenv processes stop  # Stop all processes
opentee-distclean      # Remove build directory
rm -rf .devenv         # Remove devenv state
opentee-build          # Rebuild
devenv up              # Restart
```

## Advanced Usage

### Custom Process Configuration

Edit `devenv.nix` to customize process behavior, add health checks, or configure restart policies.

### Adding New Test Scripts

Add to the `scripts` section in `devenv.nix`:

```nix
scripts = {
  my-test.exec = ''
    "$OPENTEE_BUILD_DIR/bin/my_test_binary"
  '';
};
```

### Running Multiple Environments

You can run multiple Open-TEE environments simultaneously by using different project directories, as each has isolated state.

## Migration from Manual Setup

If you're currently using the manual setup from the documentation:

1. Stop any running `opentee-engine` processes
2. Enter devenv shell: `devenv shell`
3. Build: `opentee-build`
4. Start: `devenv up`

Your `/etc/opentee.conf` is not used when running via devenv. The configuration is auto-generated in the state directory.

## Contributing

When contributing to Open-TEE with devenv:

1. Pre-commit hooks are automatically installed
2. Format code with: `nix fmt`
3. Run checks with: `nix flake check`
4. All test applications should pass before submitting

## Further Reading

- [devenv documentation](https://devenv.sh/)
- [process-compose documentation](https://github.com/F1bonacc1/process-compose)
- [Open-TEE main documentation](https://open-tee.github.io/documentation/)
