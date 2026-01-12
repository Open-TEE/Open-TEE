# Nix Setup for Open-TEE

This directory contains the Nix configuration for Open-TEE development and deployment.

## Quick Start

### For Nix Flakes Users

```bash
# Enter development shell
nix develop

# Build the project
nix build

# Run checks
nix flake check

# Format code
nix fmt
```

### For Traditional Nix Users

```bash
# Enter development shell
nix-shell

# Build the project
nix-build
```

## Structure

```
nix/
├── flake-module.nix    # Main module entry point
├── checks.nix          # CI checks and pre-commit hooks
├── devshell.nix        # Development environment
├── nixpkgs.nix         # Nixpkgs configuration
└── treefmt.nix         # Code formatters configuration
```

## Module Descriptions

### `flake-module.nix`

The central import point for all Nix modules. This follows the flake-parts pattern for modular flake organization.

### `checks.nix`

Defines checks that run via `nix flake check`:
- **reuse**: SPDX license compliance
- **pre-commit**: All git pre-commit hooks
- **package builds**: Ensures packages build correctly

Also configures git pre-commit hooks:
- `treefmt`: Auto-format on commit
- `reuse`: License check on commit
- `end-of-file-fixer`: Ensure files end with newline
- `trim-trailing-whitespace`: Clean up whitespace

### `devshell.nix`

Comprehensive development environment with:
- Build tools (autoconf, automake, libtool, gcc, make, pkg-config)
- Runtime dependencies (fuse, libelf, libuuid, mbedtls, openssl, zlib)
- Development tools (git, gdb, ripgrep, reuse)
- Code formatters (all treefmt programs)
- Pre-commit hooks (auto-installed on shell entry)

### `nixpkgs.nix`

Centralized nixpkgs configuration:
- System-specific package sets
- Configuration options (e.g., `allowUnfree`)
- Custom lib extensions

### `treefmt.nix`

Code formatting configuration:
- **alejandra**: Nix code formatter
- **deadnix**: Remove dead Nix code
- **shellcheck**: Shell script linter
- **statix**: Nix anti-pattern checker
- **clang-format**: C/C++ formatter

## Development Workflow

### 1. Enter Dev Shell

```bash
nix develop
```

This will:
- Load all development dependencies
- Install pre-commit hooks in `.git/hooks/`
- Display helpful information

### 2. Build the Project

Traditional autotools workflow:
```bash
./autogen.sh
./configure
make
```

Or use Nix:
```bash
nix build
```

### 3. Format Code

Before committing:
```bash
nix fmt
```

Or let pre-commit hooks handle it automatically.

### 4. Run Checks

```bash
nix flake check
```

This runs:
- All package builds
- License compliance checks
- Pre-commit hook checks
- Format checks

## Adding New Dependencies

### Build-Time Dependencies

Edit `packages/flake-module.nix`:
```nix
nativeBuildInputs = with pkgs; [
  # ... existing ...
  newBuildTool
];
```

### Runtime Dependencies

Edit `packages/flake-module.nix`:
```nix
buildInputs = with pkgs; [
  # ... existing ...
  newLibrary
];
```

### Development Tools

Edit `nix/devshell.nix`:
```nix
packages = with pkgs; [
  # ... existing ...
  newDevTool
];
```

## Customization

### Nixpkgs Options

Edit `nix/nixpkgs.nix` to customize nixpkgs:
```nix
_module.args.pkgs = import inputs.nixpkgs {
  inherit system;
  config = {
    allowUnfree = true;  # Allow unfree packages
    # ... other options ...
  };
};
```

### Formatter Configuration

Edit `nix/treefmt.nix` to add/configure formatters:
```nix
programs = {
  # ... existing formatters ...
  newFormatter.enable = true;
};
```

### Pre-commit Hooks

Edit `nix/checks.nix` to add/configure hooks:
```nix
pre-commit.settings.hooks = {
  # ... existing hooks ...
  new-hook = {
    enable = true;
    package = pkgs.some-package;
  };
};
```

## Troubleshooting

### "dirty git tree" Warning

Stage your changes:
```bash
git add .
```

### Missing Dependencies

Ensure you're in the dev shell:
```bash
nix develop
```

### Build Failures

Check the build log:
```bash
nix log /nix/store/...-open-tee-0.0.0.drv
```

### Pre-commit Hooks Not Working

Reinstall hooks:
```bash
nix develop
# Hooks are automatically reinstalled on shell entry
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Nix CI

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: DeterminateSystems/nix-installer-action@main
      - uses: DeterminateSystems/magic-nix-cache-action@main

      - name: Check Nix flake
        run: nix flake check

      - name: Build
        run: nix build
```

## Further Reading

- [Nix Manual](https://nixos.org/manual/nix/stable/)
- [flake-parts Documentation](https://flake.parts/)
- [Nixpkgs Manual](https://nixos.org/manual/nixpkgs/stable/)
- [git-hooks.nix](https://github.com/cachix/git-hooks.nix)
- [treefmt](https://github.com/numtide/treefmt)

## License

The Nix configuration is licensed under Apache-2.0, same as the Open-TEE project.
