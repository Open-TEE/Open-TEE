# devenv Quick Reference Card

## Installation

```bash
# Install Nix (if needed)
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install

# Install devenv
nix profile install nixpkgs#devenv
```

## Daily Commands

| Command | Description |
|---------|-------------|
| `devenv shell` | Enter development shell |
| `devenv up` | Start daemon (TUI mode) |
| `devenv up -d` | Start daemon (background) |
| `devenv processes stop` | Stop all processes |

## Build Commands

| Command | Description |
|---------|-------------|
| `opentee-build` | Build Open-TEE |
| `opentee-clean` | Clean artifacts |
| `opentee-distclean` | Remove build dir |

## Test Commands

| Command | Description |
|---------|-------------|
| `test-conn` | Connection test |
| `test-services` | Services test |
| `test-sha1` | SHA1 example |
| `test-pkcs11` | PKCS#11 test |

## Status Commands

| Command | Description |
|---------|-------------|
| `opentee-status` | Full status |
| `opentee-logs` | View logs |

## TUI Keyboard Shortcuts

When `devenv up` is running:

| Key | Action |
|-----|--------|
| `?` | Help |
| `↑`/`↓` | Navigate processes |
| `l` | View logs |
| `r` | Restart process |
| `q` | Quit |

## Directory Structure

```
Open-TEE/
├── build/              # Build output (OPENTEE_BUILD_DIR)
└── .devenv/
    └── state/          # Runtime state (DEVENV_STATE)
        ├── opentee.conf
        ├── open_tee_sock
        ├── TEE_secure_storage/
        └── process-compose/
            └── *.log
```

## Typical Workflow

```bash
# First time
devenv shell
opentee-build

# Daily development
devenv up          # Terminal 1: Start daemon
test-conn          # Terminal 2: Run tests
opentee-status     # Check everything works
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "opentee-engine not found" | Run `opentee-build` |
| Socket errors | Check `opentee-status` |
| Stuck processes | `devenv processes stop` |
| Fresh start | `opentee-distclean && rm -rf .devenv` |

## Environment Variables

| Variable | Value |
|----------|-------|
| `OPENTEE_SOCKET_FILE_PATH` | `$DEVENV_STATE/open_tee_sock` |
| `OPENTEE_STORAGE_PATH` | `$DEVENV_STATE/TEE_secure_storage` |
| `OPENTEE_BUILD_DIR` | `$DEVENV_ROOT/build` |

## More Info

- Full documentation: `docs/DEVENV.md`
- Summary: `docs/DEVENV-SUMMARY.md`
- devenv docs: https://devenv.sh/
