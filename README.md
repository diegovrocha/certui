# certui

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/diegovrocha/certui)](https://github.com/diegovrocha/certui/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/diegovrocha/certui)](https://go.dev/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/diegovrocha/certui/pulls)
[![Go Report Card](https://goreportcard.com/badge/github.com/diegovrocha/certui)](https://goreportcard.com/report/github.com/diegovrocha/certui)

```
  ____         _____ _   _ ___
 / ___|___ _ _|_   _| | | |_ _|  Cert + TUI
| |   / _ \ '__|| | | | | || |   Digital certificate conversion,
| |__|  __/ |   | | | |_| || |   validation and generation.
 \____\___|_|   |_|  \___/|___|  https://github.com/diegovrocha/certui
```

Digital certificate conversion, validation and generation TUI.

Built with [Bubble Tea](https://github.com/charmbracelet/bubbletea). Single binary, zero runtime dependencies — just `openssl`.

**Contributions welcome!** See [CONTRIBUTING.md](CONTRIBUTING.md).

## Requirements

- **openssl** — pre-installed on macOS and most Linux distributions

## Install

### Quick install (macOS/Linux)

```bash
curl -sSLf https://raw.githubusercontent.com/diegovrocha/certui/main/install.sh | sh
```

### Manual download

Download the binary for your platform from [Releases](https://github.com/diegovrocha/certui/releases):

| Platform | File |
|----------|------|
| macOS (Apple Silicon) | `certui_darwin_arm64.tar.gz` |
| macOS (Intel) | `certui_darwin_amd64.tar.gz` |
| Linux (amd64) | `certui_linux_amd64.tar.gz` |
| Linux (arm64) | `certui_linux_arm64.tar.gz` |
| Windows (amd64) | `certui_windows_amd64.zip` |

Extract and move to your PATH:

```bash
tar -xzf certui_<os>_<arch>.tar.gz
sudo mv certui /usr/local/bin/
```

### From source

Requires [Go 1.22+](https://go.dev/dl/):

```bash
git clone https://github.com/diegovrocha/certui.git
cd certui
make install    # builds and copies to /usr/local/bin
```

Other make targets:

```bash
make build      # build binary locally
make test       # run Go tests across ui/menu/inspect packages
make uninstall  # remove from /usr/local/bin
```

## Features

### Convert
- **PFX/P12 → PEM** — certificate + key as text
- **PFX/P12 → CER** — certificate only, PEM (text) or DER (binary)
- **PFX/P12 → KEY** — private key only
- **PFX/P12 → P12** — repack `--legacy` → modern cipher (AES-256-CBC)

### Validate
- **Inspect** — view certificate details (CN, issuer, validity, SANs, key usage...). Press `f` for full view with Authority Key ID, OCSP, CRL, policies and signature. Press `y` to copy details to clipboard, `s` to save as `.txt`, `n` to inspect another
- **Batch inspect** — browse directories and scan any folder for all certificates. Shows a table with status (valid / expiring / expired), sortable by name (`c`), expiry date (`d`), or days remaining (`r`). Press `Enter` on any row to see full details, `b` to go back to folder browser
- **Download from URL** — fetch certificate from `host:port` via `openssl s_client`, shows TLS version, cipher and full chain. Press `s` to save the chain as `.pem`
- **Verify chain** — validate cert → intermediate CA → root CA (system CA or custom)
- **Verify cert+key** — check if certificate matches private key (RSA or EC)
- **Compare certs** — compare 2+ certificates by fingerprint, serial, subject and modulus. For 3+ certs shows a match matrix with identical-cert grouping. Supports PFX/PEM/DER (prompts for password on PFX). Press `d` in results for a side-by-side field-by-field diff with green (match) / red (differ) colors

### Generate
- **Self-signed** — generate certificate + key for dev/testing
  - Configurable validity (30/90/365/730/3650 days)
  - **RSA** (2048 / 4096 bits) or **EC** (P-256 / P-384 / P-521 — smaller keys, faster handshakes, TLS 1.3 default)
  - **SANs** (Subject Alternative Names) with presets:
    - *None* — just CN
    - *Web* — CN + `localhost` + `127.0.0.1` + `::1` (ideal for local dev)
    - *Wildcard* — CN + `*.CN`
    - *Wildcard + Web* — both combined
    - *Custom* — comma-separated list, auto-detects DNS/IP/email/URI
  - Optional subject fields (O, OU, C, ST, L)

### Utilities
- **History** — log of all operations stored in `~/.certui/history.log`, viewable from the menu
- **Update** — in-app download and replace of the binary. Shows scrollable GitHub release notes before installing, then auto-restarts certui with the new version (3-second countdown, press `r` to restart immediately or `c` to cancel). Also auto-detects new releases on launch and shows a notice in the banner
- **Quit**

### File picker
- **Directory navigation** — breadcrumb path, enter folders with `Enter` or `→`, go to parent with `←`
- **Live filter** — type to filter files by name in real time
- **Smart folders** — directories without matching certificate files are hidden automatically
- **Context-aware filters** — only shows relevant extensions per operation (e.g. `.pfx`/`.p12` for PFX conversions)

## Navigation

Press `?` on any screen to see a contextual help overlay listing the keys that screen understands.

### General
| Key | Action |
|-----|--------|
| `↑/↓` or `j/k` | Navigate menu and lists |
| `Enter` | Select / Confirm / Open details |
| `Esc` | Back to previous screen |
| `q` | Quit (main menu only) |
| `Ctrl+C` | Quit from anywhere |
| `/` | Fuzzy search filter in main menu |
| `?` | Toggle contextual help |

### File picker
| Key | Action |
|-----|--------|
| `→` or `Enter` | Enter highlighted folder |
| `←` | Go to parent directory |
| Type | Filter files by name |

### Inspect results
| Key | Action |
|-----|--------|
| `f` | Toggle full view (extra fields) |
| `y` | Copy details to clipboard |
| `s` | Save details as `.txt` |
| `n` | Inspect another certificate |
| `↑/↓` | Scroll long output |

### Batch inspect
| Key | Action |
|-----|--------|
| `→` or `Enter` | Enter folder / Open cert details |
| `←` | Go to parent directory |
| `s` | Scan current folder (shortcut) |
| `r` | Sort by days remaining |
| `c` | Sort by CN (name) |
| `d` | Sort by expiry date |
| `b` | Back to folder browser (from table) |

### Compare
| Key | Action |
|-----|--------|
| `d` | Toggle side-by-side diff view |

### Update
| Key | Action |
|-----|--------|
| `↑/↓` | Scroll changelog |
| `Enter` | Install update (on confirm step) / Restart now (on success) |
| `r` | Restart now after update |
| `c` | Cancel auto-restart |

## Docker (test on Linux)

A `Dockerfile.test` is provided to try certui on Linux without installing anything locally:

```bash
docker build -t certui-test -f Dockerfile.test .
docker run -it --rm -v $(pwd):/certs certui-test
```

The container mounts your current directory as `/certs` so certui can access local certificate files. Uses `debian:stable-slim` (~75 MB) and downloads the latest released binary automatically.

## Theme

certui auto-detects light / dark terminals via the `$COLORFGBG` environment variable and picks appropriate colors. To override detection:

```bash
CERTUI_THEME=light certui
CERTUI_THEME=dark  certui
```

| Variable | Values | Effect |
|----------|--------|--------|
| `CERTUI_THEME` | `light`, `dark` | Force theme (overrides autodetection) |
| `COLORFGBG` | auto | Read from terminal for autodetection |

## Screenshots / demos

TODO — add screenshots and an asciinema demo. For now, run `certui` to see it in action.

## License

[MIT](LICENSE) - Diêgo Vieira Rocha
