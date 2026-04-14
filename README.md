# certui

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/diegovrocha/certui)](https://github.com/diegovrocha/certui/releases)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/diegovrocha/certui/pulls)
[![Go Report Card](https://goreportcard.com/badge/github.com/diegovrocha/certui)](https://goreportcard.com/report/github.com/diegovrocha/certui)

```
                _        _
  ___ ___ _ __| |_ _   _(_)
 / __/ _ \ '__| __| | | | |
| (_|  __/ |  | |_| |_| | |
 \___\___|_|   \__|\__,_|_|
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
make test       # run 22 Go tests across ui/menu/inspect packages
make uninstall  # remove from /usr/local/bin
```

## Features

### Convert
- **PFX/P12 → PEM** — certificate + key as text
- **PFX/P12 → CER** — certificate only, PEM (text) or DER (binary)
- **PFX/P12 → KEY** — private key only
- **PFX/P12 → P12** — repack `--legacy` → modern cipher (AES-256-CBC)

### Validate
- **Inspect** — view certificate details (CN, issuer, validity, SANs, key usage...). Press `f` for full view with Authority Key ID, OCSP, CRL, policies and signature
- **Verify chain** — validate cert → intermediate CA → root CA
- **Verify cert+key** — check if certificate matches private key (RSA/EC)
- **Compare certs** — compare two certificates by fingerprint, serial, subject and modulus. Supports PFX/PEM/DER

### Generate
- **Self-signed** — generate certificate + key for dev/testing. Configurable validity (30/90/365/730/3650 days), RSA key size (2048/4096) and optional subject fields (O, OU, C, ST, L)

### Dashboard
- **Quick Info sidebar** — on terminals with 85+ columns, a sidebar shows the count of certificate files in the current directory (`.pfx`/`.p12`, `.pem`/`.crt`, `.cer`/`.der`, `.key`)
- **Interactive file picker** — browse directories with breadcrumb, real-time text filter, and auto-hide of folders without matching files

## Navigation

| Key | Action |
|-----|--------|
| `↑/↓` or `j/k` | Navigate menu and lists |
| `Enter` | Select / Confirm / Enter directory |
| `←` | Go to parent directory |
| `Esc` | Back to previous screen |
| `q` | Quit |
| Type | Filter files in file picker |
| `f` | Toggle full view (inspect) |
| `n` | Inspect another certificate |

## Update

certui checks for updates automatically on startup via the GitHub releases API. If a new version is available, it shows:

```
Update v1.1.0 available → github.com/diegovrocha/certui/releases
```

## License

[MIT](LICENSE) - Diêgo Vieira Rocha
