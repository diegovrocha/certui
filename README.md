# certool

```
                _              _
  ___ ___ _ __| |_ ___   ___ | |
 / __/ _ \ '__| __/ _ \ / _ \| |
| (_|  __/ |  | || (_) | (_) | |
 \___\___|_|   \__\___/ \___/|_|
```

Digital certificate conversion, validation and generation TUI.

Built with [Bubble Tea](https://github.com/charmbracelet/bubbletea). Single binary, zero runtime dependencies — just `openssl`.

## Requirements

- **openssl** — pre-installed on macOS and most Linux distributions

## Install

### Binary (recommended)

Download from [Releases](https://github.com/diegovrocha/certool/releases), extract and move to your PATH:

```bash
# macOS (Apple Silicon)
tar -xzf certool_darwin_arm64.tar.gz
sudo mv certool /usr/local/bin/

# macOS (Intel)
tar -xzf certool_darwin_amd64.tar.gz
sudo mv certool /usr/local/bin/

# Linux (amd64)
tar -xzf certool_linux_amd64.tar.gz
sudo mv certool /usr/local/bin/

# Linux (arm64)
tar -xzf certool_linux_arm64.tar.gz
sudo mv certool /usr/local/bin/
```

### From source

Requires [Go 1.22+](https://go.dev/dl/):

```bash
git clone https://github.com/diegovrocha/certool.git
cd certool
make install    # builds and copies to /usr/local/bin
```

Other make targets:

```bash
make build      # build binary locally
make test       # run tests
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
- **Self-signed** — generate certificate + key for dev/testing with optional subject fields (O, OU, C, ST, L)

## Navigation

| Key | Action |
|-----|--------|
| `↑/↓` or `j/k` | Navigate menu and lists |
| `Enter` | Select / Confirm |
| `Esc` | Back to previous screen |
| `q` | Quit |
| Type | Filter files in file picker |
| `f` | Toggle full view (inspect) |
| `n` | Inspect another certificate |

## Update

certool checks for updates automatically on startup via the GitHub releases API. If a new version is available, it shows:

```
Update v1.1.0 available! Run: brew upgrade certool
```

## License

[MIT](LICENSE) - Diêgo Vieira Rocha
