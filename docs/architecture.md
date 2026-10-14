# certui — Architecture

certui is a terminal UI for working with digital certificates. It wraps OpenSSL
subprocesses inside a Bubble Tea TUI, giving every operation a consistent
wizard-style flow: pick a file, supply credentials, confirm output, watch it run.

---

## Why Bubble Tea

certui uses [Bubble Tea](https://github.com/charmbracelet/bubbletea) (and its
companion libraries Bubbles and Lipgloss) rather than alternatives like tview or
raw tcell for three reasons:

1. **The Elm Architecture fits wizard flows naturally.** Each operation is a
   `tea.Model` with its own state machine. `Update` receives messages and returns
   the next state; `View` renders it. There is no callback soup — control flow is
   explicit and testable.

2. **Composable sub-models.** The root model (`menu.Model`) holds a single
   `tea.Model` field (`sub`). Activating an operation sets `sub` to the new model
   and delegates all messages to it. Going back clears `sub`. No global state,
   no routing table beyond the `handleAction` switch.

3. **Lipgloss for styling.** ANSI-aware layout and colour are handled
   declaratively with Lipgloss styles rather than raw escape codes. The theme
   system (`internal/ui/styles.go`) swaps the entire palette (dark/light) by
   replacing the style variables at startup, so every screen gets the right
   colours without per-call conditionals.

tview would couple layout and business logic through widget callbacks and global
`*tview.Application` references. tcell directly would require manual ANSI
management and input dispatch — roughly reimplementing what Bubble Tea already
provides.

---

## Why OpenSSL subprocesses

certui calls `openssl` via `os/exec` rather than using `crypto/x509` or
`software.sslmate.com/src/go-pkcs12`. The reasons are practical:

- **Legacy PKCS#12 ciphers.** PFX files issued by older Windows CAs, Java
  keystores, and banking middleware use `PBE-SHA1-3DES` or `PBE-SHA1-RC2-40`
  encryption. Go's `crypto/x509` has no PKCS#12 parser at all; `go-pkcs12`
  handles a subset of modern ciphers but fails on the legacy PBE algorithms that
  certui's target audience routinely encounters.

- **Round-trip repacking.** The repack operations (legacy → modern AES-256-CBC,
  modern → Java8/3DES) require decrypting a PKCS#12 under one cipher suite and
  re-encrypting under another. OpenSSL's `pkcs12 -export` flags (`-keypbe`,
  `-certpbe`, `-macalg`) expose exactly this surface. Replicating it in pure Go
  would mean depending on a fork of `go-pkcs12` or maintaining custom ASN.1
  marshalling.

- **`-legacy` flag detection.** OpenSSL 3.x moved legacy providers behind an
  opt-in flag. `detectLegacy()` in `internal/convert/convert.go` probes
  `openssl list -providers` and `openssl pkcs12 -help` at runtime to add
  `-legacy` only when the installed OpenSSL supports it — a probe that is trivial
  against the CLI but would require inspecting OpenSSL's provider registry in Go.

- **Battle-tested PEM/DER parsing.** `openssl x509 -text`, `openssl x509
  -noout -fingerprint`, and related commands have been parsing certificates in
  production for decades. certui's `internal/inspect` package leans on this
  rather than re-implementing X.509 field extraction with `crypto/x509`'s
  lower-level ASN.1 types.

The tradeoff is that `openssl` must be in `$PATH` (a hard requirement documented
in CONTRIBUTING.md and enforced at startup via `ui.OpenSSLVersion()`).

---

## Model state machine

Every sub-operation is a `tea.Model` with a `step` integer that drives both
`Update` and `View`. The convert package is the canonical example:

```
stepFile → stepPassword → stepOutput → [stepPassword2] → stepRunning → stepDone
```

| Step | What the user sees | What happens on `enter` |
|---|---|---|
| `stepFile` | `ui.FilePicker` | sets `m.infile`, advances to `stepPassword` |
| `stepPassword` | masked text input | stores password, advances to `stepOutput` (or `stepPassword2` for repack) |
| `stepOutput` | pre-filled filename input | sets `m.outfile`, advances to `stepRunning` |
| `stepPassword2` | masked text input (repack only) | stores second password, advances to `stepRunning` |
| `stepRunning` | spinner / "Processing…" | fires `m.runConversion()` as a `tea.Cmd` |
| `stepDone` | `ui.ResultBox` (green or red) | awaiting `esc` to return to menu |

`runConversion()` returns a `tea.Cmd` — a function that runs off the main
goroutine and delivers a `convResult` message. The `Update` switch receives
`convResult`, writes `m.result` and `m.success`, and transitions to `stepDone`.
This keeps the UI responsive during the OpenSSL subprocess.

The inspect, verify, generate, and other sub-packages follow the same pattern
with their own `step` constants and `tea.Cmd`-based async work.

### Menu push/pop

`menu.Model` has two screens: `screenMenu` and `screenSub`. When the user
selects an item, `handleAction` constructs the sub-model, sets `m.screen =
screenSub`, and calls `m.sub.Init()`. `View` delegates entirely to `m.sub.View()`
while in `screenSub`. Pressing `esc` in `updateSub` sets `m.screen = screenMenu`
and nils `m.sub`, discarding all sub-model state.

---

## Module map

```
certui/
├── cmd/certui/
│   └── main.go              Entry point. Creates tea.Program with menu.New(),
│                            handles post-update process restart via syscall.Exec.
│
├── internal/
│   ├── menu/                Root model. Owns the items list, cursor, filter
│   │                        state, and the active sub tea.Model. Routes actions
│   │                        via handleAction(). Checks for updates on Init().
│   │
│   ├── convert/             All PFX/P12 conversion operations share one Model
│   │                        struct parameterised by convType. Calls openssl
│   │                        pkcs12 and openssl x509 subprocesses. Handles
│   │                        legacy cipher detection.
│   │
│   ├── extract/             Extracts the public or private key from a PFX/P12,
│   │                        PEM or DER file (openssl x509 -pubkey / pkey).
│   │                        Picks the end-entity cert regardless of bundle order.
│   │
│   ├── ossl/                Shared openssl runner. Passwords travel as
│   │                        -passin/-passout env:… (never on argv, which any
│   │                        local user can read via ps); TempFile() gives
│   │                        unique 0600 temp files the caller removes.
│   │
│   ├── inspect/             Parses openssl x509 -text output into CertInfo
│   │                        structs. Supports PEM, DER, and PFX inputs.
│   │                        Exposes NewWithFileEmbedded for use inside other
│   │                        sub-screens (e.g. remote, batch).
│   │
│   ├── verify/              Three models: chain validation (openssl verify),
│   │                        cert+key match (modulus comparison), and multi-cert
│   │                        hash comparison.
│   │
│   ├── generate/            Self-signed certificate generation via
│   │                        openssl req -x509. Collects CN, SAN, duration,
│   │                        and key type through a multi-step form.
│   │
│   ├── remote/              Fetches the TLS certificate from a host:port using
│   │                        openssl s_client, then embeds an inspect.Model to
│   │                        display the result.
│   │
│   ├── fetchca/             Follows the AIA CA Issuers extension from a cert
│   │                        to download the issuer chain.
│   │
│   ├── batch/               Scans a directory for cert files and runs inspect
│   │                        on each, displaying a summary table.
│   │
│   ├── history/             Appends operation records to a JSON-lines log in
│   │                        the user's config dir. history.NewView() renders
│   │                        the log as a scrollable list.
│   │
│   ├── update/              Checks GitHub releases for a newer version, then
│   │                        downloads and installs the binary in-place.
│   │                        Sets update.RestartRequested so main.go can
│   │                        re-exec the new binary.
│   │
│   └── ui/
│       ├── styles.go        Lipgloss style variables (TitleStyle, ActiveStyle,
│       │                    ErrorStyle, etc.). init() detects dark/light theme
│       │                    from $COLORFGBG; CERTUI_THEME env var overrides.
│       ├── components.go    ResultBox (rounded border, green/red), CertBox
│       │                    (double-line box for cert fields), OpenSSLVersion(),
│       │                    Banner() (ASCII logo).
│       ├── filepicker.go    Self-contained FilePicker tea.Model. Constructors
│       │                    NewPfxFilePicker, NewCertFilePicker, NewAllFilePicker
│       │                    scope the extension filter. Supports inline text
│       │                    filtering and directory traversal.
│       ├── help.go          HelpSection / HelpEntry types and RenderHelp().
│       │                    CommonHelp() returns the universal "? help  esc back
│       │                    ctrl+c quit" section shared by all sub-screens.
│       └── update.go        CheckUpdate() — non-blocking GitHub release check
│                            used by menu.Init().
```

---

## UI component system

All visual output goes through `internal/ui`. Sub-models do not import Lipgloss
directly; they call the package-level style variables and helper functions.

Key conventions:

- **Styles are package-level vars**, not constants. `applyTheme()` reassigns them
  at startup (and can be called again by tests via `ForceTheme`). This means any
  file that imports `ui` gets the right colours without additional wiring.

- **`ResultBox(success bool, title string, lines ...string)`** is the standard
  end-state renderer. A green rounded border on success, red on failure.
  All sub-models call this at `stepDone`.

- **`FilePicker`** is a self-contained `tea.Model` — it has its own `Update` and
  `View`. Sub-models embed it as a field and delegate messages to it when
  `m.step == stepFile`. When `picker.Done` is true the parent reads `picker.Selected`
  and advances its own step.

- **Esc ownership**: the menu returns to the main screen on `esc` unless the
  sub-model implements `CapturesEsc() bool` and returns true (help overlay
  open, save prompt active, nested view). Implement it whenever a screen
  uses `esc` for something local.

- **`HelpSection` / `RenderHelp`** provide a uniform help overlay. Each
  sub-model defines its own `[]HelpSection` and passes them to `RenderHelp()`.
  `CommonHelp()` appends the shared "esc back / ctrl+c quit" section so every
  screen documents the same global keys.

- **Stdout discipline**: `ResultBox`, `CertBox`, and all `View()` methods write
  to Bubble Tea's renderer, never to `os.Stdout`. Functions designed to be
  called from shell scripts or tests send only their return value to stdout;
  all incidental messages go to stderr. This avoids corrupting captured output.

---

## Adding a new operation

Follow the four steps from CONTRIBUTING.md:

1. **Create the model** in `internal/<feature>/<name>.go`. Implement `tea.Model`
   (`Init`, `Update`, `View`). Define a `step` type with at minimum `stepFile`
   (or whatever your first input is) through `stepDone`. Use `ui.FilePicker` for
   file selection and `ui.ResultBox` for the final state. Fire the heavy work
   (OpenSSL subprocess, network call, etc.) as a `tea.Cmd` so the UI stays
   responsive.

2. **Register the menu entry** in `internal/menu/menu.go`. Add a `menuItem` to
   the `items` slice with a unique `action` string:
   ```go
   {label: "My feature", desc: "short description", action: "my_feature"},
   ```

3. **Route the action** in `handleAction()` in the same file:
   ```go
   case "my_feature":
       m.screen = screenSub
       m.sub = myfeature.New()
       return m, m.sub.Init()
   ```

4. **Add tests** in `internal/<feature>/<name>_test.go`. At minimum test that
   `Init()` returns without panic and that `Update` transitions steps correctly
   when fed synthetic `tea.KeyMsg` values.

For operations that display certificate details after running, embed
`inspect.NewWithFileEmbedded(path)` as a sub-model rather than duplicating the
parsing logic — see `internal/remote` for a working example.
