// Package batch implements the "Batch inspect" TUI flow: it recursively
// scans a directory for certificate files, extracts a summary for each
// (CN, issuer, expiry), and displays the results in a sortable table.
package batch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-runewidth"
	"github.com/diegovrocha/certui/internal/history"
	"github.com/diegovrocha/certui/internal/inspect"
	"github.com/diegovrocha/certui/internal/ui"
)

type step int

const (
	stepBrowse step = iota
	stepScanning
	stepTable
	stepDetail
)

type dirEntry struct {
	name  string
	path  string
	isDir bool
}

type sortMode int

const (
	sortByDays sortMode = iota
	sortByCN
	sortByExpiry
)

// Row represents a single scanned certificate file.
type Row struct {
	Path     string
	RelPath  string
	CN       string
	Issuer   string
	NotAfter string
	Days     int
	Status   string // "ok", "warn", "expired", "pfx", "error"
	Error    string
}

type Model struct {
	step       step
	dir        string
	entries    []dirEntry // subdirs in current dir (for browse step)
	browseCur  int
	rows       []Row
	cursor     int
	scroll     int
	height     int
	width      int
	sortMode   sortMode
	err        string
	scanned    bool
	detail     tea.Model
	logged     bool
	showHelp   bool
}

type scanDoneMsg struct {
	rows []Row
	err  string
}

// New returns a new batch-inspect model starting in a directory browser
// so the user can navigate to the folder they want to scan.
func New() tea.Model {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	m := &Model{
		step:     stepBrowse,
		dir:      cwd,
		sortMode: sortByDays,
	}
	m.loadDir()
	return m
}

func (m *Model) Init() tea.Cmd {
	return nil
}

// loadDir refreshes the list of subdirectories for the current m.dir.
func (m *Model) loadDir() {
	m.entries = nil
	m.browseCur = 0
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		m.entries = append(m.entries, dirEntry{
			name:  e.Name() + "/",
			path:  filepath.Join(m.dir, e.Name()),
			isDir: true,
		})
	}
	sort.SliceStable(m.entries, func(i, j int) bool {
		return strings.ToLower(m.entries[i].name) < strings.ToLower(m.entries[j].name)
	})
}

func (m *Model) scan() tea.Cmd {
	dir := m.dir
	return func() tea.Msg {
		rows := scanDir(dir, 5)
		return scanDoneMsg{rows: rows}
	}
}

func scanDir(root string, maxDepth int) []Row {
	var rows []Row
	rootDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))

	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		name := info.Name()
		if info.IsDir() {
			// Skip hidden directories
			if name != "." && strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			// Depth control
			d := strings.Count(filepath.Clean(path), string(os.PathSeparator)) - rootDepth
			if d > maxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(name))
		switch ext {
		case ".pfx", ".p12", ".pem", ".crt", ".cer", ".der":
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			rows = append(rows, extractRow(path, rel, ext))
		}
		return nil
	})
	return rows
}

func extractRow(path, rel, ext string) Row {
	r := Row{Path: path, RelPath: rel}
	if ext == ".pfx" || ext == ".p12" {
		r.CN = "—"
		r.Issuer = "—"
		r.Status = "pfx"
		r.Error = "requires password"
		return r
	}
	pemFile := path
	tmp := ""
	// DER detection: if not a PEM marker, convert via openssl
	if ext == ".der" || ext == ".cer" {
		if !hasPEMMarker(path) {
			tmp = fmt.Sprintf("/tmp/certui_batch_%d.pem", time.Now().UnixNano())
			if err := exec.Command("openssl", "x509", "-in", path, "-inform", "DER",
				"-out", tmp, "-outform", "PEM").Run(); err != nil {
				r.CN = "—"
				r.Issuer = "—"
				r.Status = "error"
				r.Error = "unrecognized format"
				return r
			}
			pemFile = tmp
			defer exec.Command("rm", "-f", tmp).Run()
		}
	}

	// Use openssl to extract fields directly
	subject := opensslField(pemFile, "-subject", "subject=")
	issuer := opensslField(pemFile, "-issuer", "issuer=")
	notAfter := opensslField(pemFile, "-enddate", "notAfter=")
	if subject == "" && issuer == "" {
		r.CN = "—"
		r.Issuer = "—"
		r.Status = "error"
		r.Error = "no certificate"
		return r
	}
	r.CN = extractCN(subject)
	r.Issuer = extractCN(issuer)
	r.NotAfter = notAfter

	// Parse notAfter to compute days remaining
	if t, ok := parseOpensslDate(notAfter); ok {
		days := int(time.Until(t).Hours() / 24)
		r.Days = days
		// Format as YYYY-MM-DD for display
		r.NotAfter = t.Format("2006-01-02")
		switch {
		case days < 0:
			r.Status = "expired"
		case days <= 30:
			r.Status = "warn"
		default:
			r.Status = "ok"
		}
	} else {
		r.Status = "error"
		r.Error = "could not parse expiry"
	}
	return r
}

func hasPEMMarker(file string) bool {
	return exec.Command("grep", "-q", "BEGIN CERTIFICATE", file).Run() == nil
}

func opensslField(file, flag, prefix string) string {
	out, _ := exec.Command("openssl", "x509", "-in", file, "-noout", flag).Output()
	s := strings.TrimSpace(string(out))
	if s == "" {
		return ""
	}
	if prefix != "" {
		s = strings.TrimPrefix(s, prefix)
	}
	return strings.TrimSpace(s)
}

func extractCN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") || strings.HasPrefix(part, "CN =") {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(part, "CN="), "CN ="))
		}
	}
	if dn == "" {
		return "—"
	}
	return dn
}

// parseOpensslDate accepts formats OpenSSL emits for notAfter.
func parseOpensslDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	layouts := []string{
		"Jan _2 15:04:05 2006 MST",
		"Jan  2 15:04:05 2006 MST",
		"2006-01-02T15:04:05Z",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		if m.detail != nil {
			var cmd tea.Cmd
			m.detail, cmd = m.detail.Update(msg)
			return m, cmd
		}
		return m, nil
	case scanDoneMsg:
		m.rows = msg.rows
		m.err = msg.err
		m.scanned = true
		m.step = stepTable
		m.applySort()
		if !m.logged {
			history.Log("batch_inspect",
				history.KV("dir", m.dir),
				history.KV("count", fmt.Sprintf("%d", len(m.rows))))
			m.logged = true
		}
		return m, nil
	case tea.KeyMsg:
		// Help overlay on non-input steps (browse/table)
		if m.step == stepBrowse || m.step == stepTable {
			if msg.String() == "?" {
				m.showHelp = !m.showHelp
				return m, nil
			}
			if m.showHelp {
				if msg.String() == "esc" {
					m.showHelp = false
					return m, nil
				}
				return m, nil
			}
		}
		if m.step == stepDetail {
			if msg.String() == "esc" {
				m.step = stepTable
				m.detail = nil
				return m, nil
			}
			if m.detail != nil {
				var cmd tea.Cmd
				m.detail, cmd = m.detail.Update(msg)
				return m, cmd
			}
			return m, nil
		}
		if m.step == stepBrowse {
			switch msg.String() {
			case "up", "k":
				if m.browseCur > 0 {
					m.browseCur--
				}
			case "down", "j":
				if m.browseCur < len(m.entries) {
					m.browseCur++
				}
			case "left":
				parent := filepath.Dir(m.dir)
				if parent != m.dir {
					m.dir = parent
					m.loadDir()
				}
			case "right":
				// Enter highlighted dir if it's a real dir (not the scan action)
				if m.browseCur < len(m.entries) {
					m.dir = m.entries[m.browseCur].path
					m.loadDir()
				}
			case "enter":
				// browseCur == len(entries) means "Scan this folder"
				if m.browseCur >= len(m.entries) {
					m.step = stepScanning
					m.scanned = false
					m.logged = false
					return m, m.scan()
				}
				// Otherwise navigate into the selected directory
				m.dir = m.entries[m.browseCur].path
				m.loadDir()
			case "s", "S":
				// Quick shortcut: scan current folder regardless of cursor
				m.step = stepScanning
				m.scanned = false
				m.logged = false
				return m, m.scan()
			}
			return m, nil
		}
		if m.step == stepTable {
			switch msg.String() {
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
				}
			case "down", "j":
				if m.cursor < len(m.rows)-1 {
					m.cursor++
				}
			case "b", "B":
				// Back to directory browser
				m.step = stepBrowse
				m.rows = nil
				m.cursor = 0
				m.scroll = 0
				m.loadDir()
				return m, nil
			case "c", "C":
				m.sortMode = sortByCN
				m.applySort()
			case "d", "D":
				m.sortMode = sortByExpiry
				m.applySort()
			case "r", "R":
				m.sortMode = sortByDays
				m.applySort()
			case "enter":
				if len(m.rows) == 0 {
					return m, nil
				}
				row := m.rows[m.cursor]
				if row.Status == "pfx" || row.Status == "error" {
					return m, nil
				}
				sub := inspect.NewWithFile(row.Path)
				m.detail = sub
				m.step = stepDetail
				return m, sub.Init()
			}
		}
	}

	if m.step == stepDetail && m.detail != nil {
		var cmd tea.Cmd
		m.detail, cmd = m.detail.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *Model) applySort() {
	switch m.sortMode {
	case sortByCN:
		sort.SliceStable(m.rows, func(i, j int) bool {
			return strings.ToLower(m.rows[i].CN) < strings.ToLower(m.rows[j].CN)
		})
	case sortByExpiry:
		sort.SliceStable(m.rows, func(i, j int) bool {
			return m.rows[i].NotAfter < m.rows[j].NotAfter
		})
	default: // sortByDays
		sort.SliceStable(m.rows, func(i, j int) bool {
			return m.rows[i].Days < m.rows[j].Days
		})
	}
	if m.cursor >= len(m.rows) {
		m.cursor = len(m.rows) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
}

func (m *Model) View() string {
	if m.step == stepDetail && m.detail != nil {
		return m.detail.View()
	}
	if m.showHelp {
		return m.renderHelp()
	}

	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(ui.Banner())
	b.WriteString("\n  " + ui.TitleStyle.Render("── Batch Inspect ──") + "\n\n")

	// Breadcrumb (display home as ~)
	home, _ := os.UserHomeDir()
	display := m.dir
	if home != "" && strings.HasPrefix(display, home) {
		display = "~" + display[len(home):]
	}
	b.WriteString(fmt.Sprintf("  %s %s\n\n", ui.DimStyle.Render("📂"), ui.DimStyle.Render(display)))

	if m.step == stepBrowse {
		b.WriteString("  " + ui.ActiveStyle.Render("Select a folder to scan, or press Enter on [Scan this folder]") + "\n\n")

		maxVisible := 12
		start := 0
		if m.browseCur >= maxVisible {
			start = m.browseCur - maxVisible + 1
		}
		totalItems := len(m.entries) + 1 // +1 for [Scan this folder]
		end := start + maxVisible
		if end > totalItems {
			end = totalItems
		}

		if start > 0 {
			b.WriteString(fmt.Sprintf("  %s\n", ui.DimStyle.Render(fmt.Sprintf("  ↑ %d more above", start))))
		}

		for i := start; i < end; i++ {
			if i == len(m.entries) {
				// The "scan here" virtual row
				label := ui.SuccessStyle.Render("🔍 [Scan this folder]")
				if i == m.browseCur {
					b.WriteString("  " + ui.ActiveStyle.Render("➤ ") + label + "\n")
				} else {
					b.WriteString("    " + label + "\n")
				}
				continue
			}
			e := m.entries[i]
			line := "📁 " + e.name
			if i == m.browseCur {
				b.WriteString("  " + ui.ActiveStyle.Render("➤ ") + ui.ActiveStyle.Render(line) + "\n")
			} else {
				b.WriteString("    " + line + "\n")
			}
		}

		if end < totalItems {
			b.WriteString(fmt.Sprintf("  %s\n", ui.DimStyle.Render(fmt.Sprintf("  ↓ %d more below", totalItems-end))))
		}

		b.WriteString(fmt.Sprintf("\n  %s\n", ui.DimStyle.Render(fmt.Sprintf("%d folders", len(m.entries)))))
		b.WriteString("\n  " + ui.DimStyle.Render("? help  ↑/↓ navigate  → enter folder  ← parent  enter open  s scan current  esc back  ctrl+c quit") + "\n")
		return b.String()
	}

	if m.step == stepScanning && !m.scanned {
		b.WriteString("  " + ui.DimStyle.Render("Scanning recursively (max depth 5)…") + "\n")
		b.WriteString("\n  " + ui.DimStyle.Render("esc back  ctrl+c quit") + "\n")
		return b.String()
	}

	if len(m.rows) == 0 {
		b.WriteString("  " + ui.WarnStyle.Render("No certificate files found") + "\n")
		b.WriteString("\n  " + ui.DimStyle.Render("esc back  ctrl+c quit") + "\n")
		return b.String()
	}

	// Column widths
	fileW, cnW, expW, daysW := 24, 28, 12, 5

	// Header (4-space indent to match cursor prefix "  ➤ " / "    ")
	b.WriteString(fmt.Sprintf("    %s │ %s │ %s │ %s │ %s\n",
		padRight("File", fileW),
		padRight("CN", cnW),
		padRight("Expires", expW),
		padLeft("Days", daysW),
		"Status"))
	b.WriteString("    " + strings.Repeat("─", fileW) +
		"─┼─" + strings.Repeat("─", cnW) +
		"─┼─" + strings.Repeat("─", expW) +
		"─┼─" + strings.Repeat("─", daysW) +
		"─┼─" + strings.Repeat("─", 12) + "\n")

	// Compute viewport
	viewHeight := m.height - 18
	if viewHeight < 5 {
		viewHeight = 12
	}
	if len(m.rows) > viewHeight {
		if m.cursor-m.scroll >= viewHeight {
			m.scroll = m.cursor - viewHeight + 1
		}
		if m.cursor < m.scroll {
			m.scroll = m.cursor
		}
	} else {
		m.scroll = 0
	}
	end := m.scroll + viewHeight
	if end > len(m.rows) {
		end = len(m.rows)
	}

	var nOK, nWarn, nExpired, nPFX, nErr int
	for _, r := range m.rows {
		switch r.Status {
		case "ok":
			nOK++
		case "warn":
			nWarn++
		case "expired":
			nExpired++
		case "pfx":
			nPFX++
		case "error":
			nErr++
		}
	}

	if m.scroll > 0 {
		b.WriteString(fmt.Sprintf("  %s\n", ui.DimStyle.Render(fmt.Sprintf("↑ %d above", m.scroll))))
	}
	for i := m.scroll; i < end; i++ {
		r := m.rows[i]
		row := formatRow(r, fileW, cnW, expW, daysW)
		if i == m.cursor {
			b.WriteString("  " + ui.ActiveStyle.Render("➤ ") + row + "\n")
		} else {
			b.WriteString("    " + row + "\n")
		}
	}
	if end < len(m.rows) {
		b.WriteString(fmt.Sprintf("  %s\n", ui.DimStyle.Render(fmt.Sprintf("↓ %d below", len(m.rows)-end))))
	}

	b.WriteString("\n")
	totals := fmt.Sprintf("%s  %s  %s",
		ui.SuccessStyle.Render(fmt.Sprintf("%d valid", nOK)),
		ui.WarnStyle.Render(fmt.Sprintf("%d expiring soon", nWarn)),
		ui.ErrorStyle.Render(fmt.Sprintf("%d expired", nExpired)))
	if nPFX > 0 {
		totals += "  " + ui.DimStyle.Render(fmt.Sprintf("%d PFX (skipped)", nPFX))
	}
	if nErr > 0 {
		totals += "  " + ui.DimStyle.Render(fmt.Sprintf("%d error", nErr))
	}
	b.WriteString("  " + totals + "\n")

	sortLabel := "days"
	switch m.sortMode {
	case sortByCN:
		sortLabel = "cn"
	case sortByExpiry:
		sortLabel = "expiry"
	}
	b.WriteString("\n  " + ui.DimStyle.Render(fmt.Sprintf(
		"? help  ↑/↓ navigate  enter inspect  r/c/d sort  [sort=%s]  b browse folders  esc back  ctrl+c quit",
		sortLabel)) + "\n")
	return b.String()
}

func (m *Model) renderHelp() string {
	sections := []ui.HelpSection{
		{
			Title: "Folder browser",
			Entries: []ui.HelpEntry{
				{"↑/↓", "Navigate entries"},
				{"→ / enter", "Open folder"},
				{"←", "Parent folder"},
				{"s", "Scan current folder"},
				{"enter", "On \"[Scan this folder]\" starts scan"},
			},
		},
		{
			Title: "Results table",
			Entries: []ui.HelpEntry{
				{"↑/↓", "Navigate rows"},
				{"enter", "Open cert details"},
				{"r", "Sort by days remaining"},
				{"c", "Sort by CN"},
				{"d", "Sort by expiry date"},
				{"b", "Back to folder browser"},
			},
		},
		ui.CommonHelp(),
	}
	return "\n" + ui.Banner() + "  " + ui.TitleStyle.Render("── Batch Inspect ──") + "\n" + ui.RenderHelp("Batch Inspect — Help", sections)
}

func formatRow(r Row, fileW, cnW, expW, daysW int) string {
	file := padRight(truncate(filepath.Base(r.Path), fileW), fileW)
	cn := padRight(truncate(r.CN, cnW), cnW)
	expStr := r.NotAfter
	if expStr == "" {
		expStr = "—"
	}
	exp := padRight(truncate(expStr, expW), expW)

	var days string
	if r.Status == "pfx" || r.Status == "error" {
		days = "—"
	} else {
		days = fmt.Sprintf("%d", r.Days)
	}
	days = padLeft(days, daysW)

	var status string
	switch r.Status {
	case "ok":
		status = ui.SuccessStyle.Render("✔ OK")
	case "warn":
		status = ui.WarnStyle.Render(fmt.Sprintf("⚠ %dd", r.Days))
	case "expired":
		status = ui.ErrorStyle.Render("✖ EXPIRED")
	case "pfx":
		status = ui.DimStyle.Render("🔒 password")
	case "error":
		status = ui.DimStyle.Render("— " + r.Error)
	default:
		status = "—"
	}

	dataCols := fmt.Sprintf("%s │ %s │ %s │ %s", file, cn, exp, days)

	// Color the non-status columns by status
	switch r.Status {
	case "expired":
		return ui.ErrorStyle.Render(dataCols) + " │ " + status
	case "warn":
		return ui.WarnStyle.Render(dataCols) + " │ " + status
	case "ok":
		return ui.SuccessStyle.Render(dataCols) + " │ " + status
	}
	return dataCols + " │ " + status
}

// truncate cuts a string to a maximum display width, using runewidth-aware
// logic (handles multi-byte chars like emojis and accented letters).
func truncate(s string, w int) string {
	if runewidth.StringWidth(s) <= w {
		return s
	}
	if w <= 3 {
		return runewidth.Truncate(s, w, "")
	}
	return runewidth.Truncate(s, w, "...")
}

// padRight pads a string with spaces on the right to reach width w (display cols).
func padRight(s string, w int) string {
	pad := w - runewidth.StringWidth(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}

// padLeft pads a string with spaces on the left to reach width w (display cols).
func padLeft(s string, w int) string {
	pad := w - runewidth.StringWidth(s)
	if pad <= 0 {
		return s
	}
	return strings.Repeat(" ", pad) + s
}
