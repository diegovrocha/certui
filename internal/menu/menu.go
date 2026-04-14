package menu

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/diegovrocha/certui/internal/batch"
	"github.com/diegovrocha/certui/internal/convert"
	"github.com/diegovrocha/certui/internal/generate"
	"github.com/diegovrocha/certui/internal/history"
	"github.com/diegovrocha/certui/internal/inspect"
	"github.com/diegovrocha/certui/internal/remote"
	"github.com/diegovrocha/certui/internal/ui"
	"github.com/diegovrocha/certui/internal/update"
	"github.com/diegovrocha/certui/internal/verify"
)

type menuItem struct {
	label       string
	desc        string
	action      string
	isSeparator bool
}

type screen int

const (
	screenMenu screen = iota
	screenSub
)

type Model struct {
	items      []menuItem
	cursor     int
	screen     screen
	sub        tea.Model
	width      int
	height     int
	quitting   bool
	updateMsg  string
	updateDone bool

	// Fuzzy filter state (main menu only)
	filterMode bool
	filterText string

	// Contextual help overlay
	showHelp bool
}

func New() Model {
	items := []menuItem{
		{label: "── CONVERT ──────────────────────────────────────", isSeparator: true},
		{label: "PFX/P12 → PEM", desc: "certificate + key as text", action: "pfx_pem"},
		{label: "PFX/P12 → CER", desc: "certificate PEM (text)", action: "pfx_cer_pem"},
		{label: "PFX/P12 → CER", desc: "certificate DER (binary)", action: "pfx_cer_der"},
		{label: "PFX/P12 → KEY", desc: "private key only", action: "pfx_key"},
		{label: "PFX/P12 → P12", desc: "repack --legacy → modern", action: "pfx_repack"},
		{label: "── VALIDATE ─────────────────────────────────────", isSeparator: true},
		{label: "Inspect", desc: "subject, validity, issuer...", action: "inspect"},
		{label: "Download from URL", desc: "fetch cert from server (TLS)", action: "remote"},
		{label: "Batch inspect", desc: "scan folder for all certs", action: "batch_inspect"},
		{label: "Verify chain", desc: "validate cert → CA → root", action: "verify_chain"},
		{label: "Verify cert+key", desc: "check if cert matches key", action: "verify_key"},
		{label: "Compare certs", desc: "check if two certs are the same", action: "compare_hash"},
		{label: "── GENERATE ─────────────────────────────────────", isSeparator: true},
		{label: "Generate self-signed", desc: "create cert + key for dev/testing", action: "gen_self"},
		{label: "─────────────────────────────────────────────────", isSeparator: true},
		{label: "History", desc: "view recent operations log", action: "history"},
		{label: "Update", desc: "download and install the latest version", action: "update"},
		{label: "Quit", action: "quit"},
	}

	m := Model{items: items, cursor: 1}
	return m
}

type updateCheckMsg string

func checkForUpdate() tea.Msg {
	return updateCheckMsg(ui.CheckUpdate())
}

func (m Model) Init() tea.Cmd {
	return checkForUpdate
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case updateCheckMsg:
		m.updateMsg = string(msg)
		m.updateDone = true
		return m, nil

	case tea.KeyMsg:
		if m.screen == screenSub {
			return m.updateSub(msg)
		}
		return m.updateMenu(msg)
	}

	if m.screen == screenSub && m.sub != nil {
		var cmd tea.Cmd
		m.sub, cmd = m.sub.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m Model) updateMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Help overlay toggle (only when not typing in filter mode)
	if !m.filterMode {
		if key == "?" {
			m.showHelp = !m.showHelp
			return m, nil
		}
		if m.showHelp {
			if key == "esc" {
				m.showHelp = false
				return m, nil
			}
			// Swallow all other keys while help is open
			return m, nil
		}
	}

	if m.filterMode {
		switch key {
		case "esc":
			m.filterMode = false
			m.filterText = ""
			m.resetCursor()
			return m, nil
		case "enter":
			visible := m.visibleIndices()
			if len(visible) == 0 {
				return m, nil
			}
			action := m.items[m.cursor].action
			if action == "" || m.items[m.cursor].isSeparator {
				return m, nil
			}
			return m.handleAction(action)
		case "up":
			m.moveCursorFiltered(-1)
			return m, nil
		case "down":
			m.moveCursorFiltered(1)
			return m, nil
		case "backspace":
			if len(m.filterText) > 0 {
				m.filterText = m.filterText[:len(m.filterText)-1]
			}
			m.snapCursorToFirstMatch()
			return m, nil
		case "/":
			// Toggle off only when filter is empty.
			if m.filterText == "" {
				m.filterMode = false
				m.resetCursor()
			}
			return m, nil
		case "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case " ", "space":
			m.filterText += " "
			m.snapCursorToFirstMatch()
			return m, nil
		}
		// Accept printable single-rune keys as filter input.
		if len(msg.Runes) == 1 {
			r := msg.Runes[0]
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == ' ' || r == '-' || r == '_' {
				m.filterText += string(r)
				m.snapCursorToFirstMatch()
				return m, nil
			}
		}
		return m, nil
	}

	switch key {
	case "up", "k":
		m.moveCursor(-1)
	case "down", "j":
		m.moveCursor(1)
	case "/":
		m.filterMode = true
		m.filterText = ""
		m.snapCursorToFirstMatch()
		return m, nil
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	case "enter":
		action := m.items[m.cursor].action
		return m.handleAction(action)
	}
	return m, nil
}

func (m Model) updateSub(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.screen = screenMenu
		m.sub = nil
		return m, nil
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	}
	if m.sub != nil {
		var cmd tea.Cmd
		m.sub, cmd = m.sub.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *Model) moveCursor(delta int) {
	n := len(m.items)
	for i := 0; i < n; i++ {
		m.cursor = (m.cursor + delta + n) % n
		if !m.items[m.cursor].isSeparator {
			break
		}
	}
}

// moveCursorFiltered moves the cursor within currently matching items.
func (m *Model) moveCursorFiltered(delta int) {
	visible := m.visibleIndices()
	if len(visible) == 0 {
		return
	}
	// Find current position in visible list.
	pos := 0
	for i, idx := range visible {
		if idx == m.cursor {
			pos = i
			break
		}
	}
	pos = (pos + delta + len(visible)) % len(visible)
	m.cursor = visible[pos]
}

// resetCursor points cursor at the first non-separator item.
func (m *Model) resetCursor() {
	for i, it := range m.items {
		if !it.isSeparator {
			m.cursor = i
			return
		}
	}
}

// snapCursorToFirstMatch snaps the cursor to the first filter-matching item.
func (m *Model) snapCursorToFirstMatch() {
	visible := m.visibleIndices()
	if len(visible) > 0 {
		m.cursor = visible[0]
	}
}

// visibleIndices returns the indices of items that currently match the filter
// (or all selectable items when filter is empty / inactive).
func (m Model) visibleIndices() []int {
	var out []int
	q := strings.ToLower(strings.TrimSpace(m.filterText))
	for i, it := range m.items {
		if it.isSeparator {
			continue
		}
		if !m.filterMode || q == "" {
			out = append(out, i)
			continue
		}
		hay := strings.ToLower(it.label + " " + it.desc)
		if strings.Contains(hay, q) {
			out = append(out, i)
		}
	}
	return out
}

func (m Model) handleAction(action string) (tea.Model, tea.Cmd) {
	switch action {
	case "quit":
		m.quitting = true
		return m, tea.Quit
	case "pfx_pem":
		m.screen = screenSub
		m.sub = convert.NewPfxToPem()
		return m, m.sub.Init()
	case "pfx_cer_pem":
		m.screen = screenSub
		m.sub = convert.NewPfxToCerPem()
		return m, m.sub.Init()
	case "pfx_cer_der":
		m.screen = screenSub
		m.sub = convert.NewPfxToCerDer()
		return m, m.sub.Init()
	case "pfx_key":
		m.screen = screenSub
		m.sub = convert.NewPfxToKey()
		return m, m.sub.Init()
	case "pfx_repack":
		m.screen = screenSub
		m.sub = convert.NewPfxRepack()
		return m, m.sub.Init()
	case "inspect":
		m.screen = screenSub
		m.sub = inspect.New()
		return m, m.sub.Init()
	case "remote":
		m.screen = screenSub
		m.sub = remote.New()
		return m, m.sub.Init()
	case "batch_inspect":
		m.screen = screenSub
		m.sub = batch.New()
		return m, m.sub.Init()
	case "verify_chain":
		m.screen = screenSub
		m.sub = verify.NewChain()
		return m, m.sub.Init()
	case "verify_key":
		m.screen = screenSub
		m.sub = verify.NewCertKey()
		return m, m.sub.Init()
	case "compare_hash":
		m.screen = screenSub
		m.sub = verify.NewCompareHash()
		return m, m.sub.Init()
	case "gen_self":
		m.screen = screenSub
		m.sub = generate.NewSelfSigned()
		return m, m.sub.Init()
	case "update":
		m.screen = screenSub
		m.sub = update.New()
		return m, m.sub.Init()
	case "history":
		m.screen = screenSub
		m.sub = history.NewView()
		return m, m.sub.Init()
	}
	return m, nil
}

func (m Model) View() string {
	if m.quitting {
		return "\n  " + ui.SuccessStyle.Render("Goodbye!") + "\n\n"
	}

	if m.screen == screenSub && m.sub != nil {
		return m.sub.View()
	}

	if m.showHelp {
		return m.renderHelp()
	}

	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(ui.Banner())
	b.WriteString("  " + ui.DimStyle.Render(ui.OpenSSLVersion()) + "\n")
	if m.updateMsg != "" {
		b.WriteString("  " + ui.WarnStyle.Render(m.updateMsg) + "\n")
	}
	b.WriteString("\n")

	filtering := m.filterMode && strings.TrimSpace(m.filterText) != ""
	visibleSet := map[int]bool{}
	matches := 0
	if filtering {
		for _, idx := range m.visibleIndices() {
			visibleSet[idx] = true
			matches++
		}
	}

	// Build menu lines
	for i, item := range m.items {
		if item.isSeparator {
			if filtering {
				// Hide separators while filtering.
				continue
			}
			b.WriteString(fmt.Sprintf("  %s\n", ui.SeparatorStyle.Render(item.label)))
			continue
		}
		if filtering && !visibleSet[i] {
			continue
		}

		cursor := "  "
		labelStyle := ui.InactiveStyle
		if m.cursor == i {
			cursor = ui.ActiveStyle.Render("➤ ")
			labelStyle = ui.ActiveStyle
		}

		label := labelStyle.Render(fmt.Sprintf("%-20s", item.label))
		desc := ui.DescStyle.Render(item.desc)
		b.WriteString(fmt.Sprintf("  %s%s %s\n", cursor, label, desc))
	}

	if m.filterMode {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s %s_  %s\n",
			ui.ActiveStyle.Render("Filter:"),
			m.filterText,
			ui.DimStyle.Render("(esc to clear)")))
		b.WriteString(fmt.Sprintf("  %s\n", ui.DimStyle.Render(fmt.Sprintf("Matches: %d", matches))))
		b.WriteString("\n  " + ui.DimStyle.Render("↑/↓ navigate  enter select  backspace delete  esc clear  ctrl+c quit") + "\n")
	} else {
		b.WriteString("\n  " + ui.DimStyle.Render("? help  ↑/↓ navigate  enter select  / filter  q / ctrl+c quit") + "\n")
	}

	return b.String()
}

func (m Model) renderHelp() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(ui.Banner())
	b.WriteString("  " + ui.TitleStyle.Render("── Main Menu ──") + "\n")
	sections := []ui.HelpSection{
		{
			Title: "Navigation",
			Entries: []ui.HelpEntry{
				{"↑/↓ or j/k", "Navigate menu items"},
				{"enter", "Select highlighted item"},
				{"q", "Quit certui"},
			},
		},
		{
			Title: "Search",
			Entries: []ui.HelpEntry{
				{"/", "Fuzzy filter menu items"},
				{"esc", "Clear filter"},
			},
		},
		ui.CommonHelp(),
	}
	b.WriteString(ui.RenderHelp("Main Menu — Help", sections))
	return b.String()
}

func (m Model) indexOf(target menuItem) int {
	for i, item := range m.items {
		if item.action == target.action && item.label == target.label {
			return i
		}
	}
	return -1
}
