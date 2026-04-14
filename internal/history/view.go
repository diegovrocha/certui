package history

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/diegovrocha/certui/internal/ui"
)

type Model struct {
	lines    []string
	err      string
	scroll   int
	height   int
	showHelp bool
}

func NewView() tea.Model {
	m := &Model{}
	lines, err := Read()
	if err != nil {
		m.err = err.Error()
		return m
	}
	// Keep last 50 entries
	if len(lines) > 50 {
		lines = lines[len(lines)-50:]
	}
	m.lines = lines
	return m
}

func (m *Model) Init() tea.Cmd { return nil }

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.height = msg.Height
	case tea.KeyMsg:
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
		switch msg.String() {
		case "up", "k":
			if m.scroll > 0 {
				m.scroll--
			}
		case "down", "j":
			m.scroll++
		case "pgup":
			m.scroll -= 10
			if m.scroll < 0 {
				m.scroll = 0
			}
		case "pgdown":
			m.scroll += 10
		case "home", "g":
			m.scroll = 0
		case "end", "G":
			m.scroll = len(m.lines)
		}
	}
	return m, nil
}

func (m *Model) View() string {
	if m.showHelp {
		return m.renderHelp()
	}
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(ui.Banner())
	b.WriteString("\n  " + ui.TitleStyle.Render("── History ──") + "\n\n")

	if m.err != "" {
		b.WriteString(ui.ResultBox(false, "Error", m.err))
		b.WriteString("\n  " + ui.DimStyle.Render("? help  esc back  ctrl+c quit") + "\n")
		return b.String()
	}

	if len(m.lines) == 0 {
		b.WriteString("  " + ui.DimStyle.Render("No history yet. Perform an operation to see entries here.") + "\n")
		b.WriteString("\n  " + ui.DimStyle.Render("? help  esc back  ctrl+c quit") + "\n")
		return b.String()
	}

	viewHeight := m.height - 15
	if viewHeight < 5 {
		viewHeight = 20
	}

	total := len(m.lines)
	if total <= viewHeight {
		m.scroll = 0
		for _, l := range m.lines {
			b.WriteString("  " + l + "\n")
		}
	} else {
		maxScroll := total - viewHeight
		if m.scroll > maxScroll {
			m.scroll = maxScroll
		}
		if m.scroll < 0 {
			m.scroll = 0
		}
		end := m.scroll + viewHeight
		if end > total {
			end = total
		}
		if m.scroll > 0 {
			b.WriteString("  " + ui.DimStyle.Render(fmt.Sprintf("↑ %d lines above", m.scroll)) + "\n")
		}
		for i := m.scroll; i < end; i++ {
			b.WriteString("  " + m.lines[i] + "\n")
		}
		remaining := total - end
		if remaining > 0 {
			b.WriteString("  " + ui.DimStyle.Render(fmt.Sprintf("↓ %d lines below", remaining)) + "\n")
		}
	}

	b.WriteString("\n  " + ui.DimStyle.Render(fmt.Sprintf("? help  Showing last %d entries  ↑/↓ scroll  esc back  ctrl+c quit", total)) + "\n")
	return b.String()
}

func (m *Model) renderHelp() string {
	sections := []ui.HelpSection{
		{
			Title: "Navigation",
			Entries: []ui.HelpEntry{
				{"↑/↓", "Scroll one line"},
				{"PgUp/PgDn", "Page up / down"},
				{"g", "Top"},
				{"G", "Bottom"},
			},
		},
		ui.CommonHelp(),
	}
	return "\n" + ui.Banner() + "  " + ui.TitleStyle.Render("── History ──") + "\n" + ui.RenderHelp("History — Help", sections)
}
