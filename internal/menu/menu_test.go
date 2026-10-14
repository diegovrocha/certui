package menu

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestNewMenu(t *testing.T) {
	m := New()

	if len(m.items) == 0 {
		t.Error("Menu should have items")
	}

	// First selectable item should not be a separator
	if m.items[m.cursor].isSeparator {
		t.Error("Initial cursor should not be on a separator")
	}
}

func TestMoveCursorSkipsSeparators(t *testing.T) {
	m := New()

	// Cursor starts at 1 (first selectable item)
	initial := m.cursor
	if m.items[initial].isSeparator {
		t.Error("Initial position should not be a separator")
	}

	// Move down
	m.moveCursor(1)
	if m.items[m.cursor].isSeparator {
		t.Error("moveCursor(1) should not stop on a separator")
	}

	// Move up
	m.moveCursor(-1)
	if m.items[m.cursor].isSeparator {
		t.Error("moveCursor(-1) should not stop on a separator")
	}
}

func TestMoveCursorWraps(t *testing.T) {
	m := New()

	// Move up many times - should wrap
	for i := 0; i < len(m.items)*2; i++ {
		m.moveCursor(-1)
		if m.items[m.cursor].isSeparator {
			t.Errorf("Cursor stopped on separator at index %d", m.cursor)
		}
	}

	// Move down many times - should wrap
	for i := 0; i < len(m.items)*2; i++ {
		m.moveCursor(1)
		if m.items[m.cursor].isSeparator {
			t.Errorf("Cursor stopped on separator at index %d", m.cursor)
		}
	}
}

func TestMenuHasAllActions(t *testing.T) {
	m := New()

	expectedActions := []string{
		"pfx_pem", "pfx_cer_pem", "pfx_cer_der", "pfx_key", "extract_key", "pfx_repack",
		"inspect", "remote", "batch_inspect", "verify_chain", "verify_key", "compare_hash", "gen_self", "history", "update", "quit",
	}

	actions := make(map[string]bool)
	for _, item := range m.items {
		if item.action != "" {
			actions[item.action] = true
		}
	}

	for _, expected := range expectedActions {
		if !actions[expected] {
			t.Errorf("Menu should have action '%s'", expected)
		}
	}
}

func TestMenuView(t *testing.T) {
	m := New()
	v := m.View()

	if !strings.Contains(v, "CONVERT") {
		t.Error("View should contain CONVERT section")
	}
	if !strings.Contains(v, "VALIDATE") {
		t.Error("View should contain VALIDATE section")
	}
	if !strings.Contains(v, "GENERATE") {
		t.Error("View should contain GENERATE section")
	}
	if !strings.Contains(v, "➤") {
		t.Error("View should contain cursor ➤")
	}
	if !strings.Contains(v, "Quit") {
		t.Error("View should contain Quit option")
	}
}

func TestMenuQuit(t *testing.T) {
	m := New()
	m.quitting = true
	v := m.View()

	if !strings.Contains(v, "Goodbye") {
		t.Error("View on quit should show 'Goodbye'")
	}
}

func sendKey(m Model, key string) Model {
	var km tea.KeyMsg
	if len(key) == 1 {
		km = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
	} else {
		switch key {
		case "esc":
			km = tea.KeyMsg{Type: tea.KeyEsc}
		case "backspace":
			km = tea.KeyMsg{Type: tea.KeyBackspace}
		case "enter":
			km = tea.KeyMsg{Type: tea.KeyEnter}
		case "up":
			km = tea.KeyMsg{Type: tea.KeyUp}
		case "down":
			km = tea.KeyMsg{Type: tea.KeyDown}
		default:
			km = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
		}
	}
	next, _ := m.Update(km)
	return next.(Model)
}

func TestFuzzyFilterActivation(t *testing.T) {
	m := New()
	if m.filterMode {
		t.Fatal("filterMode should start false")
	}
	m = sendKey(m, "/")
	if !m.filterMode {
		t.Error("after '/', filterMode should be true")
	}
}

func TestFuzzyFilterText(t *testing.T) {
	m := New()
	m = sendKey(m, "/")
	m = sendKey(m, "i")
	m = sendKey(m, "n")
	m = sendKey(m, "s")
	if m.filterText != "ins" {
		t.Errorf("filterText: got %q want %q", m.filterText, "ins")
	}
}

func TestFuzzyFilterBackspace(t *testing.T) {
	m := New()
	m = sendKey(m, "/")
	m = sendKey(m, "a")
	m = sendKey(m, "b")
	m = sendKey(m, "c")
	if m.filterText != "abc" {
		t.Fatalf("setup: got filterText=%q", m.filterText)
	}
	m = sendKey(m, "backspace")
	if m.filterText != "ab" {
		t.Errorf("after backspace: got %q want ab", m.filterText)
	}
}

func TestFuzzyFilterEsc(t *testing.T) {
	m := New()
	m = sendKey(m, "/")
	m = sendKey(m, "x")
	if !m.filterMode || m.filterText == "" {
		t.Fatal("setup: filter should be active with text")
	}
	m = sendKey(m, "esc")
	if m.filterMode {
		t.Error("after esc, filterMode should be false")
	}
	if m.filterText != "" {
		t.Errorf("after esc, filterText should be empty, got %q", m.filterText)
	}
}

func TestFuzzyMatchItems(t *testing.T) {
	m := New()
	m.filterMode = true
	m.filterText = "insp"

	visible := m.visibleIndices()
	if len(visible) == 0 {
		t.Fatal("filter 'insp' should match at least one item")
	}
	for _, idx := range visible {
		it := m.items[idx]
		hay := strings.ToLower(it.label + " " + it.desc)
		if !strings.Contains(hay, "insp") {
			t.Errorf("visible item %q (desc %q) does not contain filter 'insp'", it.label, it.desc)
		}
	}
	// At least "Inspect" and "Batch inspect" should match.
	if len(visible) < 2 {
		t.Errorf("expected >=2 matches for 'insp', got %d", len(visible))
	}
}

// escSub is a sub-screen that claims esc while its overlay is open.
type escSub struct {
	open bool
	got  int
}

func (s *escSub) Init() tea.Cmd                           { return nil }
func (s *escSub) View() string                            { return "" }
func (s *escSub) CapturesEsc() bool                       { return s.open }
func (s *escSub) Update(msg tea.Msg) (tea.Model, tea.Cmd) { s.got++; s.open = false; return s, nil }

func TestEscGoesToSubWhenItCaptures(t *testing.T) {
	sub := &escSub{open: true}
	m := New()
	m.screen, m.sub = screenSub, sub

	m = sendKey(m, "esc")
	if m.screen != screenSub || sub.got != 1 {
		t.Fatalf("esc with overlay open should stay in sub (screen=%v got=%d)", m.screen, sub.got)
	}
	m = sendKey(m, "esc")
	if m.screen != screenMenu {
		t.Error("second esc should return to the menu")
	}
}

func TestFilterEmptyShowsAllMatches(t *testing.T) {
	m := sendKey(New(), "/")
	want := fmt.Sprintf("Matches: %d", len(m.visibleIndices()))
	if !strings.Contains(m.View(), want) {
		t.Errorf("empty filter view should contain %q", want)
	}
}
