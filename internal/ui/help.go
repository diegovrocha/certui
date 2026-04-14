package ui

import (
	"fmt"
	"strings"
)

// HelpEntry is a single (key, description) pair in a help overlay.
type HelpEntry struct {
	Key  string
	Desc string
}

// HelpSection groups related help entries under a heading.
type HelpSection struct {
	Title   string
	Entries []HelpEntry
}

// RenderHelp builds a bordered help box from sections.
//
// Usage:
//	if m.showHelp {
//	    return ui.RenderHelp("Inspect — Help", []ui.HelpSection{...})
//	}
func RenderHelp(title string, sections []HelpSection) string {
	var b strings.Builder

	// Compute max key width for column alignment
	maxKey := 0
	for _, s := range sections {
		for _, e := range s.Entries {
			if l := len(e.Key); l > maxKey {
				maxKey = l
			}
		}
	}
	if maxKey < 8 {
		maxKey = 8
	}

	b.WriteString("\n  " + TitleStyle.Render("? "+title) + "\n")
	b.WriteString("  " + DimStyle.Render(strings.Repeat("─", len(title)+2)) + "\n\n")

	for i, section := range sections {
		if i > 0 {
			b.WriteString("\n")
		}
		if section.Title != "" {
			b.WriteString("  " + ActiveStyle.Render(section.Title) + "\n")
		}
		for _, e := range section.Entries {
			b.WriteString(fmt.Sprintf("    %s  %s\n",
				ActiveStyle.Render(fmt.Sprintf("%-*s", maxKey, e.Key)),
				e.Desc,
			))
		}
	}

	b.WriteString("\n  " + DimStyle.Render("press ? or esc to close") + "\n")
	return b.String()
}

// CommonHelp returns entries shared across every screen.
func CommonHelp() HelpSection {
	return HelpSection{
		Title: "Global",
		Entries: []HelpEntry{
			{"?", "Toggle this help overlay"},
			{"esc", "Back to previous screen"},
			{"ctrl+c", "Quit certui"},
		},
	}
}
