package ui

import "github.com/charmbracelet/lipgloss"

var (
	ColorCyan    = lipgloss.Color("14")
	ColorMagenta = lipgloss.Color("5")
	ColorGreen   = lipgloss.Color("2")
	ColorRed     = lipgloss.Color("1")
	ColorYellow  = lipgloss.Color("3")
	ColorDim     = lipgloss.Color("8")

	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorCyan)

	SubtitleStyle = lipgloss.NewStyle().
			Italic(true).
			Foreground(ColorMagenta)

	DimStyle = lipgloss.NewStyle().
			Faint(true)

	ActiveStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorCyan)

	InactiveStyle = lipgloss.NewStyle()

	SeparatorStyle = lipgloss.NewStyle().
			Faint(true)

	DescStyle = lipgloss.NewStyle().
			Foreground(ColorMagenta)

	SuccessStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorGreen)

	ErrorStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorRed)

	WarnStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorYellow)

	BoxStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(ColorCyan).
			Padding(1, 2)
)

const Version = "1.0.0"

func Banner() string {
	logo := TitleStyle.Render(
		"                _        _\n"+
			"  ___ ___ _ __| |_ _   _(_)\n"+
			" / __/ _ \\ '__| __| | | | |\n"+
			"| (_|  __/ |  | |_| |_| | |\n"+
			" \\___\\___|_|   \\__|\\__,_|_|") +
		DimStyle.Render("  v"+Version)
	subtitle := SubtitleStyle.Render("  Digital certificate conversion, validation and generation")
	return logo + "\n" + subtitle + "\n"
}
