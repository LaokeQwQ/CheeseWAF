package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type model struct {
	cursor int
	items  []string
	status string
}

func newModel() model {
	return model{
		items: []string{
			"Service status",
			"SSL certificate",
			"Admin users",
			"Live logs",
			"Quick diagnostics",
			"Quit",
		},
		status: "Use arrow keys and Enter.",
	}
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.items)-1 {
				m.cursor++
			}
		case "enter":
			if m.items[m.cursor] == "Quit" {
				return m, tea.Quit
			}
			m.status = fmt.Sprintf("%s is wired to the admin API in Phase 1.", m.items[m.cursor])
		}
	}
	return m, nil
}

func (m model) View() string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86")).Render("CheeseWAF TUI")
	var b strings.Builder
	b.WriteString(title + "\n\n")
	for i, item := range m.items {
		prefix := "  "
		if i == m.cursor {
			prefix = "> "
		}
		b.WriteString(prefix + item + "\n")
	}
	b.WriteString("\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Render(m.status) + "\n")
	return b.String()
}
