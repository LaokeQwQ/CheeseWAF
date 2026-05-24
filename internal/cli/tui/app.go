package tui

import tea "github.com/charmbracelet/bubbletea"

func Run() error {
	_, err := tea.NewProgram(newModel()).Run()
	return err
}
