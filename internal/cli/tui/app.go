package tui

import tea "github.com/charmbracelet/bubbletea"

type Options struct {
	ConfigPath string
	DataDir    string
}

func Run(options ...Options) error {
	opts := Options{}
	if len(options) > 0 {
		opts = options[0]
	}
	_, err := tea.NewProgram(newModel(opts)).Run()
	return err
}
