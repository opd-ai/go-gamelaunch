package gamelaunch

import (
	"fmt"
	"sort"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
)

// gameItem represents a game in the menu list
type gameItem struct {
	id   string
	name string
}

func (i gameItem) Title() string       { return i.name }
func (i gameItem) Description() string { return fmt.Sprintf("ID: %s", i.id) }
func (i gameItem) FilterValue() string { return i.name }

// menuModel is the model for the game selection menu
type menuModel struct {
	list     list.Model
	selected string
	quitting bool
}

// createGameMenu creates the game selection menu
func (l *Launcher) createGameMenu() tea.Model {
	// Create sorted list of games
	var items []list.Item
	var gameIDs []string

	for id := range l.games {
		gameIDs = append(gameIDs, id)
	}
	sort.Strings(gameIDs)

	for _, id := range gameIDs {
		game := l.games[id]
		items = append(items, gameItem{
			id:   game.ID,
			name: game.Name,
		})
	}

	// Create list with custom styling
	const listHeight = 20
	const listWidth = 60

	lst := list.New(items, list.NewDefaultDelegate(), listWidth, listHeight)
	lst.Title = "🎮 Select a Game"
	lst.SetShowStatusBar(true)
	lst.SetFilteringEnabled(true)
	lst.Styles.Title = lst.Styles.Title.Bold(true)
	lst.SetShowHelp(true)

	return menuModel{
		list: lst,
	}
}

// Init initializes the menu model
func (m menuModel) Init() tea.Cmd {
	return nil
}

// Update handles menu input
func (m menuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.list.SetWidth(msg.Width)
		m.list.SetHeight(msg.Height - 2)
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case "enter":
			if item, ok := m.list.SelectedItem().(gameItem); ok {
				m.selected = item.id
				return m, tea.Quit
			}
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

// View renders the menu
func (m menuModel) View() string {
	if m.selected != "" {
		return fmt.Sprintf("Launching %s...\n", m.selected)
	}
	return m.list.View()
}
