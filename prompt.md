Project Path: go-gamelaunch

Source Tree:

```
go-gamelaunch
├── pkg
│   └── gamelaunch
│       ├── session.go
│       ├── menu.go
│       ├── gamelaunch.go
│       └── auth.go
├── LICENSE
├── go.mod
├── README.md
├── cmd
│   └── gamelaunch
│       └── main.go
├── Makefile
└── go.sum

```

`/home/user/go/src/github.com/opd-ai/go-gamelaunch/pkg/gamelaunch/session.go`:

```go
package gamelaunch

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
)

// sessionHandler handles incoming SSH sessions
func (l *Launcher) sessionHandler(s ssh.Session) {
	// Check if PTY was requested
	ptyReq, winCh, isPty := s.Pty()
	if !isPty {
		io.WriteString(s, "Error: This service requires an interactive terminal.\n")
		io.WriteString(s, "Please connect with: ssh user@host (not ssh user@host command)\n")
		return
	}

	// Create game selection menu
	menu := l.createGameMenu()

	// Run the menu in the SSH session
	p := tea.NewProgram(
		menu,
		tea.WithInput(s),
		tea.WithOutput(s),
		tea.WithAltScreen(),
	)

	finalModel, err := p.Run()
	if err != nil {
		io.WriteString(s, fmt.Sprintf("Error running menu: %v\n", err))
		return
	}

	// Check if a game was selected
	menuModel := finalModel.(menuModel)
	if menuModel.selected == "" || menuModel.quitting {
		return
	}

	// Launch the selected game
	if err := l.LaunchGameWithPTY(menuModel.selected, s, ptyReq, winCh); err != nil {
		io.WriteString(s, fmt.Sprintf("\nError launching game: %v\n", err))
	}
}

// LaunchGameWithPTY launches a game with proper PTY handling
func (l *Launcher) LaunchGameWithPTY(gameID string, session ssh.Session, ptyReq ssh.Pty, winCh <-chan ssh.Window) error {
	// Get game config
	game, exists := l.games[gameID]
	if !exists {
		return fmt.Errorf("game %q not found", gameID)
	}

	// Prepare command
	cmd := exec.Command(game.Command, game.Args...)

	// Apply environment variables starting with the system environment
	cmd.Env = append(os.Environ(), game.Env...)

	// Apply environment variables
	cmd.Env = append(cmd.Env, game.Env...)

	// Apply user-specific environment
	if user := session.User(); user != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("USER=%s", user))
		cmd.Env = append(cmd.Env, fmt.Sprintf("LOGNAME=%s", user))
	}

	// Apply terminal type from SSH session
	cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))

	// Check if command exists
	if _, err := exec.LookPath(game.Command); err != nil {
		return fmt.Errorf("game binary not found: %w", err)
	}

	// Start command with PTY
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{
		Rows: uint16(ptyReq.Window.Height),
		Cols: uint16(ptyReq.Window.Width),
	})
	if err != nil {
		return fmt.Errorf("failed to start game: %w", err)
	}
	defer func() {
		ptmx.Close()
		cmd.Process.Kill()
	}()

	// Handle window size changes
	go func() {
		for win := range winCh {
			pty.Setsize(ptmx, &pty.Winsize{
				Rows: uint16(win.Height),
				Cols: uint16(win.Width),
			})
		}
	}()

	// Set up bidirectional copy between SSH session and PTY
	done := make(chan error, 2)

	// Copy from SSH to PTY (user input)
	go func() {
		_, err := io.Copy(ptmx, session)
		done <- err
	}()

	// Copy from PTY to SSH (game output)
	go func() {
		_, err := io.Copy(session, ptmx)
		done <- err
	}()

	// Wait for command to finish or connection to close
	cmdDone := make(chan error, 1)
	go func() {
		cmdDone <- cmd.Wait()
	}()

	select {
	case err := <-cmdDone:
		// Game exited
		if err != nil && !strings.Contains(err.Error(), "signal: killed") {
			return fmt.Errorf("game exited with error: %w", err)
		}
		return nil
	case <-done:
		// Connection closed
		return nil
	}
}

```

`/home/user/go/src/github.com/opd-ai/go-gamelaunch/pkg/gamelaunch/menu.go`:

```go
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

```

`/home/user/go/src/github.com/opd-ai/go-gamelaunch/pkg/gamelaunch/gamelaunch.go`:

```go
package gamelaunch

import (
	"fmt"
	"net"
	"os"

	gssh "github.com/gliderlabs/ssh"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

// GameConfig represents a single game configuration
type GameConfig struct {
	ID      string
	Name    string
	Command string
	Args    []string
	Env     []string
}

// Launcher is the main game launcher service
type Launcher struct {
	games    map[string]GameConfig
	config   *viper.Viper
	server   *gssh.Server
	listener net.Listener // Custom listener support
}

// Option is a functional option for configuring the Launcher
type Option func(*Launcher) error

// WithListener sets a custom net.Listener for the SSH server
func WithListener(listener net.Listener) Option {
	return func(l *Launcher) error {
		if listener == nil {
			return fmt.Errorf("listener cannot be nil")
		}
		l.listener = listener
		return nil
	}
}

// WithConfig allows passing a pre-configured viper instance
func WithConfig(v *viper.Viper) Option {
	return func(l *Launcher) error {
		if v == nil {
			return fmt.Errorf("viper config cannot be nil")
		}
		l.config = v
		return nil
	}
}

// NewLauncher creates a new launcher instance from configuration
func NewLauncher(configPath string, opts ...Option) (*Launcher, error) {
	launcher := &Launcher{
		games: make(map[string]GameConfig),
	}

	// Apply options first
	for _, opt := range opts {
		if err := opt(launcher); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	// Load config if not provided via options
	if launcher.config == nil {
		v := viper.New()
		v.SetConfigFile(configPath)

		// Set defaults
		v.SetDefault("server.address", ":2022")
		v.SetDefault("server.host_keys", []string{"./host_key_rsa"})

		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}

		launcher.config = v
	}

	// Load games from config
	if err := launcher.loadGames(); err != nil {
		return nil, fmt.Errorf("failed to load games: %w", err)
	}

	// Setup SSH server
	if err := launcher.setupServer(); err != nil {
		return nil, fmt.Errorf("failed to setup server: %w", err)
	}

	return launcher, nil
}

// NewLauncherWithListener creates a launcher with a custom listener
// This is a convenience constructor for the common use case
func NewLauncherWithListener(configPath string, listener net.Listener) (*Launcher, error) {
	return NewLauncher(configPath, WithListener(listener))
}

// loadGames loads game configurations from viper config
func (l *Launcher) loadGames() error {
	gamesConfig := l.config.GetStringMap("games")

	for id, gameData := range gamesConfig {
		gameMap, ok := gameData.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid game config for %s", id)
		}

		game := GameConfig{
			ID:      id,
			Name:    getString(gameMap, "name", id),
			Command: getString(gameMap, "command", ""),
		}

		// Parse args if present
		if args, ok := gameMap["args"].([]interface{}); ok {
			for _, arg := range args {
				if str, ok := arg.(string); ok {
					game.Args = append(game.Args, str)
				}
			}
		}

		// Parse env if present
		if envs, ok := gameMap["env"].([]interface{}); ok {
			for _, env := range envs {
				if str, ok := env.(string); ok {
					game.Env = append(game.Env, str)
				}
			}
		}

		if game.Command == "" {
			return fmt.Errorf("game %s missing command", id)
		}

		l.games[id] = game
	}

	if len(l.games) == 0 {
		return fmt.Errorf("no games configured")
	}

	return nil
}

// setupServer configures the SSH server
func (l *Launcher) setupServer() error {
	l.server = &gssh.Server{
		Handler: l.sessionHandler,
	}

	// Only set address if no custom listener provided
	if l.listener == nil {
		l.server.Addr = l.config.GetString("server.address")
	}

	// Setup authentication
	if l.config.IsSet("auth.users") {
		l.server.PasswordHandler = l.passwordHandler
		l.server.PublicKeyHandler = l.sshPublicKeyHandler
		l.server.KeyboardInteractiveHandler = l.keyboardInteractiveHandler
	}

	// Load host keys
	hostKeys := l.config.GetStringSlice("server.host_keys")
	for _, keyPath := range hostKeys {
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("failed to read host key %s: %w", keyPath, err)
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return fmt.Errorf("failed to parse host key %s: %w", keyPath, err)
		}

		l.server.AddHostKey(signer)
	}

	return nil
}

// Address returns the server listening address
// Returns empty string if using custom listener
func (l *Launcher) Address() string {
	if l.listener != nil {
		if addr := l.listener.Addr(); addr != nil {
			return addr.String()
		}
		return "<custom listener>"
	}
	return l.config.GetString("server.address")
}

// Serve starts the SSH server
func (l *Launcher) Serve() error {
	if l.listener != nil {
		// Use custom listener
		return l.server.Serve(l.listener)
	}
	// Use default TCP listener
	return l.server.ListenAndServe()
}

// ServeWithListener starts the SSH server with a provided listener
// This allows runtime listener injection
func (l *Launcher) ServeWithListener(listener net.Listener) error {
	if listener == nil {
		return fmt.Errorf("listener cannot be nil")
	}
	return l.server.Serve(listener)
}

// Server returns the underlying SSH server for advanced configuration
func (l *Launcher) Server() *gssh.Server {
	return l.server
}

// Games returns a copy of the games configuration
func (l *Launcher) Games() map[string]GameConfig {
	games := make(map[string]GameConfig)
	for k, v := range l.games {
		games[k] = v
	}
	return games
}

// helper function to get string from interface map
func getString(m map[string]interface{}, key, defaultVal string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return defaultVal
}

```

`/home/user/go/src/github.com/opd-ai/go-gamelaunch/pkg/gamelaunch/auth.go`:

```go
package gamelaunch

import (
	"log"

	gssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
)

// passwordHandler handles password authentication
// if a user attempts to log in without an account,
// if the username is not found,
// a new account is created with the provided password
// if the user already exists, it checks the password
// returns true if authentication is successful
// returns false if authentication fails
func (l *Launcher) passwordHandler(ctx gssh.Context, password string) bool {
	users := l.config.GetStringMapString("auth.users")

	if users == nil {
		// Initialize users map if it doesn't exist
		users = make(map[string]string)
		l.config.Set("auth.users", users)
	}

	user := ctx.User()
	expectedPassword, exists := users[user]

	if !exists {
		// Create new account if user doesn't exist
		users[user] = password
		l.config.Set("auth.users", users)
		// Save config changes
		if err := l.config.WriteConfig(); err != nil {
			log.Printf("Failed to save new user: %v", err)
			return false
		}
		return true
	}

	// Check password for existing user
	return password == expectedPassword
}

// sshPublicKeyHandler handles public key authentication
// if a user attempts to log in without an account,
// if the username is not found,
// a new account is created with the provided public key
// if the user already exists, it checks the public key
// returns true if authentication is successful
func (l *Launcher) sshPublicKeyHandler(ctx gssh.Context, key gssh.PublicKey) bool {
	users := l.config.GetStringMapString("auth.users")

	if users == nil {
		// Initialize users map if it doesn't exist
		users = make(map[string]string)
		l.config.Set("auth.users", users)
	}

	user := ctx.User()
	expectedKey, exists := users[user]

	if !exists {
		// Create new account if user doesn't exist
		users[user] = string(key.Marshal())
		l.config.Set("auth.users", users)
		// Save config changes
		if err := l.config.WriteConfig(); err != nil {
			log.Printf("Failed to save new user: %v", err)
			return false
		}
		return true
	}

	// Check public key for existing user
	return string(key.Marshal()) == expectedKey
}

// keyboardInteractiveHandler handles interactive authentication
// if a user attempts to log in without an account,
// it requests a username and password.
// if the username is not found,
// it creates a new account with the provided username and password.
// a new account is created with the provided credentials
// if the user already exists, it checks the credentials
// returns true if authentication is successful
func (l *Launcher) keyboardInteractiveHandler(ctx gssh.Context, challenger ssh.KeyboardInteractiveChallenge) bool {
	users := l.config.GetStringMapString("auth.users")

	if users == nil {
		// Initialize users map if it doesn't exist
		users = make(map[string]string)
		l.config.Set("auth.users", users)
	}

	user := ctx.User()
	expectedPassword, exists := users[user]

	// Challenge for password
	answers, err := challenger(user, "", []string{"Password: "}, []bool{false})
	if err != nil || len(answers) != 1 {
		return false
	}

	password := answers[0]

	if !exists {
		// Create new account if user doesn't exist
		users[user] = password
		l.config.Set("auth.users", users)
		// Save config changes
		if err := l.config.WriteConfig(); err != nil {
			log.Printf("Failed to save new user: %v", err)
			return false
		}
		return true
	}

	// Check password for existing user
	return password == expectedPassword
}

```

`/home/user/go/src/github.com/opd-ai/go-gamelaunch/LICENSE`:

```
MIT License

Copyright (c) 2025 opdai

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

```

`/home/user/go/src/github.com/opd-ai/go-gamelaunch/go.mod`:

```mod
module github.com/opd-ai/go-gamelaunch

go 1.23.2

require (
	github.com/charmbracelet/bubbles v0.21.0
	github.com/charmbracelet/bubbletea v1.3.5
	github.com/creack/pty v1.1.24
	github.com/gliderlabs/ssh v0.3.8
	github.com/spf13/cobra v1.9.1
	github.com/spf13/viper v1.20.1
	golang.org/x/crypto v0.32.0
)

require (
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/atotto/clipboard v0.1.4 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/charmbracelet/colorprofile v0.2.3-0.20250311203215-f60798e515dc // indirect
	github.com/charmbracelet/lipgloss v1.1.0 // indirect
	github.com/charmbracelet/x/ansi v0.8.0 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.13-0.20250311204145-2c3ea96c31dd // indirect
	github.com/charmbracelet/x/term v0.2.1 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/fsnotify/fsnotify v1.8.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.2.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.3 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/sagikazarmark/locafero v0.7.0 // indirect
	github.com/sahilm/fuzzy v0.1.1 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.12.0 // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.9.0 // indirect
	golang.org/x/sync v0.13.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

```

`/home/user/go/src/github.com/opd-ai/go-gamelaunch/README.md`:

```md
# go-gamelaunch

A modern dgamelaunch-style SSH server for hosting terminal-based roguelike games, built with Go.

## Features

- 🎮 Host multiple terminal games over SSH
- 🔐 Simple password authentication
- 📟 Full PTY support with resize handling
- 🎨 Beautiful game selection menu using Bubble Tea
- ⚙️ Easy YAML configuration
- 🚀 Minimal dependencies, maximum reliability
- 🔌 Custom net.Listener support for advanced networking

## Installation

```bash
go install github.com/opd-ai/go-gamelaunch/cmd/gamelaunch@latest
```

## Quick Start

1. Generate a sample configuration:
```bash
gamelaunch generate-config
```

2. Generate SSH host keys:
```bash
ssh-keygen -t rsa -f host_key_rsa -N ''
ssh-keygen -t ed25519 -f host_key_ed25519 -N ''
```

3. Edit `config.yaml` to configure your games and users

4. Start the server:
```bash
gamelaunch
```

5. Connect with SSH:
```bash
ssh player1@localhost -p 2022
```

## Configuration

The server is configured via YAML file:

```yaml
server:
  address: :2022
  host_keys:
    - ./host_key_rsa
    - ./host_key_ed25519

auth:
  users:
    player1: password123

games:
  nethack:
    name: "NetHack 3.6.6"
    command: /usr/games/nethack
    args: []
    env:
      - "NETHACKOPTIONS=color,showexp"
```

## Advanced Usage

### Custom Listeners

The library supports custom `net.Listener` implementations for advanced networking scenarios:

```go
// TLS listener
tlsListener := tls.NewListener(tcpListener, tlsConfig)
launcher, err := gamelaunch.NewLauncherWithListener("config.yaml", tlsListener)

// Unix socket
listener, err := net.Listen("unix", "/var/run/gamelaunch.sock")
launcher, err := gamelaunch.NewLauncherWithListener("config.yaml", listener)

// Systemd socket activation
listeners, _ := activation.Listeners()
launcher, err := gamelaunch.NewLauncherWithListener("config.yaml", listeners[0])
```

### Command Line Options

```bash
# Use TLS
gamelaunch --tls --tls-cert server.crt --tls-key server.key

# Use Unix socket
gamelaunch --unix-socket /var/run/gamelaunch.sock

# Show usage examples
gamelaunch examples
```

## Library Usage

```go
import "github.com/opd-ai/go-gamelaunch/pkg/gamelaunch"

// Basic usage
launcher, err := gamelaunch.NewLauncher("config.yaml")
if err != nil {
    log.Fatal(err)
}
launcher.Serve()

// With custom listener
listener, err := net.Listen("tcp", ":2022")
launcher, err := gamelaunch.NewLauncherWithListener("config.yaml", listener)
launcher.Serve()

// With options
launcher, err := gamelaunch.NewLauncher("config.yaml",
    gamelaunch.WithListener(customListener),
    gamelaunch.WithConfig(viperConfig),
)
```

## How It Works

The server leverages several excellent Go libraries:

- **gliderlabs/ssh**: Provides the SSH server implementation
- **creack/pty**: Handles pseudo-terminal allocation for games
- **charmbracelet/bubbletea**: Creates the interactive game selection menu
- **spf13/viper**: Manages configuration

When a user connects:
1. They authenticate with username/password
2. A beautiful TUI menu appears to select a game
3. The selected game launches with full terminal emulation
4. Window resizing is handled automatically
5. When the game exits, the connection closes

## Requirements

- Go 1.21 or later
- Games must be installed and accessible on the system
- SSH client with PTY support (all standard clients work)

## Security Considerations

- Always use strong passwords or consider implementing public key authentication
- Run the server as a non-root user with minimal privileges
- Use TLS for encrypted connections when exposed to the internet
- Consider using a firewall to restrict access

## License

MIT
```

`/home/user/go/src/github.com/opd-ai/go-gamelaunch/cmd/gamelaunch/main.go`:

```go
package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/opd-ai/go-gamelaunch/pkg/gamelaunch"
	"github.com/spf13/cobra"
)

func main() {
	var (
		configPath string
		useTLS     bool
		tlsCert    string
		tlsKey     string
		unixSocket string
	)

	rootCmd := &cobra.Command{
		Use:   "gamelaunch",
		Short: "Terminal game launcher SSH server",
		Long: `A dgamelaunch-style server that allows multiple users to play
terminal-based roguelike games over SSH connections.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var launcher *gamelaunch.Launcher
			var err error

			// Handle different listener types
			switch {
			case unixSocket != "":
				// Unix socket listener
				listener, err := net.Listen("unix", unixSocket)
				if err != nil {
					return fmt.Errorf("failed to create unix socket: %w", err)
				}
				defer listener.Close()

				launcher, err = gamelaunch.NewLauncherWithListener(configPath, listener)
				if err != nil {
					return fmt.Errorf("failed to create launcher: %w", err)
				}

				log.Printf("Starting game launcher on unix socket: %s", unixSocket)

			case useTLS:
				// TLS-wrapped TCP listener
				cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
				if err != nil {
					return fmt.Errorf("failed to load TLS certificates: %w", err)
				}

				tlsConfig := &tls.Config{
					Certificates: []tls.Certificate{cert},
				}

				// Create base TCP listener
				tcpListener, err := net.Listen("tcp", ":2222")
				if err != nil {
					return fmt.Errorf("failed to create TCP listener: %w", err)
				}

				// Wrap with TLS
				tlsListener := tls.NewListener(tcpListener, tlsConfig)

				launcher, err = gamelaunch.NewLauncherWithListener(configPath, tlsListener)
				if err != nil {
					return fmt.Errorf("failed to create launcher: %w", err)
				}

				log.Printf("Starting game launcher with TLS on %s", tlsListener.Addr())

			default:
				// Standard TCP listener (handled internally)
				launcher, err = gamelaunch.NewLauncher(configPath)
				if err != nil {
					return fmt.Errorf("failed to create launcher: %w", err)
				}

				log.Printf("Starting game launcher server on %s", launcher.Address())
			}

			log.Printf("Configuration loaded from: %s", configPath)

			// Start server
			if err := launcher.Serve(); err != nil {
				return fmt.Errorf("server error: %w", err)
			}

			return nil
		},
	}

	rootCmd.Flags().StringVarP(&configPath, "config", "c", "config.yaml", "path to configuration file")
	rootCmd.Flags().BoolVar(&useTLS, "tls", false, "enable TLS")
	rootCmd.Flags().StringVar(&tlsCert, "tls-cert", "server.crt", "TLS certificate file")
	rootCmd.Flags().StringVar(&tlsKey, "tls-key", "server.key", "TLS key file")
	rootCmd.Flags().StringVar(&unixSocket, "unix-socket", "", "use Unix socket instead of TCP")

	// Add other subcommands...
	rootCmd.AddCommand(generateConfigCmd(), exampleCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func exampleCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "examples",
		Short: "Show example code for using custom listeners",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(exampleCode)
		},
	}
}

const exampleCode = `
// Example 1: Using a custom TCP listener with SO_REUSEPORT
import (
    "golang.org/x/sys/unix"
    "github.com/opd-ai/go-gamelaunch/pkg/gamelaunch"
)

func createReusePortListener(addr string) (net.Listener, error) {
    lc := net.ListenConfig{
        Control: func(network, address string, c syscall.RawConn) error {
            return c.Control(func(fd uintptr) {
                unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
            })
        },
    }
    return lc.Listen(context.Background(), "tcp", addr)
}

func main() {
    listener, err := createReusePortListener(":2022")
    if err != nil {
        log.Fatal(err)
    }
    
    launcher, err := gamelaunch.NewLauncherWithListener("config.yaml", listener)
    if err != nil {
        log.Fatal(err)
    }
    
    launcher.Serve()
}

// Example 2: Using systemd socket activation
import (
    "github.com/coreos/go-systemd/v22/activation"
)

func main() {
    listeners, err := activation.Listeners()
    if err != nil {
        log.Fatal(err)
    }
    
    if len(listeners) != 1 {
        log.Fatal("Expected exactly one socket from systemd")
    }
    
    launcher, err := gamelaunch.NewLauncherWithListener("config.yaml", listeners[0])
    if err != nil {
        log.Fatal(err)
    }
    
    launcher.Serve()
}

// Example 3: Chaining through a proxy protocol listener
import (
    proxyproto "github.com/pires/go-proxyproto"
)

func main() {
    // Create base listener
    baseListener, err := net.Listen("tcp", ":2022")
    if err != nil {
        log.Fatal(err)
    }
    
    // Wrap with PROXY protocol support
    proxyListener := &proxyproto.Listener{Listener: baseListener}
    
    launcher, err := gamelaunch.NewLauncherWithListener("config.yaml", proxyListener)
    if err != nil {
        log.Fatal(err)
    }
    
    launcher.Serve()
}

// Example 4: Using in embedded scenarios
func integrateWithExistingServer() {
    // Create launcher without starting server
    launcher, err := gamelaunch.NewLauncher("config.yaml")
    if err != nil {
        log.Fatal(err)
    }
    
    // Get the SSH server for custom configuration
    sshServer := launcher.Server()
    
    // Add custom SSH handlers
    sshServer.PublicKeyHandler = customPublicKeyHandler
    sshServer.BannerHandler = customBannerHandler
    
    // Create custom listener with your requirements
    listener := createCustomListener()
    
    // Start with custom listener
    launcher.ServeWithListener(listener)
}
`

func generateConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "generate-config",
		Short: "Generate a sample configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			return generateSampleConfig()
		},
	}
}

func generateSampleConfig() error {
	config := `# Game Launcher Configuration

server:
  # Address to listen on
  address: :2022
  
  # Host key files (generate with: ssh-keygen -t rsa -f host_key_rsa)
  host_keys:
    - ./host_key_rsa
    - ./host_key_ed25519

auth:
  # User credentials for SSH access
  users:
    player1: password123
    player2: password456
    demo: demo

games:
  # Example game configurations
  nethack:
    name: "NetHack 3.6.6"
    command: /usr/games/nethack
    args: []
    env:
      - "NETHACKOPTIONS=color,showexp,time,toptenwin"
  
  crawl:
    name: "Dungeon Crawl Stone Soup"
    command: /usr/games/crawl
    args: []
    env: []
  
  angband:
    name: "Angband"
    command: /usr/games/angband
    args: [-mgcu]
    env: []
  
  rogue:
    name: "Rogue"
    command: /usr/games/rogue
    args: []
    env:
      - "ROGUEOPTS=color,terse"
`

	if err := os.WriteFile("config.yaml", []byte(config), 0o644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Println("Generated config.yaml")
	fmt.Println("\nNext steps:")
	fmt.Println("1. Generate host keys:")
	fmt.Println("   ssh-keygen -t rsa -f host_key_rsa -N ''")
	fmt.Println("   ssh-keygen -t ed25519 -f host_key_ed25519 -N ''")
	fmt.Println("2. Edit config.yaml to add your games")
	fmt.Println("3. Run: gamelaunch")

	return nil
}

```

`/home/user/go/src/github.com/opd-ai/go-gamelaunch/Makefile`:

```
fmt:
	find . -name '*.go' -not -path './vendor/*' -exec gofumpt -extra -s -w {} \;

prompt: fmt
	code2prompt --output prompt.md .
```

`/home/user/go/src/github.com/opd-ai/go-gamelaunch/go.sum`:

```sum
github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be h1:9AeTilPcZAjCFIImctFaOjnTIavg87rW78vTPkQqLI8=
github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be/go.mod h1:ySMOLuWl6zY27l47sB3qLNK6tF2fkHG55UZxx8oIVo4=
github.com/atotto/clipboard v0.1.4 h1:EH0zSVneZPSuFR11BlR9YppQTVDbh5+16AmcJi4g1z4=
github.com/atotto/clipboard v0.1.4/go.mod h1:ZY9tmq7sm5xIbd9bOK4onWV4S6X0u6GY7Vn0Yu86PYI=
github.com/aymanbagabas/go-osc52/v2 v2.0.1 h1:HwpRHbFMcZLEVr42D4p7XBqjyuxQH5SMiErDT4WkJ2k=
github.com/aymanbagabas/go-osc52/v2 v2.0.1/go.mod h1:uYgXzlJ7ZpABp8OJ+exZzJJhRNQ2ASbcXHWsFqH8hp8=
github.com/aymanbagabas/go-udiff v0.2.0 h1:TK0fH4MteXUDspT88n8CKzvK0X9O2xu9yQjWpi6yML8=
github.com/aymanbagabas/go-udiff v0.2.0/go.mod h1:RE4Ex0qsGkTAJoQdQQCA0uG+nAzJO/pI/QwceO5fgrA=
github.com/charmbracelet/bubbles v0.21.0 h1:9TdC97SdRVg/1aaXNVWfFH3nnLAwOXr8Fn6u6mfQdFs=
github.com/charmbracelet/bubbles v0.21.0/go.mod h1:HF+v6QUR4HkEpz62dx7ym2xc71/KBHg+zKwJtMw+qtg=
github.com/charmbracelet/bubbletea v1.3.5 h1:JAMNLTbqMOhSwoELIr0qyP4VidFq72/6E9j7HHmRKQc=
github.com/charmbracelet/bubbletea v1.3.5/go.mod h1:TkCnmH+aBd4LrXhXcqrKiYwRs7qyQx5rBgH5fVY3v54=
github.com/charmbracelet/colorprofile v0.2.3-0.20250311203215-f60798e515dc h1:4pZI35227imm7yK2bGPcfpFEmuY1gc2YSTShr4iJBfs=
github.com/charmbracelet/colorprofile v0.2.3-0.20250311203215-f60798e515dc/go.mod h1:X4/0JoqgTIPSFcRA/P6INZzIuyqdFY5rm8tb41s9okk=
github.com/charmbracelet/lipgloss v1.1.0 h1:vYXsiLHVkK7fp74RkV7b2kq9+zDLoEU4MZoFqR/noCY=
github.com/charmbracelet/lipgloss v1.1.0/go.mod h1:/6Q8FR2o+kj8rz4Dq0zQc3vYf7X+B0binUUBwA0aL30=
github.com/charmbracelet/x/ansi v0.8.0 h1:9GTq3xq9caJW8ZrBTe0LIe2fvfLR/bYXKTx2llXn7xE=
github.com/charmbracelet/x/ansi v0.8.0/go.mod h1:wdYl/ONOLHLIVmQaxbIYEC/cRKOQyjTkowiI4blgS9Q=
github.com/charmbracelet/x/cellbuf v0.0.13-0.20250311204145-2c3ea96c31dd h1:vy0GVL4jeHEwG5YOXDmi86oYw2yuYUGqz6a8sLwg0X8=
github.com/charmbracelet/x/cellbuf v0.0.13-0.20250311204145-2c3ea96c31dd/go.mod h1:xe0nKWGd3eJgtqZRaN9RjMtK7xUYchjzPr7q6kcvCCs=
github.com/charmbracelet/x/exp/golden v0.0.0-20241011142426-46044092ad91 h1:payRxjMjKgx2PaCWLZ4p3ro9y97+TVLZNaRZgJwSVDQ=
github.com/charmbracelet/x/exp/golden v0.0.0-20241011142426-46044092ad91/go.mod h1:wDlXFlCrmJ8J+swcL/MnGUuYnqgQdW9rhSD61oNMb6U=
github.com/charmbracelet/x/term v0.2.1 h1:AQeHeLZ1OqSXhrAWpYUtZyX1T3zVxfpZuEQMIQaGIAQ=
github.com/charmbracelet/x/term v0.2.1/go.mod h1:oQ4enTYFV7QN4m0i9mzHrViD7TQKvNEEkHUMCmsxdUg=
github.com/cpuguy83/go-md2man/v2 v2.0.6/go.mod h1:oOW0eioCTA6cOiMLiUPZOpcVxMig6NIQQ7OS05n1F4g=
github.com/creack/pty v1.1.24 h1:bJrF4RRfyJnbTJqzRLHzcGaZK1NeM5kTC9jGgovnR1s=
github.com/creack/pty v1.1.24/go.mod h1:08sCNb52WyoAwi2QDyzUCTgcvVFhUzewun7wtTfvcwE=
github.com/davecgh/go-spew v1.1.0/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/davecgh/go-spew v1.1.1 h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=
github.com/davecgh/go-spew v1.1.1/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f h1:Y/CXytFA4m6baUTXGLOoWe4PQhGxaX0KpnayAqC48p4=
github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f/go.mod h1:vw97MGsxSvLiUE2X8qFplwetxpGLQrlU1Q9AUEIzCaM=
github.com/frankban/quicktest v1.14.6 h1:7Xjx+VpznH+oBnejlPUj8oUpdxnVs4f8XU8WnHkI4W8=
github.com/frankban/quicktest v1.14.6/go.mod h1:4ptaffx2x8+WTWXmUCuVU6aPUX1/Mz7zb5vbUoiM6w0=
github.com/fsnotify/fsnotify v1.8.0 h1:dAwr6QBTBZIkG8roQaJjGof0pp0EeF+tNV7YBP3F/8M=
github.com/fsnotify/fsnotify v1.8.0/go.mod h1:8jBTzvmWwFyi3Pb8djgCCO5IBqzKJ/Jwo8TRcHyHii0=
github.com/gliderlabs/ssh v0.3.8 h1:a4YXD1V7xMF9g5nTkdfnja3Sxy1PVDCj1Zg4Wb8vY6c=
github.com/gliderlabs/ssh v0.3.8/go.mod h1:xYoytBv1sV0aL3CavoDuJIQNURXkkfPA/wxQ1pL1fAU=
github.com/go-viper/mapstructure/v2 v2.2.1 h1:ZAaOCxANMuZx5RCeg0mBdEZk7DZasvvZIxtHqx8aGss=
github.com/go-viper/mapstructure/v2 v2.2.1/go.mod h1:oJDH3BJKyqBA2TXFhDsKDGDTlndYOZ6rGS0BRZIxGhM=
github.com/google/go-cmp v0.6.0 h1:ofyhxvXcZhMsU5ulbFiLKl/XBFqE1GSq7atu8tAmTRI=
github.com/google/go-cmp v0.6.0/go.mod h1:17dUlkBOakJ0+DkrSSNjCkIjxS6bF9zb3elmeNGIjoY=
github.com/inconshreveable/mousetrap v1.1.0 h1:wN+x4NVGpMsO7ErUn/mUI3vEoE6Jt13X2s0bqwp9tc8=
github.com/inconshreveable/mousetrap v1.1.0/go.mod h1:vpF70FUmC8bwa3OWnCshd2FqLfsEA9PFc4w1p2J65bw=
github.com/kr/pretty v0.3.1 h1:flRD4NNwYAUpkphVc1HcthR4KEIFJ65n8Mw5qdRn3LE=
github.com/kr/pretty v0.3.1/go.mod h1:hoEshYVHaxMs3cyo3Yncou5ZscifuDolrwPKZanG3xk=
github.com/kr/text v0.2.0 h1:5Nx0Ya0ZqY2ygV366QzturHI13Jq95ApcVaJBhpS+AY=
github.com/kr/text v0.2.0/go.mod h1:eLer722TekiGuMkidMxC/pM04lWEeraHUUmBw8l2grE=
github.com/kylelemons/godebug v1.1.0 h1:RPNrshWIDI6G2gRW9EHilWtl7Z6Sb1BR0xunSBf0SNc=
github.com/kylelemons/godebug v1.1.0/go.mod h1:9/0rRGxNHcop5bhtWyNeEfOS8JIWk580+fNqagV/RAw=
github.com/lucasb-eyer/go-colorful v1.2.0 h1:1nnpGOrhyZZuNyfu1QjKiUICQ74+3FNCN69Aj6K7nkY=
github.com/lucasb-eyer/go-colorful v1.2.0/go.mod h1:R4dSotOR9KMtayYi1e77YzuveK+i7ruzyGqttikkLy0=
github.com/mattn/go-isatty v0.0.20 h1:xfD0iDuEKnDkl03q4limB+vH+GxLEtL/jb4xVJSWWEY=
github.com/mattn/go-isatty v0.0.20/go.mod h1:W+V8PltTTMOvKvAeJH7IuucS94S2C6jfK/D7dTCTo3Y=
github.com/mattn/go-localereader v0.0.1 h1:ygSAOl7ZXTx4RdPYinUpg6W99U8jWvWi9Ye2JC/oIi4=
github.com/mattn/go-localereader v0.0.1/go.mod h1:8fBrzywKY7BI3czFoHkuzRoWE9C+EiG4R1k4Cjx5p88=
github.com/mattn/go-runewidth v0.0.16 h1:E5ScNMtiwvlvB5paMFdw9p4kSQzbXFikJ5SQO6TULQc=
github.com/mattn/go-runewidth v0.0.16/go.mod h1:Jdepj2loyihRzMpdS35Xk/zdY8IAYHsh153qUoGf23w=
github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 h1:ZK8zHtRHOkbHy6Mmr5D264iyp3TiX5OmNcI5cIARiQI=
github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6/go.mod h1:CJlz5H+gyd6CUWT45Oy4q24RdLyn7Md9Vj2/ldJBSIo=
github.com/muesli/cancelreader v0.2.2 h1:3I4Kt4BQjOR54NavqnDogx/MIoWBFa0StPA8ELUXHmA=
github.com/muesli/cancelreader v0.2.2/go.mod h1:3XuTXfFS2VjM+HTLZY9Ak0l6eUKfijIfMUZ4EgX0QYo=
github.com/muesli/termenv v0.16.0 h1:S5AlUN9dENB57rsbnkPyfdGuWIlkmzJjbFf0Tf5FWUc=
github.com/muesli/termenv v0.16.0/go.mod h1:ZRfOIKPFDYQoDFF4Olj7/QJbW60Ol/kL1pU3VfY/Cnk=
github.com/pelletier/go-toml/v2 v2.2.3 h1:YmeHyLY8mFWbdkNWwpr+qIL2bEqT0o95WSdkNHvL12M=
github.com/pelletier/go-toml/v2 v2.2.3/go.mod h1:MfCQTFTvCcUyyvvwm1+G6H/jORL20Xlb6rzQu9GuUkc=
github.com/pmezard/go-difflib v1.0.0 h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=
github.com/pmezard/go-difflib v1.0.0/go.mod h1:iKH77koFhYxTK1pcRnkKkqfTogsbg7gZNVY4sRDYZ/4=
github.com/rivo/uniseg v0.2.0/go.mod h1:J6wj4VEh+S6ZtnVlnTBMWIodfgj8LQOQFoIToxlJtxc=
github.com/rivo/uniseg v0.4.7 h1:WUdvkW8uEhrYfLC4ZzdpI2ztxP1I582+49Oc5Mq64VQ=
github.com/rivo/uniseg v0.4.7/go.mod h1:FN3SvrM+Zdj16jyLfmOkMNblXMcoc8DfTHruCPUcx88=
github.com/rogpeppe/go-internal v1.9.0 h1:73kH8U+JUqXU8lRuOHeVHaa/SZPifC7BkcraZVejAe8=
github.com/rogpeppe/go-internal v1.9.0/go.mod h1:WtVeX8xhTBvf0smdhujwtBcq4Qrzq/fJaraNFVN+nFs=
github.com/russross/blackfriday/v2 v2.1.0/go.mod h1:+Rmxgy9KzJVeS9/2gXHxylqXiyQDYRxCVz55jmeOWTM=
github.com/sagikazarmark/locafero v0.7.0 h1:5MqpDsTGNDhY8sGp0Aowyf0qKsPrhewaLSsFaodPcyo=
github.com/sagikazarmark/locafero v0.7.0/go.mod h1:2za3Cg5rMaTMoG/2Ulr9AwtFaIppKXTRYnozin4aB5k=
github.com/sahilm/fuzzy v0.1.1 h1:ceu5RHF8DGgoi+/dR5PsECjCDH1BE3Fnmpo7aVXOdRA=
github.com/sahilm/fuzzy v0.1.1/go.mod h1:VFvziUEIMCrT6A6tw2RFIXPXXmzXbOsSHF0DOI8ZK9Y=
github.com/sourcegraph/conc v0.3.0 h1:OQTbbt6P72L20UqAkXXuLOj79LfEanQ+YQFNpLA9ySo=
github.com/sourcegraph/conc v0.3.0/go.mod h1:Sdozi7LEKbFPqYX2/J+iBAM6HpqSLTASQIKqDmF7Mt0=
github.com/spf13/afero v1.12.0 h1:UcOPyRBYczmFn6yvphxkn9ZEOY65cpwGKb5mL36mrqs=
github.com/spf13/afero v1.12.0/go.mod h1:ZTlWwG4/ahT8W7T0WQ5uYmjI9duaLQGy3Q2OAl4sk/4=
github.com/spf13/cast v1.7.1 h1:cuNEagBQEHWN1FnbGEjCXL2szYEXqfJPbP2HNUaca9Y=
github.com/spf13/cast v1.7.1/go.mod h1:ancEpBxwJDODSW/UG4rDrAqiKolqNNh2DX3mk86cAdo=
github.com/spf13/cobra v1.9.1 h1:CXSaggrXdbHK9CF+8ywj8Amf7PBRmPCOJugH954Nnlo=
github.com/spf13/cobra v1.9.1/go.mod h1:nDyEzZ8ogv936Cinf6g1RU9MRY64Ir93oCnqb9wxYW0=
github.com/spf13/pflag v1.0.6 h1:jFzHGLGAlb3ruxLB8MhbI6A8+AQX/2eW4qeyNZXNp2o=
github.com/spf13/pflag v1.0.6/go.mod h1:McXfInJRrz4CZXVZOBLb0bTZqETkiAhM9Iw0y3An2Bg=
github.com/spf13/viper v1.20.1 h1:ZMi+z/lvLyPSCoNtFCpqjy0S4kPbirhpTMwl8BkW9X4=
github.com/spf13/viper v1.20.1/go.mod h1:P9Mdzt1zoHIG8m2eZQinpiBjo6kCmZSKBClNNqjJvu4=
github.com/stretchr/objx v0.1.0/go.mod h1:HFkY916IF+rwdDfMAkV7OtwuqBVzrE8GR6GFx+wExME=
github.com/stretchr/testify v1.3.0/go.mod h1:M5WIy9Dh21IEIfnGCwXGc5bZfKNJtfHm1UVUgZn+9EI=
github.com/stretchr/testify v1.10.0 h1:Xv5erBjTwe/5IxqUQTdXv5kgmIvbHo3QQyRwhJsOfJA=
github.com/stretchr/testify v1.10.0/go.mod h1:r2ic/lqez/lEtzL7wO/rwa5dbSLXVDPFyf8C91i36aY=
github.com/subosito/gotenv v1.6.0 h1:9NlTDc1FTs4qu0DDq7AEtTPNw6SVm7uBMsUCUjABIf8=
github.com/subosito/gotenv v1.6.0/go.mod h1:Dk4QP5c2W3ibzajGcXpNraDfq2IrhjMIvMSWPKKo0FU=
github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e h1:JVG44RsyaB9T2KIHavMF/ppJZNG9ZpyihvCd0w101no=
github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e/go.mod h1:RbqR21r5mrJuqunuUZ/Dhy/avygyECGrLceyNeo4LiM=
go.uber.org/atomic v1.9.0 h1:ECmE8Bn/WFTYwEW/bpKD3M8VtR/zQVbavAoalC1PYyE=
go.uber.org/atomic v1.9.0/go.mod h1:fEN4uk6kAWBTFdckzkM89CLk9XfWZrxpCo0nPH17wJc=
go.uber.org/multierr v1.9.0 h1:7fIwc/ZtS0q++VgcfqFDxSBZVv/Xo49/SYnDFupUwlI=
go.uber.org/multierr v1.9.0/go.mod h1:X2jQV1h+kxSjClGpnseKVIxpmcjrj7MNnI0bnlfKTVQ=
golang.org/x/crypto v0.32.0 h1:euUpcYgM8WcP71gNpTqQCn6rC2t6ULUPiOzfWaXVVfc=
golang.org/x/crypto v0.32.0/go.mod h1:ZnnJkOaASj8g0AjIduWNlq2NRxL0PlBrbKVyZ6V/Ugc=
golang.org/x/exp v0.0.0-20220909182711-5c715a9e8561 h1:MDc5xs78ZrZr3HMQugiXOAkSZtfTpbJLDr/lwfgO53E=
golang.org/x/exp v0.0.0-20220909182711-5c715a9e8561/go.mod h1:cyybsKvd6eL0RnXn6p/Grxp8F5bW7iYuBgsNCOHpMYE=
golang.org/x/sync v0.13.0 h1:AauUjRAJ9OSnvULf/ARrrVywoJDy0YS2AwQ98I37610=
golang.org/x/sync v0.13.0/go.mod h1:1dzgHSNfp02xaA81J2MS99Qcpr2w7fw1gpm99rleRqA=
golang.org/x/sys v0.0.0-20210809222454-d867a43fc93e/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
golang.org/x/sys v0.6.0/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
golang.org/x/sys v0.32.0 h1:s77OFDvIQeibCmezSnk/q6iAfkdiQaJi4VzroCFrN20=
golang.org/x/sys v0.32.0/go.mod h1:BJP2sWEmIv4KK5OTEluFJCKSidICx8ciO85XgH3Ak8k=
golang.org/x/term v0.28.0 h1:/Ts8HFuMR2E6IP/jlo7QVLZHggjKQbhu/7H0LJFr3Gg=
golang.org/x/term v0.28.0/go.mod h1:Sw/lC2IAUZ92udQNf3WodGtn4k/XoLyZoh8v/8uiwek=
golang.org/x/text v0.21.0 h1:zyQAAkrwaneQ066sspRyJaG9VNi/YJ1NfzcGB3hZ/qo=
golang.org/x/text v0.21.0/go.mod h1:4IBbMaMmOPCJ8SecivzSH54+73PCFmPWxNTLm+vZkEQ=
gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405/go.mod h1:Co6ibVJAznAaIkqp8huTwlJQCZ016jof/cbN4VW5Yz0=
gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 h1:YR8cESwS4TdDjEe65xsg0ogRM/Nc3DYOhEAlW+xobZo=
gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15/go.mod h1:Co6ibVJAznAaIkqp8huTwlJQCZ016jof/cbN4VW5Yz0=
gopkg.in/yaml.v3 v3.0.1 h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=
gopkg.in/yaml.v3 v3.0.1/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=

```