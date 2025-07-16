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
		v.SetDefault("auth.allow_registration", false)

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
