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