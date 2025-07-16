package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/opd-ai/go-gamelaunch/pkg/gamelaunch"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

				launcher, err = gamelaunch.NewLauncher(configPath, gamelaunch.WithListener(listener))
				if err != nil {
					return fmt.Errorf("failed to create launcher: %w", err)
				}

				log.Printf("Starting game launcher on unix socket: %s", unixSocket)

			case useTLS:
				// Load config to get server address
				v := viper.New()
				v.SetConfigFile(configPath)
				v.SetDefault("server.address", ":2022")

				if err := v.ReadInConfig(); err != nil {
					return fmt.Errorf("failed to read config: %w", err)
				}

				serverAddr := v.GetString("server.address")

				// TLS-wrapped TCP listener
				cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
				if err != nil {
					return fmt.Errorf("failed to load TLS certificates: %w", err)
				}

				tlsConfig := &tls.Config{
					Certificates: []tls.Certificate{cert},
				}

				// Create base TCP listener using configured address
				tcpListener, err := net.Listen("tcp", serverAddr)
				if err != nil {
					return fmt.Errorf("failed to create TCP listener: %w", err)
				}

				// Wrap with TLS
				tlsListener := tls.NewListener(tcpListener, tlsConfig)

				launcher, err = gamelaunch.NewLauncher(configPath, gamelaunch.WithListener(tlsListener))
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
	var generateKeys bool
	var overwriteKeys bool

	cmd := &cobra.Command{
		Use:   "generate-config",
		Short: "Generate a sample configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := generateSampleConfig(); err != nil {
				return err
			}

			if generateKeys {
				fmt.Println("Generating SSH host keys...")
				opts := gamelaunch.DefaultKeygenOptions()
				opts.OverwriteExisting = overwriteKeys

				keyPaths, err := gamelaunch.GenerateHostKeys(".", opts)
				if err != nil {
					return fmt.Errorf("failed to generate host keys: %w", err)
				}
				fmt.Println("Generated host keys:")
				for _, path := range keyPaths {
					fmt.Printf("  - %s\n", path)
				}
			} else {
				fmt.Println("\nNext steps:")
				fmt.Println("1. Generate host keys:")
				fmt.Println("   ssh-keygen -t rsa -f host_key_rsa -N ''")
				fmt.Println("   ssh-keygen -t ed25519 -f host_key_ed25519 -N ''")
			}

			fmt.Println("2. Edit config.yaml to add your games")
			fmt.Println("3. Run: gamelaunch")

			return nil
		},
	}

	cmd.Flags().BoolVar(&generateKeys, "generate-keys", false, "automatically generate SSH host keys")
	cmd.Flags().BoolVar(&overwriteKeys, "overwrite-keys", false, "overwrite existing key files")

	return cmd
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
