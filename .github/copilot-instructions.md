# Project Overview

go-gamelaunch is a modern dgamelaunch-style SSH server built in Go for hosting terminal-based roguelike games. The project provides a secure, multi-user SSH environment where players can connect and select from available terminal games through an interactive TUI menu. The server handles PTY allocation, window resizing, and full terminal emulation for games like NetHack and Dungeon Crawl Stone Soup.

The target audience includes system administrators deploying game servers, developers building terminal-based multiplayer environments, and roguelike gaming communities seeking reliable hosting solutions. The project emphasizes minimal dependencies, maximum reliability, and beautiful user interfaces using modern Go TUI libraries.

The codebase is structured as both a standalone CLI application and a reusable library, supporting advanced networking scenarios including TLS encryption, Unix sockets, and systemd socket activation for production deployments.

## Technical Stack

- **Primary Language**: Go 1.23.2+ with modern idiomatic patterns
- **SSH Framework**: gliderlabs/ssh v0.3.8 for SSH server implementation
- **TUI Framework**: charmbracelet/bubbletea v1.3.5 for interactive menus
- **PTY Management**: creack/pty v1.1.24 for pseudo-terminal allocation
- **Configuration**: spf13/viper v1.20.1 for YAML-based config management
- **CLI Framework**: spf13/cobra v1.9.1 for command-line interface
- **Testing**: No current test framework (opportunity for improvement)
- **Build/Deploy**: Docker with multi-stage builds, docker-compose orchestration

## Code Assistance Guidelines

1. **SSH Session Management**: Always handle PTY requests properly in session handlers. Check for `isPty` before proceeding with interactive flows. Use `ssh.Session` for I/O operations and maintain proper connection lifecycle management including graceful cleanup.

2. **Error Handling Pattern**: Follow the established pattern of wrapping errors with descriptive context using `fmt.Errorf("operation description: %w", err)`. Always check for nil values before dereferencing pointers, especially for listeners and configuration objects.

3. **Configuration Management**: Use Viper for all configuration needs. Set sensible defaults with `v.SetDefault()` before reading config files. Follow the existing YAML structure with `server`, `auth`, and `games` top-level sections. Support both file-based and programmatic configuration.

4. **Game Process Management**: When launching games, always use `pty.Start()` for proper terminal emulation. Handle window resize events through channels and forward them to child processes. Ensure proper cleanup of PTY resources and process termination.

5. **Functional Options Pattern**: Use functional options (`Option func(*Launcher) error`) for configurable components like custom listeners. This allows library users to extend functionality while maintaining clean APIs and backward compatibility.

6. **TUI Development**: Follow Bubble Tea patterns for interactive components. Implement required methods (`Init`, `Update`, `View`) for all models. Use list.Model for menu systems and handle keyboard navigation properly with proper filtering and selection.

7. **Security Practices**: Implement secure defaults for SSH key handling. Support both password and public key authentication. Always validate user input and sanitize environment variables passed to game processes.

## Project Context

- **Domain**: Terminal-based game hosting and SSH server management. Core concepts include PTY sessions, SSH authentication, game process orchestration, and terminal emulation. Understanding of roguelike gaming conventions and multiplayer hosting requirements.

- **Architecture**: Library-first design with optional CLI wrapper. Clean separation between SSH handling (`auth.go`, `session.go`), game management (`gamelaunch.go`), and user interface (`menu.go`). Support for custom listeners enables advanced deployment scenarios.

- **Key Directories**: 
  - `cmd/gamelaunch/` - CLI application entry point with Cobra commands
  - `pkg/gamelaunch/` - Core library with SSH server, authentication, and game management
  - `docker/` - Containerized deployment with game installations
  - Root level contains configuration examples and deployment scripts

- **Configuration**: YAML-based config with server address, SSH keys, user credentials, and game definitions. Environment variables and command-line arguments supported. Docker volumes for persistent SSH keys and game saves.

## Quality Standards

- **Code Coverage**: Currently no test coverage - priority should be given to adding comprehensive tests using Go's built-in testing package. Target >80% coverage for core library functions, especially authentication and session management.

- **Documentation**: Maintain clear godoc comments for all exported functions and types. Update README examples when adding new features. Include usage examples in function documentation, particularly for the functional options pattern.

- **Code Review**: Follow Go best practices including proper error handling, resource cleanup with defer statements, and idiomatic naming conventions. Use gofumpt for consistent formatting. Ensure all new features support the functional options pattern for library extensibility.

- **Security Review**: All authentication changes require careful review. Validate input sanitization for game commands and arguments. Review SSH key handling and ensure secure defaults. Test TLS configuration and certificate validation.

- **Performance**: SSH sessions should establish quickly (<100ms). Game launches should be responsive. Monitor PTY memory usage for long-running sessions. Use appropriate buffer sizes for terminal I/O operations.
