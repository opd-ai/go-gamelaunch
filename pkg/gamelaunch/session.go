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
