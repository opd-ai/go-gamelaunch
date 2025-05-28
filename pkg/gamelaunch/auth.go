package gamelaunch

import (
	"github.com/gliderlabs/ssh"
)

// passwordHandler handles password authentication
func (l *Launcher) passwordHandler(ctx ssh.Context, password string) bool {
	users := l.config.GetStringMapString("auth.users")

	if users == nil {
		// No users configured, deny all
		return false
	}

	user := ctx.User()
	expectedPassword, exists := users[user]

	return exists && password == expectedPassword
}
