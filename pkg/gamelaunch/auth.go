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
		// Check if automatic user registration is allowed
		if !l.config.GetBool("auth.allow_registration") {
			log.Printf("Authentication failed for user %s: user does not exist and registration is disabled", user)
			return false
		}

		// Create new account if user doesn't exist and registration is allowed
		users[user] = password
		l.config.Set("auth.users", users)
		// Save config changes
		if err := l.config.WriteConfig(); err != nil {
			log.Printf("Failed to save new user: %v", err)
			return false
		}
		log.Printf("Created new user account: %s", user)
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
		// Check if automatic user registration is allowed
		if !l.config.GetBool("auth.allow_registration") {
			log.Printf("Authentication failed for user %s: user does not exist and registration is disabled", user)
			return false
		}

		// Create new account if user doesn't exist and registration is allowed
		users[user] = string(key.Marshal())
		l.config.Set("auth.users", users)
		// Save config changes
		if err := l.config.WriteConfig(); err != nil {
			log.Printf("Failed to save new user: %v", err)
			return false
		}
		log.Printf("Created new user account: %s", user)
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
		// Check if automatic user registration is allowed
		if !l.config.GetBool("auth.allow_registration") {
			log.Printf("Authentication failed for user %s: user does not exist and registration is disabled", user)
			return false
		}

		// Create new account if user doesn't exist and registration is allowed
		users[user] = password
		l.config.Set("auth.users", users)
		// Save config changes
		if err := l.config.WriteConfig(); err != nil {
			log.Printf("Failed to save new user: %v", err)
			return false
		}
		log.Printf("Created new user account: %s", user)
		return true
	}

	// Check password for existing user
	return password == expectedPassword
}
