package gamelaunch

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// KeygenOptions configures key generation behavior
type KeygenOptions struct {
	// OverwriteExisting determines whether to overwrite existing key files
	OverwriteExisting bool
}

// DefaultKeygenOptions returns the default options for key generation
func DefaultKeygenOptions() KeygenOptions {
	return KeygenOptions{
		OverwriteExisting: false,
	}
}

// GenerateHostKeys generates SSH Ed25519 host keys and writes them to the specified directory
// Returns the paths to the generated key files
func GenerateHostKeys(dir string, options KeygenOptions) ([]string, error) {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	var keyPaths []string

	// Generate ED25519 key
	ed25519KeyPath := filepath.Join(dir, "host_key_ed25519")
	if err := generateED25519Key(ed25519KeyPath, options); err != nil {
		return keyPaths, fmt.Errorf("failed to generate ED25519 key: %w", err)
	}
	keyPaths = append(keyPaths, ed25519KeyPath)

	return keyPaths, nil
}

// generateED25519Key generates an ED25519 private key and writes it to the specified file
func generateED25519Key(filePath string, options KeygenOptions) error {
	// Check if file exists
	if !options.OverwriteExisting {
		if _, err := os.Stat(filePath); err == nil {
			return fmt.Errorf("file already exists: %s", filePath)
		}
	}

	// Generate key
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ED25519 key: %w", err)
	}

	// Encode private key
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("failed to marshal ED25519 private key: %w", err)
	}

	privateKeyPEM := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	// Write private key to file
	keyOut, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key file: %w", err)
	}
	defer keyOut.Close()

	if err := pem.Encode(keyOut, privateKeyPEM); err != nil {
		return fmt.Errorf("failed to write key to file: %w", err)
	}

	// Generate and write public key
	pubKeyPath := filePath + ".pub"
	if err := writeED25519PublicKey(pubKeyPath, pubKey); err != nil {
		return err
	}

	return nil
}

// writeED25519PublicKey writes the ED25519 public key to the specified file in SSH format
func writeED25519PublicKey(filePath string, pubKey ed25519.PublicKey) error {
	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to create public key: %w", err)
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(sshPubKey)

	if err := os.WriteFile(filePath, pubKeyBytes, 0644); err != nil {
		return fmt.Errorf("failed to write public key file: %w", err)
	}

	return nil
}
