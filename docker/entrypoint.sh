#!/bin/sh

set -e

# Generate SSH host keys if they don't exist
if [ ! -f "/app/keys/host_key_ed25519" ]; then
    echo "Generating SSH host keys..."
    /app/gamelaunch generate-config --generate-keys > /dev/null 2>&1 || true
    
    # Move generated keys to proper location
    if [ -f "./host_key_ed25519" ]; then
        mv ./host_key_ed25519 /app/keys/
        mv ./host_key_ed25519.pub /app/keys/ 2>/dev/null || true
    fi
    
    # If generation failed, create manually
    if [ ! -f "/app/keys/host_key_ed25519" ]; then
        echo "Manual key generation..."
        ssh-keygen -t ed25519 -f /app/keys/host_key_ed25519 -N '' -q
    fi
fi

# Ensure proper permissions on keys
chmod 600 /app/keys/host_key_ed25519
chmod 644 /app/keys/host_key_ed25519.pub 2>/dev/null || true

echo "Starting go-gamelaunch server..."
echo "Connect with: ssh player@localhost -p 2022"
echo "Default credentials:"
echo "  player/gamepass, demo/demo, guest/guest123, nethack/nethack"

# Start the game launcher
exec /app/gamelaunch --config /app/config/config.yaml