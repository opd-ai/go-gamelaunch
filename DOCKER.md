# Docker Setup for go-gamelaunch

This Docker setup provides a complete go-gamelaunch server with NetHack pre-installed.

## Quick Start

1. **Build and run with docker-compose:**
   ```bash
   docker-compose up -d
   ```

2. **Connect via SSH:**
   ```bash
   ssh demo@localhost -p 2022
   # Password: demo
   ```

## Available Users

- `player` / `gamepass` - Main player account
- `demo` / `demo` - Demo account
- `guest` / `guest123` - Guest account  
- `nethack` / `nethack` - NetHack-specific account

## Manual Docker Commands

```bash
# Build image
docker build -t go-gamelaunch .

# Run container
docker run -d -p 2022:2022 --name gamelaunch go-gamelaunch

# View logs
docker logs -f gamelaunch

# Get shell access
docker exec -it gamelaunch /bin/sh
```

## Volumes

- `gamelaunch_keys`: Persists SSH host keys
- `gamelaunch_saves`: Persists NetHack save files

## Configuration

The default configuration includes:

- **NetHack 3.6.7** with optimized options
- **Shell access** for debugging (optional)
- **Multiple user accounts** with different access levels
- **Persistent save files** and SSH keys

## Customization

### Custom Configuration

Mount your own config file:

```yaml
services:
  gamelaunch:
    # ... other config ...
    volumes:
      - ./my-config.yaml:/app/config/config.yaml:ro
```

### Adding More Games

Edit the configuration to add more terminal games:

```yaml
games:
  crawl:
    name: "Dungeon Crawl Stone Soup"
    command: /usr/games/crawl
    args: []
    env: []
```

### Security

For production use:

1. Change default passwords in `config.yaml`
2. Use strong passwords or SSH keys
3. Consider using a reverse proxy with TLS
4. Limit network access with firewall rules

## Troubleshooting

### Connection Issues

```bash
# Check if container is running
docker ps

# Check logs
docker logs gamelaunch

# Test port connectivity
nc -z localhost 2022
```

### Key Generation Issues

```bash
# Regenerate keys manually
docker exec gamelaunch rm -f /app/keys/host_key_ed25519*
docker restart gamelaunch
```

### NetHack Save Issues

```bash
# Check save directory permissions
docker exec gamelaunch ls -la /var/games/nethack
```