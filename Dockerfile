FROM golang:1.24 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y git

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o gamelaunch ./cmd/gamelaunch

# Final stage
FROM debian:sid-slim

# Install NetHack and other dependencies
RUN apt-get update && apt-get install -y \
    ncurses-bin \
    nethack-console \
    moria \
    tome \
    angband \
    zangband \
    omega-rpg \
    crawl \
    cataclysm-dda-curses \
    hearse \
    openssh-client \
    ca-certificates \
    netcat-openbsd \
    && groupadd -g 1001 gamelaunch \
    && useradd -m -u 1001 -g gamelaunch gamelaunch \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /app/config /app/keys /var/games/nethack \
    && chown -R gamelaunch:gamelaunch /app /var/games/nethack

# Copy the binary from builder
COPY --from=builder /app/gamelaunch /app/gamelaunch

# Copy configuration files
COPY --chown=gamelaunch:gamelaunch docker/config.yaml /app/config/
COPY --chown=gamelaunch:gamelaunch docker/entrypoint.sh /app/
COPY --chown=gamelaunch:gamelaunch docker/.bashrc /home/gamelaunch/.bashrc

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

# Switch to non-root user
USER gamelaunch

# Set working directory
WORKDIR /app

# Expose SSH port
EXPOSE 2022

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD nc -z localhost 2022 || exit 1

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]