FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

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
FROM alpine:edge

RUN mv /etc/profile.d/color_prompt.sh.disabled /etc/profile.d/color_prompt.sh

# Install NetHack and other dependencies
RUN apk update
RUN apk add --no-cache \
    ncurses \
    nethack \
    openssh-client \
    ca-certificates \
    && addgroup -g 1001 gamelaunch \
    && adduser -D -u 1001 -G gamelaunch gamelaunch

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