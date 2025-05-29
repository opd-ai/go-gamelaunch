.PHONY: build run stop clean logs shell test

# Build the Docker image
build:
    docker build -t go-gamelaunch .

# Run with docker-compose
run:
    docker-compose up -d

# Stop the container
stop:
    docker-compose down

# Clean up containers and volumes
clean:
    docker-compose down -v
    docker rmi go-gamelaunch 2>/dev/null || true

# View logs
logs:
    docker-compose logs -f

# Get a shell in the running container
shell:
    docker-compose exec gamelaunch /bin/sh

# Test SSH connection
test:
    @echo "Testing SSH connection..."
    @echo "Try connecting with: ssh demo@localhost -p 2022"
    @echo "Password: demo"

# Quick development setup
dev: build run
    @echo "Development environment started!"
    @echo "Connect with: ssh demo@localhost -p 2022 (password: demo)"
    @make logs

fmt:
	find . -name '*.go' -not -path './vendor/*' -exec gofumpt -extra -s -w {} \;

prompt: fmt
	code2prompt --output prompt.md .