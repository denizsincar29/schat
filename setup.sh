#!/bin/bash
set -e

# ─────────────────────────────────────────────────────────────────────────────
#  schat setup script
#  Sets up PostgreSQL, builds the binary, creates a systemd service.
#  Must be run as a regular user with sudo privileges, from the repo root.
# ─────────────────────────────────────────────────────────────────────────────

BOLD="\033[1m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
CYAN="\033[1;36m"
RESET="\033[0m"

info()    { echo -e "${CYAN}==>${RESET} ${BOLD}$*${RESET}"; }
success() { echo -e "${GREEN} ✓${RESET}  $*"; }
warn()    { echo -e "${YELLOW} !${RESET}  $*"; }
die()     { echo -e "${RED}ERROR:${RESET} $*" >&2; exit 1; }
ask()     { echo -e -n "${BOLD}$*${RESET} "; }

# ── Sanity checks ─────────────────────────────────────────────────────────────

[[ -f "main.go" ]] || die "Run this script from the schat repo root directory."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║        schat  Setup  Script          ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════╝${RESET}"
echo ""

# ── Check dependencies ────────────────────────────────────────────────────────

info "Checking dependencies..."

command -v go       >/dev/null 2>&1 || die "Go is not installed. Install it from https://go.dev/dl/"
command -v psql     >/dev/null 2>&1 || die "psql not found. Install PostgreSQL: sudo apt install postgresql"
command -v sudo     >/dev/null 2>&1 || die "sudo is not available."
command -v systemctl>/dev/null 2>&1 || die "systemd is not available on this system."

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
success "Go $GO_VERSION found"
success "PostgreSQL found"

# ── Interactive config ─────────────────────────────────────────────────────────

echo ""
info "Configuration"
echo ""

# DB settings
ask "Database user [schat]:"
read DB_USER
DB_USER="${DB_USER:-schat}"

ask "Database name [schat]:"
read DB_NAME
DB_NAME="${DB_NAME:-schat}"

ask "Database password (leave blank to generate one):"
read -s DB_PASSWORD
echo ""
if [[ -z "$DB_PASSWORD" ]]; then
    DB_PASSWORD=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)
    warn "Generated password: ${BOLD}$DB_PASSWORD${RESET}"
    warn "Save this somewhere safe — it won't be shown again."
fi

ask "Database host [localhost]:"
read DB_HOST
DB_HOST="${DB_HOST:-localhost}"

ask "Database port [5432]:"
read DB_PORT
DB_PORT="${DB_PORT:-5432}"

echo ""
ask "SSH port [2222]:"
read SSH_PORT
SSH_PORT="${SSH_PORT:-2222}"

# Host key path
SSH_HOST_KEY_DEFAULT="/etc/schat/ssh_host_key"
ask "SSH host key path [$SSH_HOST_KEY_DEFAULT]:"
read SSH_HOST_KEY
SSH_HOST_KEY="${SSH_HOST_KEY:-$SSH_HOST_KEY_DEFAULT}"

# Binary install path
BINARY_DEFAULT="/usr/local/bin/schat"
ask "Install binary to [$BINARY_DEFAULT]:"
read BINARY_PATH
BINARY_PATH="${BINARY_PATH:-$BINARY_DEFAULT}"

# Systemd service user
CURRENT_USER="$(whoami)"
ask "Run service as user [$CURRENT_USER]:"
read SERVICE_USER
SERVICE_USER="${SERVICE_USER:-$CURRENT_USER}"

echo ""

# ── PostgreSQL setup ──────────────────────────────────────────────────────────

info "Setting up PostgreSQL..."

# Check if PostgreSQL service is running
if ! sudo systemctl is-active --quiet postgresql; then
    info "Starting PostgreSQL service..."
    sudo systemctl start postgresql
    sudo systemctl enable postgresql
    success "PostgreSQL started and enabled"
fi

# Create role if it doesn't exist
if sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" | grep -q 1; then
    warn "PostgreSQL role '$DB_USER' already exists, updating password..."
    sudo -u postgres psql -c "ALTER USER $DB_USER WITH PASSWORD '$DB_PASSWORD';" > /dev/null
else
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';" > /dev/null
    success "Created PostgreSQL role '$DB_USER'"
fi

# Create database if it doesn't exist
if sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" | grep -q 1; then
    warn "Database '$DB_NAME' already exists, skipping creation."
else
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" > /dev/null
    success "Created database '$DB_NAME'"
fi

# Grant privileges
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;" > /dev/null
success "Granted privileges on '$DB_NAME' to '$DB_USER'"

# ── Build binary ──────────────────────────────────────────────────────────────

info "Building schat..."
cd "$SCRIPT_DIR"
go build -o /tmp/schat_build . || die "Build failed."
sudo mv /tmp/schat_build "$BINARY_PATH"
sudo chmod 755 "$BINARY_PATH"
success "Binary installed to $BINARY_PATH"

# ── Host key directory ────────────────────────────────────────────────────────

SSH_HOST_KEY_DIR="$(dirname "$SSH_HOST_KEY")"
if [[ "$SSH_HOST_KEY_DIR" != "." && ! -d "$SSH_HOST_KEY_DIR" ]]; then
    sudo mkdir -p "$SSH_HOST_KEY_DIR"
    sudo chown "$SERVICE_USER:$(id -gn $SERVICE_USER 2>/dev/null || echo $SERVICE_USER)" "$SSH_HOST_KEY_DIR"
    success "Created host key directory: $SSH_HOST_KEY_DIR"
fi

# ── Write .env file ───────────────────────────────────────────────────────────

info "Writing .env file..."
cat > "$SCRIPT_DIR/.env" << EOF
# Database
DB_HOST=$DB_HOST
DB_PORT=$DB_PORT
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
DB_NAME=$DB_NAME
DB_SSLMODE=disable

# SSH server
SSH_PORT=$SSH_PORT
SSH_HOST_KEY=$SSH_HOST_KEY
EOF
chmod 600 "$SCRIPT_DIR/.env"
success ".env written to $SCRIPT_DIR/.env"

# ── Systemd service ───────────────────────────────────────────────────────────

info "Creating systemd service..."

SERVICE_FILE="/etc/systemd/system/schat.service"

sudo tee "$SERVICE_FILE" > /dev/null << EOF
[Unit]
Description=schat SSH chat server
Documentation=https://github.com/denizsincar29/schat
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$SCRIPT_DIR
ExecStart=$BINARY_PATH
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=schat

Environment=DB_HOST=$DB_HOST
Environment=DB_PORT=$DB_PORT
Environment=DB_USER=$DB_USER
Environment=DB_PASSWORD=$DB_PASSWORD
Environment=DB_NAME=$DB_NAME
Environment=DB_SSLMODE=disable
Environment=SSH_PORT=$SSH_PORT
Environment=SSH_HOST_KEY=$SSH_HOST_KEY

[Install]
WantedBy=multi-user.target
EOF

success "Service file written to $SERVICE_FILE"

sudo systemctl daemon-reload
sudo systemctl enable schat
success "Service enabled (will start on boot)"

# ── Firewall ──────────────────────────────────────────────────────────────────

if command -v ufw >/dev/null 2>&1; then
    if sudo ufw status | grep -q "Status: active"; then
        info "Opening port $SSH_PORT in ufw..."
        sudo ufw allow "$SSH_PORT/tcp" > /dev/null
        success "ufw: allowed port $SSH_PORT/tcp"
    fi
fi

# ── Start service ─────────────────────────────────────────────────────────────

echo ""
info "Starting schat..."
sudo systemctl start schat
sleep 2

if sudo systemctl is-active --quiet schat; then
    success "schat is running!"
else
    warn "schat failed to start. Check logs with: sudo journalctl -u schat -n 50"
fi

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  Setup complete!${RESET}"
echo -e "${GREEN}${BOLD}════════════════════════════════════════${RESET}"
echo ""
echo -e "  SSH into your chat:  ${BOLD}ssh -p $SSH_PORT $(hostname)${RESET}"
echo ""
echo -e "  Service commands:"
echo -e "    ${BOLD}sudo systemctl status schat${RESET}       — check status"
echo -e "    ${BOLD}sudo journalctl -u schat -f${RESET}       — live logs"
echo -e "    ${BOLD}sudo systemctl restart schat${RESET}      — restart"
echo -e "    ${BOLD}sudo systemctl stop schat${RESET}         — stop"
echo ""
echo -e "  To update after a ${BOLD}git pull${RESET}:"
echo -e "    ${BOLD}go build -o $BINARY_PATH . && sudo systemctl restart schat${RESET}"
echo ""
