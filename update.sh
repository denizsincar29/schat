#!/bin/bash
set -e

BOLD="\033[1m"
GREEN="\033[1;32m"
CYAN="\033[1;36m"
RESET="\033[0m"

info()    { echo -e "${CYAN}==>${RESET} ${BOLD}$*${RESET}"; }
success() { echo -e "${GREEN} ✓${RESET}  $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Detect installed binary path from service file
BINARY_PATH=$(grep ExecStart /etc/systemd/system/schat.service 2>/dev/null | awk '{print $2}')
BINARY_PATH="${BINARY_PATH:-/usr/local/bin/schat}"

info "Pulling latest changes..."
git pull

info "Building..."
go build -o /tmp/schat_build .
sudo mv /tmp/schat_build "$BINARY_PATH"
sudo chmod 755 "$BINARY_PATH"
success "Binary updated: $BINARY_PATH"

info "Restarting service..."
sudo systemctl restart schat
sleep 1
sudo systemctl is-active --quiet schat && success "schat restarted successfully" || echo "Check logs: sudo journalctl -u schat -n 30"
