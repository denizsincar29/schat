#!/bin/bash

# schat-connect.sh - Easy SSH key setup and connection script for schat
# Usage: ./schat-connect.sh username@hostname [port]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print colored messages
error() { echo -e "${RED}Error: $1${NC}" >&2; }
success() { echo -e "${GREEN}✓ $1${NC}"; }
info() { echo -e "${YELLOW}→ $1${NC}"; }

# Check arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 username@hostname [port]"
    echo ""
    echo "Example: $0 myuser@chat.example.com"
    echo "         $0 myuser@localhost 2222"
    exit 1
fi

# Parse arguments
USER_HOST="$1"
PORT="${2:-2222}"  # Default port is 2222

# Extract username and hostname
if [[ ! "$USER_HOST" =~ ^([^@]+)@(.+)$ ]]; then
    error "Invalid format. Use: username@hostname"
    exit 1
fi

USERNAME="${BASH_REMATCH[1]}"
HOSTNAME="${BASH_REMATCH[2]}"

info "Setting up SSH key for schat connection"
echo "  Username: $USERNAME"
echo "  Hostname: $HOSTNAME"
echo "  Port: $PORT"
echo ""

# Check if SSH is available
if ! command -v ssh &> /dev/null; then
    error "SSH client not found. Please install OpenSSH."
    exit 1
fi

# Create .ssh directory if it doesn't exist
SSH_DIR="$HOME/.ssh"
if [ ! -d "$SSH_DIR" ]; then
    info "Creating $SSH_DIR directory"
    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"
fi

# Define key paths
KEY_PATH="$SSH_DIR/schat_${HOSTNAME}_${USERNAME}"
PUB_KEY_PATH="${KEY_PATH}.pub"

# Check if key already exists
if [ -f "$KEY_PATH" ]; then
    info "SSH key already exists at $KEY_PATH"
    read -p "Do you want to use the existing key? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        info "Please remove the existing key first: rm $KEY_PATH*"
        exit 1
    fi
else
    # Generate new SSH key
    info "Generating new SSH key pair..."
    ssh-keygen -t rsa -b 4096 -f "$KEY_PATH" -N "" -C "schat-${USERNAME}@${HOSTNAME}"
    success "SSH key pair generated"
fi

# Read the public key
if [ ! -f "$PUB_KEY_PATH" ]; then
    error "Public key not found at $PUB_KEY_PATH"
    exit 1
fi

PUBLIC_KEY=$(cat "$PUB_KEY_PATH")
success "Public key ready"

# Add/update SSH config
SSH_CONFIG="$SSH_DIR/config"
HOST_ENTRY="schat-${HOSTNAME}"

info "Configuring SSH client..."

# Check if entry already exists
if [ -f "$SSH_CONFIG" ] && grep -q "Host $HOST_ENTRY" "$SSH_CONFIG"; then
    info "SSH config entry already exists for $HOST_ENTRY"
else
    # Add new entry to SSH config
    cat >> "$SSH_CONFIG" << EOF

# schat connection
Host $HOST_ENTRY
    HostName $HOSTNAME
    Port $PORT
    User $USERNAME
    IdentityFile $KEY_PATH
    PreferredAuthentications publickey,keyboard-interactive
    StrictHostKeyChecking accept-new

EOF
    success "Added SSH config entry: $HOST_ENTRY"
fi

# Ensure correct permissions
chmod 600 "$SSH_CONFIG" 2>/dev/null || true

echo ""
info "Setup complete! Your SSH key is ready."
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "IMPORTANT: You need to add this key to your schat account"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. First, login with your password:"
echo "   ssh -p $PORT $USER_HOST"
echo ""
echo "2. Then run the /addkey command and paste this public key:"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat "$PUB_KEY_PATH"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "3. Type 'END' on a new line to finish"
echo ""
echo "After adding the key, you can connect using:"
echo "   ssh $HOST_ENTRY"
echo ""
echo "Or directly with:"
echo "   ssh -p $PORT -i $KEY_PATH $USER_HOST"
echo ""

# Ask if user wants to connect now
read -p "Would you like to connect now with password authentication? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    info "Connecting to schat..."
    ssh -p "$PORT" -o PreferredAuthentications=keyboard-interactive "$USER_HOST"
fi
