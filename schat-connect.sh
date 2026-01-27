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
if [ -f "$SSH_CONFIG" ] && (grep -q "Host ${HOST_ENTRY}-setup" "$SSH_CONFIG" || grep -q "Host $HOST_ENTRY" "$SSH_CONFIG"); then
    info "SSH config entries already exist for $HOST_ENTRY"
else
    # Add new entry to SSH config
    cat >> "$SSH_CONFIG" << EOF

# schat connection (initial setup - use password first to add key)
Host ${HOST_ENTRY}-setup
    HostName $HOSTNAME
    Port $PORT
    User $USERNAME
    PreferredAuthentications keyboard-interactive,password
    StrictHostKeyChecking accept-new

# schat connection (after key is added - use key auth)
Host $HOST_ENTRY
    HostName $HOSTNAME
    Port $PORT
    User $USERNAME
    IdentityFile $KEY_PATH
    PreferredAuthentications publickey
    StrictHostKeyChecking accept-new

EOF
    success "Added SSH config entries: ${HOST_ENTRY}-setup and $HOST_ENTRY"
fi

# Ensure correct permissions
chmod 600 "$SSH_CONFIG" 2>/dev/null || true

echo ""
info "Setup complete! Your SSH key is ready."
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "NEXT STEPS: Add your key to your schat account"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "STEP 1: Connect with your password using:"
echo "   ssh ${HOST_ENTRY}-setup"
echo ""
echo "   (Or manually: ssh -p $PORT -o PreferredAuthentications=keyboard-interactive,password $USER_HOST)"
echo ""
echo "STEP 2: Once connected, run the /addkey command and paste this public key:"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat "$PUB_KEY_PATH"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "STEP 3: Type 'END' on a new line to finish adding the key"
echo ""
echo "STEP 4: After adding the key, reconnect using:"
echo "   ssh $HOST_ENTRY"
echo ""
echo "   (This will use your SSH key for authentication)"
echo ""

# Ask if user wants to connect now
read -p "Would you like to connect now with password to add the key? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    info "Connecting to schat with password authentication..."
    echo ""
    info "After logging in, run: /addkey"
    echo ""
    ssh "${HOST_ENTRY}-setup"
fi
