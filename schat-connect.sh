#!/bin/bash

# schat-connect.sh - Easy SSH key setup and connection script for schat
# Usage: ./schat-connect.sh [username@hostname] [port]
#        ./schat-connect.sh (interactive mode)

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

# Default values
DEFAULT_HOSTNAME="denizsincar.ru"
DEFAULT_PORT="2222"

# Check if running in interactive mode
if [ $# -eq 0 ]; then
    # Interactive mode
    info "Interactive setup mode"
    echo ""
    
    # Ask for hostname
    read -p "Enter hostname [$DEFAULT_HOSTNAME]: " HOSTNAME
    HOSTNAME="${HOSTNAME:-$DEFAULT_HOSTNAME}"
    
    # Ask for port
    read -p "Enter port [$DEFAULT_PORT]: " PORT
    PORT="${PORT:-$DEFAULT_PORT}"
    
    # Ask for username
    read -p "Enter username: " USERNAME
    if [ -z "$USERNAME" ]; then
        error "Username cannot be empty"
        exit 1
    fi
    
    # Ask for custom name
    read -p "Enter custom name for SSH config [schat-${HOSTNAME}]: " CUSTOM_NAME
    CUSTOM_NAME="${CUSTOM_NAME:-schat-${HOSTNAME}}"
else
    # Command-line argument mode
    USER_HOST="$1"
    PORT="${2:-$DEFAULT_PORT}"
    
    # Extract username and hostname
    if [[ ! "$USER_HOST" =~ ^([^@]+)@(.+)$ ]]; then
        error "Invalid format. Use: username@hostname"
        echo "Or run without arguments for interactive mode"
        exit 1
    fi
    
    USERNAME="${BASH_REMATCH[1]}"
    HOSTNAME="${BASH_REMATCH[2]}"
    CUSTOM_NAME="schat-${HOSTNAME}"
fi

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
HOST_ENTRY="$CUSTOM_NAME"

info "Configuring SSH client..."

# Check if entries already exist
SETUP_EXISTS=false
MAIN_EXISTS=false
if [ -f "$SSH_CONFIG" ]; then
    grep -q "Host ${HOST_ENTRY}-setup" "$SSH_CONFIG" && SETUP_EXISTS=true
    grep -q "Host $HOST_ENTRY\$" "$SSH_CONFIG" && MAIN_EXISTS=true
fi

if [ "$SETUP_EXISTS" = true ] && [ "$MAIN_EXISTS" = true ]; then
    info "SSH config entries already exist for $HOST_ENTRY"
elif [ "$SETUP_EXISTS" = true ] || [ "$MAIN_EXISTS" = true ]; then
    info "WARNING: Incomplete SSH config detected. Removing old entries and recreating..."
    # Remove old entries
    if [ -f "$SSH_CONFIG" ]; then
        # Create a backup
        cp "$SSH_CONFIG" "${SSH_CONFIG}.backup"
        # Remove both entries if they exist
        sed -i "/^# schat connection.*$/,/^$/{ /Host ${HOST_ENTRY}/,/^$/d; }" "$SSH_CONFIG"
        sed -i "/^Host ${HOST_ENTRY}-setup$/,/^$/d" "$SSH_CONFIG"
        sed -i "/^Host ${HOST_ENTRY}$/,/^$/d" "$SSH_CONFIG"
    fi
    # Add new entries
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
    success "Recreated SSH config entries: ${HOST_ENTRY}-setup and $HOST_ENTRY"
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

# Ask if user wants to connect now and add key automatically
read -p "Would you like to automatically add the key now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    info "Connecting to schat and automatically adding key..."
    echo ""
    info "You will be prompted for your password"
    echo ""
    
    # Create a temporary script with proper cleanup trap
    TEMP_SCRIPT=$(mktemp /tmp/schat-addkey-XXXXXX.sh)
    trap "rm -f '$TEMP_SCRIPT'" EXIT INT TERM
    
    cat > "$TEMP_SCRIPT" << 'SCRIPT_EOF'
#!/bin/bash
set -e

# Read public key from stdin
PUBLIC_KEY_CONTENT=$(cat)

# Connect to SSH and send commands
# Using printf to ensure proper line endings
ssh -p "$1" -o PreferredAuthentications=keyboard-interactive,password "$2@$3" << EOF
/addkey
$PUBLIC_KEY_CONTENT
END
EOF
SCRIPT_EOF
    
    chmod +x "$TEMP_SCRIPT"
    
    # Execute the script with parameters
    if cat "$PUB_KEY_PATH" | "$TEMP_SCRIPT" "$PORT" "$USERNAME" "$HOSTNAME"; then
        success "SSH key added successfully!"
        echo ""
        info "You can now connect using: ssh $HOST_ENTRY"
        echo ""
        
        # Ask if user wants to connect now with the key
        read -p "Would you like to connect now using your SSH key? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            info "Connecting with SSH key..."
            ssh "$HOST_ENTRY"
        fi
    else
        error "Failed to add SSH key automatically"
        info "You can add it manually by connecting with: ssh ${HOST_ENTRY}-setup"
        info "Then run: /addkey"
    fi
    
    # Cleanup happens automatically via trap
fi
