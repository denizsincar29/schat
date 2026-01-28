# schat - SSH Chat Application

A feature-rich SSH-based chat application written in Go with support for user registration, admin roles, real-time messaging, and PostgreSQL database integration.

## Features

- **Seamless SSH Connection Handling**: Connect via SSH with password or key-based authentication
- **Guest Access**: Join the chat as a guest without registration (guests room only)
- **User Registration**: Easy registration process via SSH - no reconnection needed after registration
- **Default Rooms**: Each user has a default room they join on login
- **Preserved Rooms**: Special rooms (general, guests, dev) that are always available
- **Admin Roles**: Elevated privileges for administrators (first user is auto-admin)
- **Admin Management**: Promote/demote users and manage the admin team
- **Tab Completion**: Smart autocomplete for commands, usernames (with @ prefix), and room names
- **Real-time Chat**: Instant messaging with other users
- **Chat History**: See last 10 messages when connecting to chat
- **Room Support**: Create and join multiple chat rooms
- **Inactivity Tracking**: Check how long a room has been inactive
- **Private Messages**: Direct messaging between users (can send to offline users)
- **Mentions**: @mention users and get notifications (can mention offline users)
- **Offline Notifications**: Get notified about missed mentions and private messages
- **Admin Mentions**: @admin mentions all administrators
- **User Profiles**: Nicknames and status messages
- **Moderation Tools**: Ban, kick, and mute users with duration control
- **Guest Moderation**: Ban guests by username or fingerprint
- **User Management**: Admins can delete users
- **User Reports**: Report users to admins with /report command
- **Broadcast System**: Admins can schedule broadcast messages with reminders
- **Emotes**: Express yourself with /me commands
- **Audit Logging**: Track all user actions and messages
- **Bell Notifications**: Optional sound notifications for mentions
- **Screenreader Friendly**: Clean text-based UI without ASCII art

## Commands

- `/help` - Show available commands
- `/rooms` - List available rooms
- `/join <room>` - Join a room
- `/create <room> [description]` - Create a new room
- `/msg @username <message>` - Send a private message
- `/nick <nickname>` - Set your nickname
- `/status <message>` - Set your status message
- `/users` - List users in current room
- `/mentions` - View unread mentions
- `/news` - View unread mentions and private messages
- `/bell` - Toggle bell notifications
- `/me <action>` - Send an emote
- `/addkey [pp] [mr]` - Add SSH key (replaces password unless `pp` flag is used; use `mr` for machine-readable output)
- `/qr <text or URL>` - Generate and send a QR code to the chat
- `/report @username <reason>` - Report a user to admins
- `/setdefault [#room_name]` - Set or view your default room
- `/inactive [#room_name]` - Check inactivity time for current or specified room

### Admin Commands

- `/ban @username <duration> [reason]` - Ban a user
- `/kick @username <duration> [reason]` - Kick a user
- `/mute @username <duration> [reason]` - Mute a user
- `/unban @username` - Unban a user
- `/unmute @username` - Unmute a user
- `/banguest <guest_username> <duration> [reason]` - Ban a guest user
- `/unbanguest <guest_username>` - Unban a guest user
- `/promote @username` - Promote a user to admin
- `/demote @username` - Remove admin privileges from a user
- `/deleteuser @username` - Delete a user permanently
- `/admins` - List all admins (available to all users)
- `/reports` - View user reports
- `/markreports` - Mark all reports as read
- `/broadcast` - Schedule a broadcast message with reminders (interactive)
- `/broadcasts` - List scheduled broadcast messages
- `/cancelbroadcast <id>` - Cancel a scheduled broadcast

Duration format: `5m`, `2h`, `1:30` (MM:SS), or `1:30:00` (HH:MM:SS)

## Setup with Docker

### Prerequisites

- Docker
- Docker Compose

### Installation

1. Clone the repository:
```bash
git clone https://github.com/denizsincar29/schat.git
cd schat
```

2. Run the setup script:
```bash
./setup.sh
```

3. Start the application:
```bash
docker compose up -d
```

4. View logs:
```bash
docker compose logs -f
```

### Updating After Git Pull

If you pull new changes from the repository, you need to rebuild the Docker containers:

```bash
# Stop the current containers
docker compose down

# Rebuild the images with new code
docker compose build

# Start the containers again
docker compose up -d
```

**Note:** If you encounter database migration errors, you may need to reset the database:

```bash
# Stop and remove containers and volumes (WARNING: This deletes all data!)
docker compose down -v

# Start fresh
docker compose up -d
```

### Connecting

#### Easy Setup with Helper Script

The `schat-connect.sh` script automates SSH key generation and configuration:

**Interactive Mode (Recommended):**
```bash
# Run without arguments for interactive setup
./schat-connect.sh
```

You'll be prompted for:
- Hostname (default: denizsincar.ru)
- Port (default: 2222)
- Username
- Custom name for SSH config (default: schat-{hostname})

**Command-line Mode:**
```bash
# Generate SSH key, configure SSH client, and connect
./schat-connect.sh username@hostname [port]

# Examples:
./schat-connect.sh myuser@chat.example.com
./schat-connect.sh myuser@localhost 2222
```

The script will:
1. Generate a new SSH key pair in `~/.ssh/`
2. Add two entries to your SSH config:
   - `{custom-name}-setup` for initial password-based connection
   - `{custom-name}` for SSH key-based connection after setup
3. Display your public key to add via `/addkey` command
4. **Automatically add the SSH key** by connecting with password and running `/addkey`
5. Optionally connect you to the chat using your new SSH key

The automated key addition saves you from manually pasting the key!

#### Manual Connection

**Registration (first-time users):**
```bash
# Connect with keyboard-interactive auth for registration
ssh -p 2222 -o PreferredAuthentications=keyboard-interactive newusername@localhost
```

You'll be prompted to choose between password or SSH key authentication, or press Enter to join as a guest. After registration, you are automatically connected to the chat!

**Guest Access:**
```bash
# Connect with keyboard-interactive auth
ssh -p 2222 -o PreferredAuthentications=keyboard-interactive guestname@localhost
```

When prompted for authentication method, simply press Enter to join as a guest. Guest users:
- Can only access the "guests" room
- Cannot join other rooms or send private messages
- Are automatically removed when they disconnect
- Can be banned by admins using `/banguest` command
- Bans are based on username and connection fingerprint

**Login (existing users):**
```bash
# Login with password
ssh -p 2222 username@localhost
# You'll be prompted for your password

# Or use sshpass for non-interactive login
sshpass -p 'yourpassword' ssh -p 2222 username@localhost
```

**Adding SSH key to existing password account:**
1. Login with your password
2. Run `/addkey` (or `/addkey pp` to keep password)
3. Paste your public key (e.g., from `~/.ssh/id_rsa.pub`)
4. Type `END` on a new line
5. Reconnect using your SSH key

## Manual Setup (without Docker)

### Prerequisites

- Go 1.24 or later
- PostgreSQL 12 or later

### Installation

1. Clone the repository:
```bash
git clone https://github.com/denizsincar29/schat.git
cd schat
```

2. Install dependencies:
```bash
go mod download
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Create PostgreSQL database:
```bash
createdb schat
```

5. Build and run:
```bash
go build -o schat .
./schat
```

## Configuration

Configuration is done via environment variables:

- `DB_HOST` - Database host (default: localhost)
- `DB_PORT` - Database port (default: 5432)
- `DB_USER` - Database user (default: postgres)
- `DB_PASSWORD` - Database password (default: postgres)
- `DB_NAME` - Database name (default: schat)
- `DB_SSLMODE` - SSL mode (default: disable)
- `SSH_PORT` - SSH server port (default: 2222)
- `SSH_HOST_KEY` - Path to SSH host key (default: ./ssh_host_key)

## Database Schema

The application uses the following tables:
- `users` - User accounts and settings (includes default room preferences)
- `rooms` - Chat rooms (includes inactivity tracking)
- `chat_messages` - Chat message history
- `bans` - User ban records
- `guest_bans` - Guest user ban records (by fingerprint/username)
- `mutes` - User mute records
- `mentions` - User mention tracking
- `broadcast_messages` - Scheduled broadcast messages
- `audit_logs` - Action logging
- `settings` - Global settings

## Special Rooms

The application creates three preserved rooms by default:
- **general** - The default room for all users
- **guests** - Public room accessible to guest users without registration
- **dev** - Hidden room for development (only visible to admins)

Users can set their preferred default room using the `/setdefault` command.

## Broadcast System

Admins can schedule broadcast messages with multiple reminders using the `/broadcast` command:

1. Enter the base time (event time) in format: YYYY-MM-DD HH:MM
2. Enter the message for the base time
3. Add reminders with minute offsets (negative = before, positive = after)
4. Each reminder gets its own custom message

Broadcasts are automatically sent when:
- The scheduled time arrives
- At least one user is online

Example use case: Announcing a server maintenance at 17:00, with reminders at 15 and 5 minutes before.

## Admin Setup

The first user to register is automatically granted admin privileges. Admins can then promote other users to admin using the `/promote <username>` command.

Alternatively, you can manually update the database after registration:

```sql
UPDATE users SET is_admin = true WHERE username = 'your_username';
```

## Security

- Passwords are hashed using Argon2id
- SSH key authentication supported
- All actions are logged for audit purposes
- Admin-only commands are protected

## Development

### Project Structure

```
schat/
├── main.go                 # Application entry point
├── internal/
│   ├── server/            # SSH server implementation
│   ├── models/            # Database models
│   ├── database/          # Database connection and migrations
│   ├── auth/              # Authentication logic
│   └── commands/          # Command handlers
├── docker-compose.yml     # Docker Compose configuration
├── Dockerfile             # Docker build configuration
└── setup.sh              # Setup script
```

### Building

```bash
go build -o schat .
```

### Testing

Connect to the server:
```bash
ssh -p 2222 localhost
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
