# schat - SSH Chat Application

A feature-rich SSH-based chat application written in Go with support for user registration, admin roles, real-time messaging, and PostgreSQL database integration.

## Features

- **Seamless SSH Connection Handling**: Connect via SSH with password or key-based authentication
- **User Registration**: Easy registration process via SSH - no reconnection needed after registration
- **Admin Roles**: Elevated privileges for administrators (first user is auto-admin)
- **Admin Management**: Promote/demote users and manage the admin team
- **Tab Completion**: Smart autocomplete for commands, usernames (with @ prefix), and room names
- **Real-time Chat**: Instant messaging with other users
- **Chat History**: See last 10 messages when connecting to chat
- **Room Support**: Create and join multiple chat rooms
- **Private Messages**: Direct messaging between users (can send to offline users)
- **Mentions**: @mention users and get notifications (can mention offline users)
- **Offline Notifications**: Get notified about missed mentions and private messages
- **Admin Mentions**: @admin mentions all administrators
- **User Profiles**: Nicknames and status messages
- **Moderation Tools**: Ban, kick, and mute users with duration control
- **User Management**: Admins can delete users
- **User Reports**: Report users to admins with /report command
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
- `/report @username <reason>` - Report a user to admins

### Admin Commands

- `/ban @username <duration> [reason]` - Ban a user
- `/kick @username <duration> [reason]` - Kick a user
- `/mute @username <duration> [reason]` - Mute a user
- `/unban @username` - Unban a user
- `/unmute @username` - Unmute a user
- `/promote @username` - Promote a user to admin
- `/demote @username` - Remove admin privileges from a user
- `/deleteuser @username` - Delete a user permanently
- `/admins` - List all admins (available to all users)
- `/reports` - View user reports

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

**Registration (first-time users):**
```bash
# Connect with keyboard-interactive auth for registration
ssh -p 2222 -o PreferredAuthentications=keyboard-interactive newusername@localhost
```

You'll be prompted to choose between password or SSH key authentication. After registration, you are automatically connected to the chat!

**Login (existing users):**
```bash
# Login with password
ssh -p 2222 username@localhost
# You'll be prompted for your password

# Or use sshpass for non-interactive login
sshpass -p 'yourpassword' ssh -p 2222 username@localhost
```

**Note:** After registration, you must reconnect to login with your credentials.

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
- `users` - User accounts and settings
- `rooms` - Chat rooms
- `chat_messages` - Chat message history
- `bans` - User ban records
- `mutes` - User mute records
- `mentions` - User mention tracking
- `audit_logs` - Action logging
- `settings` - Global settings

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
