# schat - SSH Chat Application

A feature-rich SSH-based chat application written in Go with support for user registration, admin roles, real-time messaging, and PostgreSQL database integration.

## Features

- **Seamless SSH Connection Handling**: Connect via SSH with password or key-based authentication
- **Guest Rooms**: Create temporary guest rooms that allow unauthenticated access with expiration times
- **User Registration**: Easy registration process via SSH - no reconnection needed after registration
- **Default Rooms**: Each user has a default room they join on login
- **Preserved Rooms**: Special rooms (general, dev) that are always available
- **Advanced Room Features**: Create rooms with max participants limit and expiration time
- **Admin Roles**: Elevated privileges for administrators (first user is auto-admin)
- **Admin Management**: Promote/demote users and manage the admin team
- **Smart Notifications**: Admins don't receive notifications about their own actions
- **Tab Completion**: Smart autocomplete for commands, usernames (with @ prefix), and room names
- **Real-time Chat**: Instant messaging with other users (empty messages are prevented)
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
- **Broadcast System**: Admins can schedule broadcast messages with reminders (timezone-aware)
- **Emotes**: Express yourself with /me commands
- **Audit Logging**: Track all user actions and messages
- **Bell Notifications**: Optional sound notifications for mentions
- **Terminal Width Detection**: Proper terminal width detection on connection
- **Screenreader Friendly**: Clean text-based UI without ASCII art

## Commands

- `/help` - Show available commands
- `/rooms` - List available rooms
- `/join <room>` - Join a room
- `/create <room> [--password <password>] [--max-participants <n>] [--expires-in <duration>] [description]` - Create a new room with optional settings
- `/createguestroom <room> --expires-in <duration> [--max-participants <n>] [description]` - Create a guest room (allows unauthenticated access)
- `/msg @username <message>` - Send a private message
- `/nick <nickname>` - Set your nickname
- `/status <message>` - Set your status message
- `/users` - List users in current room
- `/mentions` - View unread mentions (available to guests)
- `/news` - View unread mentions and private messages
- `/bell` - Toggle bell notifications
- `/me <action>` - Send an emote (available to guests)
- `/addkey [pp] [mr]` - Add SSH key (replaces password unless `pp` flag is used; use `mr` for machine-readable output)
- `/qr <text or URL>` - Generate and send a QR code to the chat
- `/report @username <reason>` - Report a user to admins
- `/setdefault [#room_name]` - Set or view your default room
- `/inactive [#room_name]` - Check inactivity time for current or specified room
- `/signup` - Convert guest account to full user account (guests only)

### Admin Commands

- `/ban @username <duration> [reason]` - Ban a user or guest
- `/kick @username <duration> [reason]` - Kick a user
- `/mute @username <duration> [reason]` - Mute a user
- `/unban @username` - Unban a user or guest
- `/unmute @username` - Unmute a user
- `/promote @username` - Promote a user to admin
- `/demote @username` - Remove admin privileges from a user
- `/deleteuser @username` - Delete a user permanently
- `/admins` - List all admins (available to all users)
- `/reports` - View user reports
- `/markreports` - Mark all reports as read
- `/broadcast` - Schedule a broadcast message with reminders (interactive, timezone-aware)
- `/broadcasts` - List scheduled broadcast messages
- `/cancelbroadcast <id>` - Cancel a scheduled broadcast

Duration format: `5m`, `2h`, `1:30` (MM:SS), or `1:30:00` (HH:MM:SS)

**Note**: The `/ban` and `/unban` commands now work for both regular users and guests. Use the guest's nickname to ban them.

## Room Features

### Creating Rooms with Advanced Options

When creating a room, you can specify several optional parameters:

```bash
/create #myroom --password secret123 --max-participants 10 --expires-in 2h This is my room description
```

Options:
- `--password` or `-p`: Set a password for the room (hashed securely)
- `--max-participants` or `--max`: Limit the number of users who can join (e.g., `--max-participants 10`)
- `--expires-in` or `--expires`: Set room expiration time (e.g., `30m`, `2h`, `1h30m`)

Examples:
```bash
# Create a room that expires in 30 minutes
/create #quick-meeting --expires-in 30m Temporary discussion room

# Create a room with max 5 participants
/create #small-group --max-participants 5 Exclusive chat

# Create a password-protected room with expiration
/create #secret-party --password party123 --expires-in 3h VIP access only
```

When a room expires:
- All users in the room are automatically moved to the #general room
- Users receive a notification about the room expiration
- The room is deleted from the system

### Guest Rooms

Guest rooms are temporary rooms that allow unauthenticated access:

**Creating a Guest Room:**
```bash
/createguestroom #party --expires-in 2h Quick chat for the event
```

Requirements:
- Must have an expiration time (at least 2 minutes)
- Can optionally set max participants
- Automatically marked as a guest room

**Joining as a Guest:**
1. Connect via SSH: `ssh -p 2222 username@hostname`
2. When prompted for authentication, enter the guest room name instead of choosing 1 or 2
3. You'll be connected to that guest room without authentication

Guest room expiration:
- Guests receive a warning 2 minutes before the room expires
- When the room expires, all guests are automatically disconnected
- Registered users in the room are moved to #general

### Guest Permissions

Guests have limited but useful permissions:
- Can send messages in their guest room only
- Can use `/help`, `/users`, `/me`, and `/mentions` commands
- Cannot create rooms or send private messages
- Can view and respond to @mentions
- Can convert to a full user account with `/signup`

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

You'll be prompted to choose between password or SSH key authentication, or enter a guest room name to join as a guest. After registration, you are automatically connected to the chat!

**Guest Access:**
```bash
# Connect with keyboard-interactive auth
ssh -p 2222 -o PreferredAuthentications=keyboard-interactive guestname@localhost
```

When prompted for authentication method, enter the name of a guest room (instead of choosing 1 or 2). Guest users:
- Can only access their assigned guest room
- Cannot join other rooms or send private messages
- Are automatically removed when they disconnect
- Are automatically disconnected when the guest room expires
- Receive a 2-minute warning before room expiration
- Can be banned by admins using the `/ban` command (same as regular users)
- Can convert to full user accounts using the `/signup` command

**Note:** A registered user must create a guest room first using `/createguestroom` before guests can join.

To convert a guest account to a full user account, use the `/signup` command while logged in as a guest. You'll be prompted to:
1. Choose a permanent username
2. Select authentication method (password or SSH key)
3. Set up your credentials

After signup, you'll have access to all rooms and features.

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
- `users` - User accounts and settings (includes default room preferences and guest flags)
- `rooms` - Chat rooms (includes inactivity tracking)
- `chat_messages` - Chat message history
- `bans` - User and guest ban records (unified)
- `mutes` - User mute records
- `mentions` - User mention tracking
- `broadcast_messages` - Scheduled broadcast messages
- `audit_logs` - Action logging
- `settings` - Global settings

## Special Rooms

The application creates two preserved rooms by default:
- **general** - The default room for all users
- **dev** - Hidden room for development (only visible to admins)

Registered users can create temporary **guest rooms** using the `/createguestroom` command, which allow unauthenticated access for a limited time.

Users can set their preferred default room using the `/setdefault` command.

## Broadcast System

Admins can schedule broadcast messages with multiple reminders using the `/broadcast` command:

1. Enter the base time (event time) in format: YYYY-MM-DD HH:MM (in server's local timezone)
2. Enter the message for the base time
3. Add reminders with minute offsets (negative = before, positive = after)
4. Each reminder gets its own custom message

**Note:** The broadcast system is now timezone-aware and interprets entered times in the server's local timezone.

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
