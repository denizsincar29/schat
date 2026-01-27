package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/denizsincar29/schat/internal/auth"
	"github.com/denizsincar29/schat/internal/commands"
	"github.com/denizsincar29/schat/internal/database"
	"github.com/denizsincar29/schat/internal/models"
	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"gorm.io/gorm"
)

const (
	// Unicode block characters for QR code rendering
	blockFull   = "█" // Full block (both top and bottom)
	blockTop    = "▀" // Upper half block
	blockBottom = "▄" // Lower half block
	blockEmpty  = " " // Empty space
)

type Client struct {
	User     *models.User
	Conn     ssh.Channel
	Terminal *term.Terminal
	Mutex    sync.Mutex
	LastMsg  time.Time
}

type Server struct {
	clients map[uint]*Client
	mutex   sync.RWMutex
}

var server *Server

func init() {
	server = &Server{
		clients: make(map[uint]*Client),
	}
}

// Run starts the SSH server
func Run() error {
	// Initialize database
	if err := database.Init(); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}

	if err := database.Migrate(); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	// Configure SSH server
	config := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			user, err := auth.AuthenticateUser(conn.User(), string(password), nil)
			if err != nil {
				return nil, fmt.Errorf("authentication failed")
			}
			return &ssh.Permissions{
				Extensions: map[string]string{
					"user_id": fmt.Sprintf("%d", user.ID),
				},
			}, nil
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			user, err := auth.AuthenticateUser(conn.User(), "", key)
			if err != nil {
				return nil, fmt.Errorf("authentication failed")
			}
			return &ssh.Permissions{
				Extensions: map[string]string{
					"user_id": fmt.Sprintf("%d", user.ID),
				},
			}, nil
		},
		// Allow keyboard-interactive for registration prompts
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			// Check if user exists
			var user models.User
			if err := database.DB.Where("username = ?", conn.User()).First(&user).Error; err != nil {
				// User doesn't exist - allow connection for registration
				return &ssh.Permissions{
					Extensions: map[string]string{
						"registration": "true",
					},
				}, nil
			}
			// User exists - they should use password or key auth
			return nil, fmt.Errorf("please use password or SSH key authentication")
		},
	}

	// Load or generate host key
	hostKey, err := loadOrGenerateHostKey()
	if err != nil {
		return fmt.Errorf("failed to load host key: %w", err)
	}
	config.AddHostKey(hostKey)

	// Listen on SSH port
	port := getEnv("SSH_PORT", "2222")
	listener, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer listener.Close()

	log.Printf("SSH server listening on port %s", port)

	// Start background cleanup routine
	go cleanupExpiredBansAndMutes()

	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(conn, config)
	}
}

func handleConnection(netConn net.Conn, config *ssh.ServerConfig) {
	defer netConn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(netConn, config)
	if err != nil {
		log.Printf("Failed to handshake: %v", err)
		return
	}
	defer sshConn.Close()

	// Discard all global requests
	go ssh.DiscardRequests(reqs)

	// Handle channels
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Failed to accept channel: %v", err)
			continue
		}

		go handleSession(channel, requests, sshConn)
	}
}

func handleSession(channel ssh.Channel, requests <-chan *ssh.Request, sshConn *ssh.ServerConn) {
	defer channel.Close()

	// Channel to signal when PTY/shell setup is complete
	setupDone := make(chan bool, 1)

	// Handle session requests
	go func() {
		shellReceived := false
		for req := range requests {
			switch req.Type {
			case "pty-req":
				// Accept PTY request - client will handle terminal modes
				req.Reply(true, nil)
			case "shell":
				shellReceived = true
				req.Reply(true, nil)
				// Signal that setup is complete
				select {
				case setupDone <- true:
				default:
				}
			case "window-change":
				// Accept window size changes
				req.Reply(true, nil)
			default:
				req.Reply(false, nil)
			}
		}
		// Ensure we signal even if shell is never received
		if !shellReceived {
			select {
			case setupDone <- true:
			default:
			}
		}
	}()

	// Wait for setup to complete or timeout
	select {
	case <-setupDone:
		// Setup complete, proceed
	case <-time.After(200 * time.Millisecond):
		// Timeout, proceed anyway
	}

	// Check if user is authenticated
	var user *models.User
	if sshConn.Permissions != nil {
		// Check if this is a registration session
		if sshConn.Permissions.Extensions["registration"] == "true" {
			// Anonymous user - handle registration
			handleRegistration(channel, sshConn.User())
			return
		}

		// Check if user_id is set (authenticated user)
		if sshConn.Permissions.Extensions["user_id"] != "" {
			var userID uint
			n, err := fmt.Sscanf(sshConn.Permissions.Extensions["user_id"], "%d", &userID)
			if err != nil || n != 1 || userID == 0 {
				fmt.Fprintf(channel, "Invalid user ID in session. Please try again.\r\n")
				return
			}
			if err := database.DB.First(&user, userID).Error; err == nil {
				// User is authenticated
				handleAuthenticatedUser(channel, user)
				return
			}
		}
	}

	// If we get here, something went wrong - close the connection
	fmt.Fprintf(channel, "Authentication error. Please try again.\r\n")
}

func handleRegistration(channel ssh.Channel, username string) {
	fmt.Fprintf(channel, "Welcome to schat!\r\n\r\n")

	terminal := term.NewTerminal(channel, "")

	// Get username if not provided
	if username == "" {
		terminal.SetPrompt("Please enter your desired username: ")
		line, err := terminal.ReadLine()
		if err != nil {
			fmt.Fprintf(channel, "\r\nError reading input: %v\r\n", err)
			return
		}
		username = strings.TrimSpace(line)
	}

	if username == "" {
		fmt.Fprintf(channel, "Username cannot be empty\r\n")
		return
	}

	fmt.Fprintf(channel, "Username: %s\r\n", username)
	fmt.Fprintf(channel, "\r\nChoose authentication method:\r\n")
	fmt.Fprintf(channel, "1. Password\r\n")
	fmt.Fprintf(channel, "2. SSH Key\r\n")
	terminal.SetPrompt("Enter choice (1 or 2): ")

	choice, err := terminal.ReadLine()
	if err != nil {
		fmt.Fprintf(channel, "\r\nError reading input: %v\r\n", err)
		return
	}
	choice = strings.TrimSpace(choice)

	var password, sshKey string

	if choice == "1" {
		terminal.SetPrompt("\r\nEnter password (visible): ")
		line, err := terminal.ReadLine()
		if err != nil {
			fmt.Fprintf(channel, "\r\nError reading input: %v\r\n", err)
			return
		}
		password = strings.TrimSpace(line)

		if password == "" {
			fmt.Fprintf(channel, "Password cannot be empty\r\n")
			return
		}
	} else if choice == "2" {
		fmt.Fprintf(channel, "\r\nPaste your SSH public key (end with a line containing only 'END'):\r\n")
		terminal.SetPrompt("")
		var keyLines []string
		for {
			line, err := terminal.ReadLine()
			if err != nil {
				fmt.Fprintf(channel, "\r\nError reading input: %v\r\n", err)
				return
			}
			line = strings.TrimSpace(line)
			if line == "END" {
				break
			}
			if line != "" {
				keyLines = append(keyLines, line)
			}
		}
		// SSH public keys should be on a single line (join wrapped lines with spaces)
		sshKey = strings.Join(keyLines, " ")

		if sshKey == "" {
			fmt.Fprintf(channel, "SSH key cannot be empty\r\n")
			return
		}
	} else {
		fmt.Fprintf(channel, "Invalid choice. Please enter 1 or 2.\r\n")
		return
	}

	// Check if this is the first user
	var userCount int64
	database.DB.Model(&models.User{}).Count(&userCount)
	isFirstUser := userCount == 0

	// Create user - first user is automatically admin
	newUser, err := auth.CreateUser(username, password, sshKey, isFirstUser)
	if err != nil {
		fmt.Fprintf(channel, "\r\nRegistration failed: %v\r\n", err)
		return
	}

	if isFirstUser {
		fmt.Fprintf(channel, "\r\nRegistration successful! You are the first user and have been granted admin privileges.\r\n")
	} else {
		fmt.Fprintf(channel, "\r\nRegistration successful!\r\n")
		// Notify all admins about new user registration
		sendNotificationToAdmins("user_registered", fmt.Sprintf("New user registered: %s", username), &newUser.ID, nil)
	}

	logAction(newUser, "register", "User registered")

	// Immediately authenticate and proceed to chat without reconnection
	fmt.Fprintf(channel, "Connecting to chat...\r\n\r\n")
	handleAuthenticatedUser(channel, newUser)
}

func handleAuthenticatedUser(channel ssh.Channel, user *models.User) {
	// Update last seen
	user.LastSeenAt = time.Now()
	database.DB.Save(user)

	// Start reading input using term.Terminal for proper echo handling
	terminal := term.NewTerminal(channel, "> ")

	// Add client to server
	client := &Client{
		User:     user,
		Conn:     channel,
		Terminal: terminal,
		LastMsg:  time.Now(),
	}
	server.mutex.Lock()
	server.clients[user.ID] = client
	server.mutex.Unlock()

	defer func() {
		server.mutex.Lock()
		delete(server.clients, user.ID)
		server.mutex.Unlock()

		// Update last seen timestamp on disconnect
		user.LastSeenAt = time.Now()

		// Clear current room
		user.CurrentRoomID = nil
		database.DB.Save(user)

		// Cleanup empty rooms
		cleanupEmptyRooms()

		logAction(user, "disconnect", "User disconnected")
	}()

	// Join default room
	var defaultRoom models.Room
	if err := database.DB.Where("name = ?", "general").First(&defaultRoom).Error; err == nil {
		user.CurrentRoomID = &defaultRoom.ID
		database.DB.Save(user)
	}

	// Welcome message
	displayName := user.Username
	if user.Nickname != "" {
		displayName = user.Nickname
	}

	fmt.Fprintf(channel, "\n")
	fmt.Fprintf(channel, "Welcome to schat, %s!\n", displayName)
	if user.IsAdmin {
		fmt.Fprintf(channel, "You are logged in as an admin.\n")
	}
	fmt.Fprintf(channel, "Type /help for available commands.\n")
	fmt.Fprintf(channel, "\n")

	// Create client for offline notifications
	client := &Client{
		User:     user,
		Conn:     channel,
		Terminal: terminal,
	}

	// Deliver offline notifications
	deliverOfflineNotifications(client)

	// Show chat history (last 10 events)
	showChatHistory(channel, user)

	// Check for unread mentions and private messages
	showUnreadNotifications(channel, user)

	// Broadcast join message
	if user.CurrentRoomID != nil {
		broadcastToRoom(*user.CurrentRoomID, fmt.Sprintf("*** %s has joined the chat", displayName), user.ID)
	}

	logAction(user, "connect", "User connected")

	// Setup tab completion
	terminal.AutoCompleteCallback = func(line string, pos int, key rune) (newLine string, newPos int, ok bool) {
		// Only handle tab key
		if key != '\t' {
			return "", 0, false
		}

		// Get the part before cursor
		prefix := line[:pos]
		suffix := line[pos:]

		// Find the word we're completing (last word in prefix)
		words := strings.Fields(prefix)
		if len(words) == 0 && len(prefix) > 0 && prefix[len(prefix)-1] == ' ' {
			// Cursor is after a space, nothing to complete
			return "", 0, false
		}

		var wordToComplete string
		var beforeWord string
		if len(words) > 0 {
			wordToComplete = words[len(words)-1]
			beforeWord = prefix[:len(prefix)-len(wordToComplete)]
		} else {
			wordToComplete = prefix
			beforeWord = ""
		}

		var completions []string

		// Command completion (starts with /)
		if strings.HasPrefix(wordToComplete, "/") {
			cmdPrefix := strings.ToLower(wordToComplete[1:])
			for cmdName := range commands.Commands {
				if strings.HasPrefix(cmdName, cmdPrefix) {
					completions = append(completions, "/"+cmdName)
				}
			}
		} else if strings.HasPrefix(wordToComplete, "@") {
			// Username completion for mentions (starts with @)
			userPrefix := wordToComplete[1:]
			var users []models.User
			// Use database filtering for efficiency
			database.DB.Where("username LIKE ?", userPrefix+"%").Limit(10).Find(&users)
			for _, u := range users {
				completions = append(completions, "@"+u.Username)
			}
		} else if len(words) > 0 && (words[0] == "/join" || words[0] == "/j" || 
			words[0] == "/permanent" || words[0] == "/perm" || words[0] == "/makepermanent" ||
			words[0] == "/hide" || words[0] == "/hideroom" ||
			words[0] == "/unhide" || words[0] == "/unhideroom" || words[0] == "/show") && len(words) <= 2 {
			// Room name completion after room-related commands
			roomPrefix := strings.ToLower(wordToComplete)
			var rooms []models.Room
			
			// Filter hidden rooms for non-admins on /join
			query := database.DB
			if !user.IsAdmin && (words[0] == "/join" || words[0] == "/j") {
				query = query.Where("is_hidden = ?", false)
			}
			
			query.Find(&rooms)
			for _, r := range rooms {
				if strings.HasPrefix(strings.ToLower(r.Name), roomPrefix) {
					completions = append(completions, r.Name)
				}
			}
		} else if len(words) > 0 {
			// Check if command needs username completion
			cmdName := strings.ToLower(words[0])
			if strings.HasPrefix(cmdName, "/") {
				cmdName = cmdName[1:]
			}
			cmd := commands.GetCommand(cmdName)
			if cmd != nil {
				// Commands that take username as argument - require @ prefix
				usernameCommands := map[string]bool{
					"msg": true, "pm": true, "whisper": true, "w": true,
					"ban": true, "b": true, "kick": true, "k": true,
					"mute": true, "silence": true, "unban": true, "ub": true,
					"unmute": true, "um": true, "promote": true, "makeadmin": true,
					"demote": true, "removeadmin": true, "deleteuser": true,
					"deluser": true, "removeuser": true, "report": true, "reportuser": true,
				}
				if usernameCommands[cmdName] {
					// Ensure @ prefix for username completion
					userPrefix := wordToComplete
					if !strings.HasPrefix(userPrefix, "@") {
						return "", 0, false
					}
					userPrefix = userPrefix[1:]

					// Add "admin" as a special completion option
					completions = append(completions, "@admin")

					var users []models.User
					// Use database filtering for efficiency
					database.DB.Where("username LIKE ?", userPrefix+"%").Limit(10).Find(&users)
					for _, u := range users {
						completions = append(completions, "@"+u.Username)
					}
				}
			}
		}

		if len(completions) == 0 {
			return "", 0, false
		}

		// Sort completions for consistent behavior
		sort.Strings(completions)

		// Return first match
		completion := completions[0]
		newLine = beforeWord + completion + suffix
		newPos = len(beforeWord + completion)
		return newLine, newPos, true
	}

	for {
		line, err := terminal.ReadLine()
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from client: %v", err)
			}
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Check if user is muted
		if user.IsMuted && user.MuteExpiresAt != nil && user.MuteExpiresAt.After(time.Now()) {
			if !strings.HasPrefix(line, "/") {
				fmt.Fprintf(channel, "You are muted until %s\n", user.MuteExpiresAt.Format("2006-01-02 15:04:05"))
				continue
			}
		}

		// Handle commands
		if strings.HasPrefix(line, "/") {
			handleCommand(client, line)
		} else {
			handleMessage(client, line)
		}
	}

	// Broadcast leave message
	if user.CurrentRoomID != nil {
		broadcastToRoom(*user.CurrentRoomID, fmt.Sprintf("*** %s has left the chat", displayName), user.ID)
	}
}

func handleCommand(client *Client, line string) {
	parts := strings.Fields(line[1:]) // Remove leading /
	if len(parts) == 0 {
		return
	}

	cmdName := strings.ToLower(parts[0])
	args := parts[1:]

	// Special handling for /addkey command which requires multiline input
	// This bypasses the standard command system because the Command handler
	// signature doesn't support interactive multiline input from the terminal
	if cmdName == "addkey" {
		handleAddKey(client, args)
		return
	}

	// Special handling for /qr command to generate QR codes
	if cmdName == "qr" {
		handleQRCode(client, args)
		return
	}

	cmd := commands.GetCommand(cmdName)
	if cmd == nil {
		fmt.Fprintf(client.Conn, "Unknown command: %s\n", cmdName)
		return
	}

	if cmd.AdminOnly && !client.User.IsAdmin {
		fmt.Fprintf(client.Conn, "This command requires admin privileges\n")
		return
	}

	// Store previous room for movement tracking
	var previousRoomID *uint
	var previousRoom *models.Room
	if cmdName == "join" || cmdName == "j" || cmdName == "room" {
		previousRoomID = client.User.CurrentRoomID
		if previousRoomID != nil {
			database.DB.First(&previousRoom, *previousRoomID)
		}
	}

	result, err := cmd.Handler(client.User, args)
	if err != nil {
		fmt.Fprintf(client.Conn, "Error: %v\n", err)
		return
	}

	// Handle post-command notifications
	if err == nil && result != "" {
		// Reload user to get updated data (e.g., new CurrentRoomID after join)
		database.DB.First(client.User, client.User.ID)

		switch cmdName {
		case "create":
			// Room was created, notify admins
			if len(args) > 0 {
				roomName := args[0]
				var room models.Room
				if err := database.DB.Where("name = ?", roomName).First(&room).Error; err == nil {
					sendNotificationToAdmins("room_created", 
						fmt.Sprintf("Room created: %s by %s", roomName, client.User.Username),
						&client.User.ID, &room.ID)
				}
			}
		case "join", "j", "room":
			// User joined a room
			if client.User.CurrentRoomID != nil && len(args) > 0 {
				var newRoom models.Room
				if err := database.DB.First(&newRoom, *client.User.CurrentRoomID).Error; err == nil {
					// Notify admins if room join notifications are enabled
					// Check setting for admin room join notifications
					var setting models.Settings
					showJoinNotifs := false
					if err := database.DB.Where("key = ?", "admin_room_join_notifications").First(&setting).Error; err == nil {
						showJoinNotifs = setting.Value == "true"
					}
					if showJoinNotifs {
						var fromMsg string
						if previousRoom != nil {
							fromMsg = fmt.Sprintf(" from %s", previousRoom.Name)
						}
						sendNotificationToAdmins("user_joined_room",
							fmt.Sprintf("%s joined room %s%s", client.User.Username, newRoom.Name, fromMsg),
							&client.User.ID, &newRoom.ID)
					}

					// Notify room creator about user movement
					if newRoom.CreatorID != nil && *newRoom.CreatorID != client.User.ID {
						var fromMsg string
						if previousRoom != nil {
							fromMsg = fmt.Sprintf(" from %s", previousRoom.Name)
						}
						sendNotificationToUser(*newRoom.CreatorID, "user_joined_room",
							fmt.Sprintf("%s joined your room %s%s", client.User.Username, newRoom.Name, fromMsg),
							&client.User.ID, &newRoom.ID)
					}

					// Notify previous room creator about user leaving
					if previousRoom != nil && previousRoom.CreatorID != nil && 
						*previousRoom.CreatorID != client.User.ID &&
						(client.User.CurrentRoomID == nil || *previousRoom.ID != *client.User.CurrentRoomID) {
						sendNotificationToUser(*previousRoom.CreatorID, "user_left_room",
							fmt.Sprintf("%s left your room %s and went to %s", 
								client.User.Username, previousRoom.Name, newRoom.Name),
							&client.User.ID, &previousRoom.ID)
					}
				}
			}
		}
	}

	if result != "" {
		// Check if it's an emote
		if strings.HasPrefix(result, "@me ") {
			handleMessage(client, result)
		} else {
			fmt.Fprintf(client.Conn, "%s\n", result)
		}
	}
}

func handleAddKey(client *Client, args []string) {
	// Check if user already has an SSH key
	if client.User.SSHKey != "" {
		fmt.Fprintf(client.Conn, "You already have an SSH key configured. To replace it, contact an admin.\n")
		return
	}

	// Check if user has a password - this ensures they have at least one auth method
	// if SSH key validation fails, preventing lockout
	if client.User.PasswordHash == "" {
		fmt.Fprintf(client.Conn, "Error: Cannot add SSH key without a password set. Please contact an admin.\n")
		return
	}

	// Parse flags - only accept recognized flags
	preservePassword := false
	machineReadable := false
	for _, arg := range args {
		argLower := strings.ToLower(arg)
		if argLower == "preserve-password" || argLower == "pp" || argLower == "keep-password" {
			preservePassword = true
		} else if argLower == "mr" || argLower == "machine-readable" {
			machineReadable = true
		} else {
			fmt.Fprintf(client.Conn, "Unknown flag: %s\n", arg)
			fmt.Fprintf(client.Conn, "Usage: /addkey [pp|preserve-password|keep-password] [mr|machine-readable]\n")
			return
		}
	}

	fmt.Fprintf(client.Conn, "\nPaste your SSH public key below.\n")
	fmt.Fprintf(client.Conn, "End with a line containing only 'END'\n")
	if !preservePassword {
		fmt.Fprintf(client.Conn, "\nNote: Your password will be removed after adding the SSH key.\n")
		fmt.Fprintf(client.Conn, "Use '/addkey pp' to keep your password.\n")
	}
	fmt.Fprintf(client.Conn, "\n")

	// Store original prompt to restore later
	originalPrompt := "> "
	client.Terminal.SetPrompt("")
	var keyLines []string
	for {
		line, err := client.Terminal.ReadLine()
		if err != nil {
			fmt.Fprintf(client.Conn, "\nError reading input: %v\n", err)
			client.Terminal.SetPrompt(originalPrompt)
			return
		}
		line = strings.TrimSpace(line)

		// Check for private key markers - prevent users from pasting private keys
		if isPrivateKeyMarker(line) {
			fmt.Fprintf(client.Conn, "\n⚠️  WARNING: You appear to be pasting a PRIVATE key!\n")
			fmt.Fprintf(client.Conn, "You should NEVER share your private key. Please paste your PUBLIC key instead.\n")
			fmt.Fprintf(client.Conn, "Your public key file typically has a .pub extension (e.g., id_rsa.pub)\n\n")
			client.Terminal.SetPrompt(originalPrompt)
			return
		}

		if line == "END" {
			break
		}
		if line != "" {
			keyLines = append(keyLines, line)
		}
	}

	// SSH public keys should be on a single line (join wrapped lines with spaces)
	sshKey := strings.Join(keyLines, " ")
	if sshKey == "" {
		fmt.Fprintf(client.Conn, "SSH key cannot be empty\n")
		client.Terminal.SetPrompt(originalPrompt)
		return
	}

	// Validate SSH key format
	_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshKey))
	if err != nil {
		fmt.Fprintf(client.Conn, "Invalid SSH key format: %v\n", err)
		client.Terminal.SetPrompt(originalPrompt)
		return
	}

	// Update user with SSH key
	client.User.SSHKey = sshKey

	// Remove password unless preserve flag is set
	if !preservePassword {
		client.User.PasswordHash = ""
	}

	if err := database.DB.Save(client.User).Error; err != nil {
		fmt.Fprintf(client.Conn, "Failed to save SSH key: %v\n", err)
		client.Terminal.SetPrompt(originalPrompt)
		return
	}

	logAction(client.User, "addkey", "Added SSH key to account")

	// Output success message - machine-readable or human-readable
	if machineReadable {
		fmt.Fprintf(client.Conn, "\nSUCCESS: SSH_KEY_ADDED\n")
	} else {
		fmt.Fprintf(client.Conn, "\nSSH key added successfully!\n")
		if preservePassword {
			fmt.Fprintf(client.Conn, "You can now login using either your password or SSH key.\n")
		} else {
			fmt.Fprintf(client.Conn, "Your password has been removed. You can now only login using your SSH key.\n")
		}
	}

	// Restore prompt
	client.Terminal.SetPrompt(originalPrompt)
}

// isPrivateKeyMarker checks if a line contains markers indicating a private key
func isPrivateKeyMarker(line string) bool {
	lineUpper := strings.ToUpper(line)
	// Check for various private key format markers
	privateKeyIndicators := []string{
		"PRIVATE KEY",   // Catches RSA, DSA, EC, OPENSSH PRIVATE KEY, etc.
		"BEGIN PRIVATE", // Additional safety
		"END PRIVATE",   // Additional safety
	}

	for _, indicator := range privateKeyIndicators {
		if strings.Contains(lineUpper, indicator) {
			return true
		}
	}
	return false
}

// handleQRCode generates and sends a QR code to the chat
func handleQRCode(client *Client, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(client.Conn, "Usage: /qr <text or URL>\n")
		return
	}

	// Join all arguments to support URLs and text with spaces
	data := strings.Join(args, " ")

	// Check if user is in a room
	if client.User.CurrentRoomID == nil {
		fmt.Fprintf(client.Conn, "You are not in a room. Use /join <room> to join one.\n")
		return
	}

	// Check if user is muted
	if client.User.IsMuted && client.User.MuteExpiresAt != nil && client.User.MuteExpiresAt.After(time.Now()) {
		fmt.Fprintf(client.Conn, "You are muted until %s\n", client.User.MuteExpiresAt.Format("2006-01-02 15:04:05"))
		return
	}

	// Generate QR code
	qr, err := qrcode.New(data, qrcode.Medium)
	if err != nil {
		fmt.Fprintf(client.Conn, "Error generating QR code: %v\n", err)
		return
	}

	// Convert QR code to string using Unicode blocks
	qrString := qrCodeToUnicode(qr)

	// Get display name
	displayName := client.User.Username
	if client.User.Nickname != "" {
		displayName = client.User.Nickname
	}

	// Save message to database
	// Store in command format to maintain compatibility with Content field
	// and allow potential re-rendering from history in the future
	chatMsg := models.ChatMessage{
		UserID:  client.User.ID,
		RoomID:  client.User.CurrentRoomID,
		Content: fmt.Sprintf("/qr %s", data),
	}
	database.DB.Create(&chatMsg)

	// Create announcement message
	announcement := fmt.Sprintf("%s sent a QR code:", displayName)

	// Broadcast announcement and QR code to room
	fullMessage := announcement + "\n" + qrString
	broadcastToRoom(*client.User.CurrentRoomID, fullMessage, client.User.ID)

	// Show to sender as well
	fmt.Fprintf(client.Conn, "%s\n%s\n", announcement, qrString)

	logAction(client.User, "qr", fmt.Sprintf("Sent QR code in room %d: %s", *client.User.CurrentRoomID, data))
}

// qrCodeToUnicode converts a QR code to Unicode block characters
func qrCodeToUnicode(qr *qrcode.QRCode) string {
	// Get the QR code bitmap
	bitmap := qr.Bitmap()

	var result strings.Builder
	result.WriteString("\n")

	// Process two rows at a time to use half-block characters
	for y := 0; y < len(bitmap); y += 2 {
		for x := 0; x < len(bitmap[y]); x++ {
			topBlack := bitmap[y][x]
			bottomBlack := false
			if y+1 < len(bitmap) {
				bottomBlack = bitmap[y+1][x]
			}

			// Choose the appropriate Unicode block character
			if topBlack && bottomBlack {
				result.WriteString(blockFull)
			} else if topBlack && !bottomBlack {
				result.WriteString(blockTop)
			} else if !topBlack && bottomBlack {
				result.WriteString(blockBottom)
			} else {
				result.WriteString(blockEmpty)
			}
		}
		result.WriteString("\n")
	}
	result.WriteString("\n")

	return result.String()
}

func handleMessage(client *Client, message string) {
	// Check if user is in a room
	if client.User.CurrentRoomID == nil {
		fmt.Fprintf(client.Conn, "You are not in a room. Use /join <room> to join one.\n")
		return
	}

	// Check if user is muted
	if client.User.IsMuted && client.User.MuteExpiresAt != nil && client.User.MuteExpiresAt.After(time.Now()) {
		fmt.Fprintf(client.Conn, "You are muted until %s\n", client.User.MuteExpiresAt.Format("2006-01-02 15:04:05"))
		return
	}

	// Process @me emotes
	displayName := client.User.Username
	if client.User.Nickname != "" {
		displayName = client.User.Nickname
	}

	formattedMsg := message
	if strings.HasPrefix(message, "@me ") {
		// /me style emote
		formattedMsg = fmt.Sprintf("* %s %s", displayName, message[4:])
	} else if strings.Contains(message, "@me") {
		// Inline @me
		formattedMsg = strings.ReplaceAll(message, "@me", displayName)
	} else {
		// Normal message with username prefix
		formattedMsg = fmt.Sprintf("%s: %s", displayName, message)
	}

	// Save message to database
	chatMsg := models.ChatMessage{
		UserID:  client.User.ID,
		RoomID:  client.User.CurrentRoomID,
		Content: message,
	}
	database.DB.Create(&chatMsg)

	// Check for mentions
	words := strings.Fields(message)
	for _, word := range words {
		if strings.HasPrefix(word, "@") && len(word) > 1 {
			// Strip trailing punctuation
			mentionedUsername := strings.TrimPrefix(word, "@")
			mentionedUsername = strings.TrimRight(mentionedUsername, ".,!?;:")

			// Handle @admin - notify all admins
			if mentionedUsername == "admin" {
				var admins []models.User
				database.DB.Where("is_admin = ?", true).Find(&admins)
				for _, admin := range admins {
					if admin.ID == client.User.ID {
						continue // Don't create mention for yourself
					}
					mention := models.Mention{
						UserID:    admin.ID,
						MessageID: chatMsg.ID,
					}
					database.DB.Create(&mention)

					// Send bell notification
					server.mutex.RLock()
					if adminClient, ok := server.clients[admin.ID]; ok {
						adminClient.Terminal.Write([]byte("\a"))
					}
					server.mutex.RUnlock()
				}
				continue
			}

			var mentionedUser models.User
			if err := database.DB.Where("username = ? OR nickname = ?", mentionedUsername, mentionedUsername).
				First(&mentionedUser).Error; err == nil {
				// Create mention
				mention := models.Mention{
					UserID:    mentionedUser.ID,
					MessageID: chatMsg.ID,
				}
				database.DB.Create(&mention)

				// Send bell notification on mention (always)
				server.mutex.RLock()
				if mentionedClient, ok := server.clients[mentionedUser.ID]; ok {
					mentionedClient.Terminal.Write([]byte("\a"))
				}
				server.mutex.RUnlock()
			}
		}
	}

	// Broadcast message to room
	broadcastToRoom(*client.User.CurrentRoomID, formattedMsg, client.User.ID)

	logAction(client.User, "message", fmt.Sprintf("Sent message in room %d", *client.User.CurrentRoomID))
}

func broadcastToRoom(roomID uint, message string, excludeUserID uint) {
	server.mutex.RLock()
	defer server.mutex.RUnlock()

	for userID, client := range server.clients {
		if userID == excludeUserID {
			continue
		}
		if client.User.CurrentRoomID != nil && *client.User.CurrentRoomID == roomID {
			client.Mutex.Lock()
			// Use terminal.Write to properly display messages above the input line
			client.Terminal.Write([]byte(message + "\r\n"))
			// Send bell notification if enabled for all incoming messages
			if client.User.BellEnabled {
				client.Terminal.Write([]byte("\a"))
			}
			client.Mutex.Unlock()
		}
	}
}

// createNotification creates a notification in the database
func createNotification(userID uint, notifType string, message string, relatedUser *uint, relatedRoom *uint) {
	notification := models.Notification{
		UserID:      userID,
		Type:        notifType,
		Message:     message,
		RelatedUser: relatedUser,
		RelatedRoom: relatedRoom,
	}
	if err := database.DB.Create(&notification).Error; err != nil {
		log.Printf("Error creating notification: %v", err)
	}
}

// sendNotificationToAdmins sends a notification to all admins (online and offline)
func sendNotificationToAdmins(notifType string, message string, relatedUser *uint, relatedRoom *uint) {
	// Get all admin users
	var admins []models.User
	if err := database.DB.Where("is_admin = ?", true).Find(&admins).Error; err != nil {
		log.Printf("Error fetching admins for notification: %v", err)
		return
	}

	for _, admin := range admins {
		// Create notification in database
		createNotification(admin.ID, notifType, message, relatedUser, relatedRoom)

		// If admin is online, send immediately
		server.mutex.RLock()
		if client, ok := server.clients[admin.ID]; ok {
			client.Mutex.Lock()
			client.Terminal.Write([]byte(fmt.Sprintf("\r\n[ADMIN] %s\r\n", message)))
			if client.User.BellEnabled {
				client.Terminal.Write([]byte("\a"))
			}
			client.Mutex.Unlock()
		}
		server.mutex.RUnlock()
	}
}

// sendNotificationToUser sends a notification to a specific user (online or offline)
func sendNotificationToUser(userID uint, notifType string, message string, relatedUser *uint, relatedRoom *uint) {
	// Create notification in database
	createNotification(userID, notifType, message, relatedUser, relatedRoom)

	// If user is online, send immediately
	server.mutex.RLock()
	if client, ok := server.clients[userID]; ok {
		client.Mutex.Lock()
		client.Terminal.Write([]byte(fmt.Sprintf("\r\n[Notification] %s\r\n", message)))
		if client.User.BellEnabled {
			client.Terminal.Write([]byte("\a"))
		}
		client.Mutex.Unlock()
	}
	server.mutex.RUnlock()
}

// deliverOfflineNotifications sends unread notifications to a user when they log in
func deliverOfflineNotifications(client *Client) {
	var notifications []models.Notification
	if err := database.DB.Where("user_id = ? AND is_read = ?", client.User.ID, false).
		Order("created_at desc").
		Limit(20). // Limit to last 20 unread notifications
		Find(&notifications).Error; err != nil {
		log.Printf("Error fetching offline notifications: %v", err)
		return
	}

	if len(notifications) == 0 {
		return
	}

	client.Mutex.Lock()
	defer client.Mutex.Unlock()

	client.Terminal.Write([]byte("\r\n=== Notifications ===\r\n"))
	// Reverse order to show oldest first
	for i := len(notifications) - 1; i >= 0; i-- {
		notif := notifications[i]
		client.Terminal.Write([]byte(fmt.Sprintf("  %s\r\n", notif.Message)))
	}
	client.Terminal.Write([]byte(fmt.Sprintf("=== %d unread notification(s) ===\r\n\r\n", len(notifications))))

	// Mark as read
	database.DB.Model(&models.Notification{}).
		Where("user_id = ? AND is_read = ?", client.User.ID, false).
		Update("is_read", true)
}

// cleanupEmptyRooms removes non-permanent rooms that have no users
func cleanupEmptyRooms() {
	// Get all rooms that are not permanent and not the general room
	var rooms []models.Room
	if err := database.DB.Where("is_permanent = ? AND name != ?", false, "general").Find(&rooms).Error; err != nil {
		log.Printf("Error fetching rooms for cleanup: %v", err)
		return
	}

	for _, room := range rooms {
		// Count users in this room
		var userCount int64
		database.DB.Model(&models.User{}).Where("current_room_id = ?", room.ID).Count(&userCount)
		
		if userCount == 0 {
			// No users in this room, delete it
			if err := database.DB.Delete(&room).Error; err != nil {
				log.Printf("Error deleting empty room %s: %v", room.Name, err)
			} else {
				log.Printf("Cleaned up empty room: %s", room.Name)
			}
		}
	}
}

func cleanupExpiredBansAndMutes() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		// Cleanup expired bans
		database.DB.Model(&models.User{}).
			Where("is_banned = ? AND ban_expires_at < ?", true, now).
			Updates(map[string]interface{}{
				"is_banned":      false,
				"ban_expires_at": gorm.Expr("NULL"),
			})

		database.DB.Model(&models.Ban{}).
			Where("is_active = ? AND expires_at < ?", true, now).
			Update("is_active", false)

		// Cleanup expired mutes
		database.DB.Model(&models.User{}).
			Where("is_muted = ? AND mute_expires_at < ?", true, now).
			Updates(map[string]interface{}{
				"is_muted":        false,
				"mute_expires_at": gorm.Expr("NULL"),
			})

		database.DB.Model(&models.Mute{}).
			Where("is_active = ? AND expires_at < ?", true, now).
			Update("is_active", false)
	}
}

func loadOrGenerateHostKey() (ssh.Signer, error) {
	keyPath := getEnv("SSH_HOST_KEY", "./ssh_host_key")

	// Try to load existing key
	if keyData, err := os.ReadFile(keyPath); err == nil {
		return ssh.ParsePrivateKey(keyData)
	}

	// Generate new key
	log.Println("Generating new SSH host key...")
	privateKey, err := generatePrivateKey()
	if err != nil {
		return nil, err
	}

	// Save key
	if err := os.WriteFile(keyPath, privateKey, 0600); err != nil {
		log.Printf("Warning: failed to save host key: %v", err)
	}

	return ssh.ParsePrivateKey(privateKey)
}

func generatePrivateKey() ([]byte, error) {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encode private key to PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	return pem.EncodeToMemory(privateKeyPEM), nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func logAction(user *models.User, action string, details string) {
	log := models.AuditLog{
		UserID:  user.ID,
		Action:  action,
		Details: details,
	}
	database.DB.Create(&log)
}

func showChatHistory(channel ssh.Channel, user *models.User) {
	if user.CurrentRoomID == nil {
		return
	}

	// Get last 10 messages and audit logs (for joins) from the current room
	var messages []models.ChatMessage
	database.DB.Where("room_id = ?", user.CurrentRoomID).
		Preload("User").
		Order("created_at DESC").
		Limit(10).
		Find(&messages)

	if len(messages) == 0 {
		fmt.Fprintf(channel, "--- No recent messages ---\n\n")
		return
	}

	// Reverse to show oldest first
	for i := len(messages) - 1; i >= 0; i-- {
		msg := messages[i]
		displayName := msg.User.Username
		if msg.User.Nickname != "" {
			displayName = msg.User.Nickname
		}

		// Format message
		content := msg.Content
		if strings.HasPrefix(content, "@me ") {
			// Emote
			fmt.Fprintf(channel, "* %s %s\n", displayName, content[4:])
		} else if strings.Contains(content, "@me") {
			// Inline @me
			fmt.Fprintf(channel, "%s\n", strings.ReplaceAll(content, "@me", displayName))
		} else {
			// Normal message
			fmt.Fprintf(channel, "%s: %s\n", displayName, content)
		}
	}
	fmt.Fprintf(channel, "\n")
}

func showUnreadNotifications(channel ssh.Channel, user *models.User) {
	// Check for unread mentions
	var mentionCount int64
	database.DB.Model(&models.Mention{}).Where("user_id = ? AND is_read = ?", user.ID, false).Count(&mentionCount)

	// Check for unread private messages
	var pmCount int64
	database.DB.Model(&models.ChatMessage{}).
		Where("recipient_id = ? AND is_private = ? AND created_at > ?", user.ID, true, user.LastSeenAt).
		Count(&pmCount)

	if mentionCount > 0 || pmCount > 0 {
		fmt.Fprintf(channel, "*** You have unread messages! ***\n")
		if mentionCount > 0 {
			fmt.Fprintf(channel, "  - %d unread mention(s)\n", mentionCount)
		}
		if pmCount > 0 {
			fmt.Fprintf(channel, "  - %d unread private message(s)\n", pmCount)
		}
		fmt.Fprintf(channel, "Type /news to view them.\n\n")
	}

	// Check for unread reports (admin only)
	if user.IsAdmin {
		var reportCount int64
		database.DB.Model(&models.Report{}).Where("is_read = ?", false).Count(&reportCount)
		if reportCount > 0 {
			fmt.Fprintf(channel, "*** You have %d unread report(s) from users. ***\n", reportCount)
			fmt.Fprintf(channel, "Type /reports to view them.\n\n")
		}
	}
}
