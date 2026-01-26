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
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"gorm.io/gorm"
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
		sshKey = strings.Join(keyLines, "\n")

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

		// Clear current room
		user.CurrentRoomID = nil
		database.DB.Save(user)

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
		} else if len(words) > 0 && (words[0] == "/join" || words[0] == "/j") && len(words) <= 2 {
			// Room name completion after /join command
			roomPrefix := strings.ToLower(wordToComplete)
			var rooms []models.Room
			database.DB.Find(&rooms)
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

	cmd := commands.GetCommand(cmdName)
	if cmd == nil {
		fmt.Fprintf(client.Conn, "Unknown command: %s\n", cmdName)
		return
	}

	if cmd.AdminOnly && !client.User.IsAdmin {
		fmt.Fprintf(client.Conn, "This command requires admin privileges\n")
		return
	}

	result, err := cmd.Handler(client.User, args)
	if err != nil {
		fmt.Fprintf(client.Conn, "Error: %v\n", err)
		return
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
			mentionedUsername := strings.TrimPrefix(word, "@")
			
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

	fmt.Fprintf(channel, "--- Last %d messages ---\n", len(messages))
	
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
	fmt.Fprintf(channel, "--- End of history ---\n\n")
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
