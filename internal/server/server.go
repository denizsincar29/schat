package server

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/denizsincar29/schat/internal/auth"
	"github.com/denizsincar29/schat/internal/commands"
	"github.com/denizsincar29/schat/internal/database"
	"github.com/denizsincar29/schat/internal/models"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

type Client struct {
	User    *models.User
	Conn    ssh.Channel
	Mutex   sync.Mutex
	LastMsg time.Time
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
		NoClientAuth: true, // Allow anonymous connections for registration
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

	// Track if PTY was requested
	var ptyRequested bool

	// Handle session requests
	go func() {
		for req := range requests {
			switch req.Type {
			case "pty-req":
				ptyRequested = true
				// Accept PTY request - client will handle terminal modes
				req.Reply(true, nil)
			case "shell":
				req.Reply(true, nil)
			case "window-change":
				// Accept window size changes
				req.Reply(true, nil)
			default:
				req.Reply(false, nil)
			}
		}
	}()

	// Give a moment for PTY request to be processed
	time.Sleep(100 * time.Millisecond)

	// Check if user is authenticated
	var user *models.User
	if sshConn.Permissions != nil && sshConn.Permissions.Extensions["user_id"] != "" {
		var userID uint
		fmt.Sscanf(sshConn.Permissions.Extensions["user_id"], "%d", &userID)
		if err := database.DB.First(&user, userID).Error; err == nil {
			// User is authenticated
			handleAuthenticatedUser(channel, user)
			return
		}
	}

	// Anonymous user - handle registration
	handleRegistration(channel, sshConn.User())
}

func handleRegistration(channel ssh.Channel, username string) {
	fmt.Fprintf(channel, "Welcome to schat!\r\n\r\n")

	reader := bufio.NewReader(channel)

	// Get username if not provided
	if username == "" {
		fmt.Fprintf(channel, "Please enter your desired username: ")
		line, err := readLine(channel, reader)
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
	fmt.Fprintf(channel, "Enter choice (1 or 2): ")

	choice, err := readLine(channel, reader)
	if err != nil {
		fmt.Fprintf(channel, "\r\nError reading input: %v\r\n", err)
		return
	}
	choice = strings.TrimSpace(choice)

	var password, sshKey string

	if choice == "1" {
		fmt.Fprintf(channel, "\r\nEnter password (visible): ")
		line, err := readLine(channel, reader)
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
		var keyLines []string
		for {
			line, err := readLine(channel, reader)
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

	// Create user
	newUser, err := auth.CreateUser(username, password, sshKey, false)
	if err != nil {
		fmt.Fprintf(channel, "\r\nRegistration failed: %v\r\n", err)
		return
	}

	fmt.Fprintf(channel, "\r\nRegistration successful! Please reconnect to login.\r\n")

	logAction(newUser, "register", "User registered")
}

// readLine reads a line from the channel with proper echo support
func readLine(channel ssh.Channel, reader *bufio.Reader) (string, error) {
	var line strings.Builder
	buf := make([]byte, 1)

	for {
		n, err := reader.Read(buf)
		if err != nil {
			if err == io.EOF && line.Len() > 0 {
				return line.String(), nil
			}
			return "", err
		}

		if n > 0 {
			ch := buf[0]
			switch ch {
			case '\r', '\n':
				// Echo newline
				channel.Write([]byte("\r\n"))
				// Skip the following \n if we got \r
				if ch == '\r' {
					// Peek ahead for \n
					peek, _ := reader.Peek(1)
					if len(peek) > 0 && peek[0] == '\n' {
						reader.ReadByte() // consume the \n
					}
				}
				return line.String(), nil
			case 127, 8: // Backspace or Delete
				if line.Len() > 0 {
					// Remove last character
					str := line.String()
					line.Reset()
					line.WriteString(str[:len(str)-1])
					// Echo backspace sequence
					channel.Write([]byte("\b \b"))
				}
			case 3: // Ctrl+C
				return "", fmt.Errorf("interrupted")
			default:
				// Echo the character back
				if ch >= 32 && ch < 127 {
					line.WriteByte(ch)
					channel.Write(buf[:1])
				}
			}
		}
	}
}

func handleAuthenticatedUser(channel ssh.Channel, user *models.User) {
	// Update last seen
	user.LastSeenAt = time.Now()
	database.DB.Save(user)

	// Add client to server
	client := &Client{
		User:    user,
		Conn:    channel,
		LastMsg: time.Now(),
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

	// Broadcast join message
	if user.CurrentRoomID != nil {
		broadcastToRoom(*user.CurrentRoomID, fmt.Sprintf("*** %s has joined the chat", displayName), user.ID)
	}

	logAction(user, "connect", "User connected")

	// Start reading input
	reader := bufio.NewReader(channel)
	for {
		fmt.Fprintf(channel, "> ")
		line, err := reader.ReadString('\n')
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
		formattedMsg = fmt.Sprintf("<%s> %s", displayName, message)
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
			var mentionedUser models.User
			if err := database.DB.Where("username = ? OR nickname = ?", mentionedUsername, mentionedUsername).
				First(&mentionedUser).Error; err == nil {
				// Create mention
				mention := models.Mention{
					UserID:    mentionedUser.ID,
					MessageID: chatMsg.ID,
				}
				database.DB.Create(&mention)

				// Send bell notification if enabled
				server.mutex.RLock()
				if mentionedClient, ok := server.clients[mentionedUser.ID]; ok {
					if mentionedUser.BellEnabled {
						mentionedClient.Conn.Write([]byte("\a"))
					}
				}
				server.mutex.RUnlock()
			}
		}
	}

	// Broadcast message to room
	broadcastToRoom(*client.User.CurrentRoomID, formattedMsg, 0)

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
			fmt.Fprintf(client.Conn, "\n%s\n> ", message)
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
