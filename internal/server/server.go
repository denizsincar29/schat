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
	"strconv"
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
	"gorm.io/gorm/clause"
)

const (
	// Unicode block characters for QR code rendering
	blockFull   = "█" // Full block (both top and bottom)
	blockTop    = "▀" // Upper half block
	blockBottom = "▄" // Lower half block
	blockEmpty  = " " // Empty space
)

type Client struct {
	User       *models.User
	Conn       ssh.Channel
	Terminal   *term.Terminal
	Mutex      sync.Mutex
	LastMsg    time.Time
	TermWidth  int // Terminal width in columns
	TermHeight int // Terminal height in rows
}

// sessionContext holds PTY dimensions and client reference for window-change updates
type sessionContext struct {
	width  int
	height int
	client *Client
	mu     sync.Mutex
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

// normalizeNewlines converts all \n to \r\n and ensures we don't double-convert
// existing \r\n sequences. This is necessary for proper terminal display when
// the PTY is in raw mode.
func normalizeNewlines(s string) string {
	// Replace all \r\n with placeholder to avoid double-conversion
	s = strings.ReplaceAll(s, "\r\n", "\x00")
	// Replace all remaining \n with \r\n
	s = strings.ReplaceAll(s, "\n", "\r\n")
	// Restore the placeholder back to \r\n
	s = strings.ReplaceAll(s, "\x00", "\r\n")
	return s
}

// normalizingWriter wraps an io.Writer to automatically convert \n to \r\n
type normalizingWriter struct {
	w io.Writer
}

func (nw *normalizingWriter) Write(p []byte) (n int, err error) {
	normalized := normalizeNewlines(string(p))
	_, err = nw.w.Write([]byte(normalized))
	if err != nil {
		return 0, err
	}
	// Return original length to maintain Write contract
	return len(p), nil
}

// normalizedChannel wraps ssh.Channel to normalize all Write operations
type normalizedChannel struct {
	ssh.Channel
	normalizedWriter io.Writer
}

func (nc *normalizedChannel) Write(data []byte) (n int, err error) {
	return nc.normalizedWriter.Write(data)
}

// wrapChannel wraps an ssh.Channel with automatic newline normalization
func wrapChannel(channel ssh.Channel) ssh.Channel {
	return &normalizedChannel{
		Channel:          channel,
		normalizedWriter: &normalizingWriter{w: channel},
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
	
	// Start room expiration cleanup
	go cleanupExpiredRooms()
	
	// Start broadcast scheduler
	go broadcastScheduler()

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

	// Wrap channel for normalized output (converts \n to \r\n)
	normalizedChan := wrapChannel(channel)

	// Channel to signal when PTY/shell setup is complete
	setupDone := make(chan bool, 1)
	ptyReceived := make(chan bool, 1)
	
	// Session context to track PTY dimensions and client reference
	ctx := &sessionContext{
		width:  0, // Will be set by pty-req
		height: 0, // Will be set by pty-req
	}

	// Handle session requests
	go func() {
		shellReceived := false
		for req := range requests {
			switch req.Type {
			case "pty-req":
				// Parse PTY request to extract terminal dimensions
				if len(req.Payload) >= 8 {
					// PTY request format: string term, uint32 columns, uint32 rows, uint32 width_px, uint32 height_px, string modes
					// Skip the term string length (4 bytes) and the term string itself
					termLen := int(req.Payload[3])
					offset := 4 + termLen
					if len(req.Payload) >= offset+8 {
						ctx.mu.Lock()
						// Parse columns (uint32, big-endian)
						ctx.width = int(uint32(req.Payload[offset])<<24 | 
							uint32(req.Payload[offset+1])<<16 |
							uint32(req.Payload[offset+2])<<8 | 
							uint32(req.Payload[offset+3]))
						// Parse rows (uint32, big-endian)
						ctx.height = int(uint32(req.Payload[offset+4])<<24 | 
							uint32(req.Payload[offset+5])<<16 |
							uint32(req.Payload[offset+6])<<8 | 
							uint32(req.Payload[offset+7]))
						ctx.mu.Unlock()
						
						// Signal that PTY dimensions are set
						select {
						case ptyReceived <- true:
						default:
						}
					}
				}
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
				// Parse window-change request to extract new dimensions
				if len(req.Payload) >= 8 {
					newWidth := int(uint32(req.Payload[0])<<24 | 
						uint32(req.Payload[1])<<16 |
						uint32(req.Payload[2])<<8 | 
						uint32(req.Payload[3]))
					newHeight := int(uint32(req.Payload[4])<<24 | 
						uint32(req.Payload[5])<<16 |
						uint32(req.Payload[6])<<8 | 
						uint32(req.Payload[7]))
					
					ctx.mu.Lock()
					ctx.width = newWidth
					ctx.height = newHeight
					// Update the terminal if client exists
					if ctx.client != nil {
						ctx.client.Mutex.Lock()
						ctx.client.TermWidth = newWidth
						ctx.client.TermHeight = newHeight
						// Update term.Terminal's internal width for proper line wrapping
						ctx.client.Terminal.SetSize(newWidth, newHeight)
						ctx.client.Mutex.Unlock()
					}
					ctx.mu.Unlock()
				}
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

	// Wait for PTY setup to complete first, then shell
	select {
	case <-ptyReceived:
		// PTY received, now wait for shell or timeout
		select {
		case <-setupDone:
			// Setup complete, proceed
		case <-time.After(200 * time.Millisecond):
			// Timeout, proceed anyway
		}
	case <-time.After(500 * time.Millisecond):
		// Timeout waiting for PTY, use defaults
		ctx.mu.Lock()
		if ctx.width == 0 {
			ctx.width = 80
		}
		if ctx.height == 0 {
			ctx.height = 24
		}
		ctx.mu.Unlock()
	}

	// Check if user is authenticated
	var user *models.User
	if sshConn.Permissions != nil {
		// Check if this is a registration session
		if sshConn.Permissions.Extensions["registration"] == "true" {
			// Anonymous user - handle registration
			handleRegistration(normalizedChan, sshConn.User(), ctx)
			return
		}

		// Check if user_id is set (authenticated user)
		if sshConn.Permissions.Extensions["user_id"] != "" {
			var userID uint
			n, err := fmt.Sscanf(sshConn.Permissions.Extensions["user_id"], "%d", &userID)
			if err != nil || n != 1 || userID == 0 {
				fmt.Fprintf(normalizedChan, "Invalid user ID in session. Please try again.\n")
				return
			}
			if err := database.DB.First(&user, userID).Error; err == nil {
				// User is authenticated
				handleAuthenticatedUser(normalizedChan, user, ctx)
				return
			}
		}
	}

	// If we get here, something went wrong - close the connection
	fmt.Fprintf(normalizedChan, "Authentication error. Please try again.\n")
}

func handleRegistration(channel ssh.Channel, username string, ctx *sessionContext) {
	// Channel is already wrapped in handleSession
	fmt.Fprintf(channel, "Welcome to schat!\n\n")

	terminal := term.NewTerminal(channel, "")
	
	// Set terminal size from PTY request
	ctx.mu.Lock()
	terminal.SetSize(ctx.width, ctx.height)
	ctx.mu.Unlock()

	// Get username if not provided
	if username == "" {
		terminal.SetPrompt("Please enter your desired username: ")
		line, err := terminal.ReadLine()
		if err != nil {
			fmt.Fprintf(channel, "\nError reading input: %v\n", err)
			return
		}
		username = strings.TrimSpace(line)
	}

	if username == "" {
		fmt.Fprintf(channel, "Username cannot be empty\n")
		return
	}

	fmt.Fprintf(channel, "Username: %s\n", username)
	fmt.Fprintf(channel, "\nChoose authentication method:\n")
	fmt.Fprintf(channel, "1. Password\n")
	fmt.Fprintf(channel, "2. SSH Key\n")
	fmt.Fprintf(channel, "Press Enter to join as guest (guests room only)\n")
	terminal.SetPrompt("Enter choice (1, 2, or Enter for guest): ")

	choice, err := terminal.ReadLine()
	if err != nil {
		fmt.Fprintf(channel, "\nError reading input: %v\n", err)
		return
	}
	choice = strings.TrimSpace(choice)

	// Guest access - empty choice
	if choice == "" {
		handleGuestUser(channel, username, ctx)
		return
	}

	var password, sshKey string

	if choice == "1" {
		terminal.SetPrompt("\nEnter password (visible): ")
		line, err := terminal.ReadLine()
		if err != nil {
			fmt.Fprintf(channel, "\nError reading input: %v\n", err)
			return
		}
		password = strings.TrimSpace(line)

		if password == "" {
			fmt.Fprintf(channel, "Password cannot be empty\n")
			return
		}
	} else if choice == "2" {
		fmt.Fprintf(channel, "\nPaste your SSH public key (end with a line containing only 'END'):\n")
		terminal.SetPrompt("")
		var keyLines []string
		for {
			line, err := terminal.ReadLine()
			if err != nil {
				fmt.Fprintf(channel, "\nError reading input: %v\n", err)
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
			fmt.Fprintf(channel, "SSH key cannot be empty\n")
			return
		}
	} else {
		fmt.Fprintf(channel, "Invalid choice. Please enter 1, 2, or press Enter for guest access.\n")
		return
	}

	// Check if this is the first user
	var userCount int64
	database.DB.Model(&models.User{}).Where("is_guest = ?", false).Count(&userCount)
	isFirstUser := userCount == 0

	// Create user - first user is automatically admin
	newUser, err := auth.CreateUser(username, password, sshKey, isFirstUser)
	if err != nil {
		fmt.Fprintf(channel, "\nRegistration failed: %v\n", err)
		return
	}

	if isFirstUser {
		fmt.Fprintf(channel, "\nRegistration successful! You are the first user and have been granted admin privileges.\n")
	} else {
		fmt.Fprintf(channel, "\nRegistration successful!\n")
		// Notify all admins about new user registration
		sendNotificationToAdmins("user_registered", fmt.Sprintf("New user registered: %s", username), &newUser.ID, nil)
	}

	logAction(newUser, "register", "User registered")

	// Immediately authenticate and proceed to chat without reconnection
	fmt.Fprintf(channel, "Connecting to chat...\n\n")
	handleAuthenticatedUser(channel, newUser, ctx)
}

// handleGuestUser creates a temporary guest user and joins them to the guests room
func handleGuestUser(channel ssh.Channel, username string, ctx *sessionContext) {
	// Channel is already wrapped in handleRegistration
	
	// Check if there's a banned guest with this nickname
	var bannedGuest models.User
	err := database.DB.Where("nickname = ? AND is_guest = ? AND is_banned = ? AND ban_expires_at > ?",
		username, true, true, time.Now()).First(&bannedGuest).Error
	
	if err == nil {
		// Found a banned guest with this nickname
		fmt.Fprintf(channel, "\nYou are banned from guest access.\n")
		if bannedGuest.BanExpiresAt != nil {
			fmt.Fprintf(channel, "Ban expires: %s\n", bannedGuest.BanExpiresAt.Format("2006-01-02 15:04:05"))
		}
		return
	}

	// Get the guests room
	var guestsRoom models.Room
	if err := database.DB.Where("name = ?", "guests").First(&guestsRoom).Error; err != nil {
		fmt.Fprintf(channel, "\nError: Guests room not found. Please contact an administrator.\n")
		log.Printf("Guests room not found: %v", err)
		return
	}

	// Create a unique guest username with timestamp to avoid collisions
	guestUsername := fmt.Sprintf("guest_%s_%d", username, time.Now().UnixNano())
	
	// Create a temporary guest user
	guestUser := &models.User{
		Username:      guestUsername,
		IsGuest:       true,
		Nickname:      username,
		CurrentRoomID: &guestsRoom.ID,
		DefaultRoomID: &guestsRoom.ID,
		LastSeenAt:    time.Now(),
		BellEnabled:   false,
	}

	// Save guest user to database (temporary)
	if err := database.DB.Create(guestUser).Error; err != nil {
		fmt.Fprintf(channel, "\nError creating guest user: %v\n", err)
		log.Printf("Error creating guest user: %v", err)
		return
	}

	fmt.Fprintf(channel, "\nJoining as guest (guests room only)...\n\n")
	
	// Start guest session
	handleGuestSession(channel, guestUser, ctx)
}

// handleGuestSession handles a guest user session (limited to guests room only)
func handleGuestSession(channel ssh.Channel, user *models.User, ctx *sessionContext) {
	// Channel is already wrapped in handleGuestUser or handleRegistration
	
	// Update last seen
	user.LastSeenAt = time.Now()
	database.DB.Save(user)

	// Start reading input using term.Terminal for proper echo handling
	terminal := term.NewTerminal(channel, "> ")
	
	// Set terminal size from PTY request
	var width, height int
	ctx.mu.Lock()
	width = ctx.width
	height = ctx.height
	ctx.mu.Unlock()
	
	terminal.SetSize(width, height)

	// Add client to server
	client := &Client{
		User:     user,
		Conn:     channel,
		Terminal: terminal,
		LastMsg:  time.Now(),
	}
	
	// Set terminal dimensions on client and update ctx
	ctx.mu.Lock()
	client.TermWidth = width
	client.TermHeight = height
	ctx.client = client
	ctx.mu.Unlock()
	
	server.mutex.Lock()
	server.clients[user.ID] = client
	server.mutex.Unlock()

	defer func() {
		// Broadcast leave message for guests
		displayName := user.Nickname
		if displayName == "" {
			displayName = user.Username
		}
		
		if user.CurrentRoomID != nil {
			var room models.Room
			database.DB.First(&room, user.CurrentRoomID)
			
			// Broadcast to room users
			broadcastToRoom(*user.CurrentRoomID, fmt.Sprintf("*** %s (guest) has left the chat", displayName), user.ID)
			
			// Notify all admins about guest leave (regardless of their current room)
			sendNotificationToAdmins("user_left", 
				fmt.Sprintf("Guest %s left #%s", displayName, room.Name), 
				&user.ID, user.CurrentRoomID)
		}
		
		server.mutex.Lock()
		delete(server.clients, user.ID)
		server.mutex.Unlock()

		// Delete guest user from database
		database.DB.Unscoped().Delete(user)

		logAction(user, "disconnect", "Guest disconnected")
	}()

	// Welcome message for guests
	displayName := user.Nickname
	if displayName == "" {
		displayName = user.Username
	}

	fmt.Fprintf(channel, "\n")
	fmt.Fprintf(channel, "Welcome to the guests room, %s!\n", displayName)
	fmt.Fprintf(channel, "You are logged in as a guest (limited to guests room only).\n")
	fmt.Fprintf(channel, "Type /help for available commands.\n")
	fmt.Fprintf(channel, "\n")

	// Show chat history for guests room
	showChatHistory(channel, user)

	// Broadcast join message
	if user.CurrentRoomID != nil {
		broadcastToRoom(*user.CurrentRoomID, fmt.Sprintf("*** %s (guest) has joined the chat", displayName), user.ID)
		
		// Notify all admins about guest join (regardless of their current room)
		var room models.Room
		if err := database.DB.First(&room, user.CurrentRoomID).Error; err == nil {
			sendNotificationToAdmins("user_joined", 
				fmt.Sprintf("Guest %s joined #%s", displayName, room.Name), 
				&user.ID, user.CurrentRoomID)
		}
	}

	logAction(user, "guest_connect", "Guest connected")

	// Main message loop (same as regular users but restricted)
	for {
		line, err := terminal.ReadLine()
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Handle commands (restricted for guests)
		if strings.HasPrefix(line, "/") {
			handleGuestCommand(client, line)
		} else {
			// Regular message - only in guests room
			handleGuestMessage(client, line)
		}
	}
}

func handleAuthenticatedUser(channel ssh.Channel, user *models.User, ctx *sessionContext) {
	// Channel is already wrapped in handleSession or handleRegistration
	
	// Update last seen
	user.LastSeenAt = time.Now()
	database.DB.Save(user)

	// Start reading input using term.Terminal for proper echo handling
	terminal := term.NewTerminal(channel, "> ")
	
	// Set terminal size from PTY request
	var width, height int
	ctx.mu.Lock()
	width = ctx.width
	height = ctx.height
	ctx.mu.Unlock()
	
	terminal.SetSize(width, height)

	// Add client to server
	client := &Client{
		User:     user,
		Conn:     channel,
		Terminal: terminal,
		LastMsg:  time.Now(),
	}
	
	// Set terminal dimensions on client and update ctx
	ctx.mu.Lock()
	client.TermWidth = width
	client.TermHeight = height
	ctx.client = client
	ctx.mu.Unlock()
	
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

	// Join default room - use user's default room if set, otherwise use general
	var defaultRoom models.Room
	if user.DefaultRoomID != nil {
		// User has a preferred default room
		if err := database.DB.First(&defaultRoom, *user.DefaultRoomID).Error; err == nil {
			user.CurrentRoomID = &defaultRoom.ID
			database.DB.Save(user)
		} else {
			// Default room doesn't exist, fall back to general
			if err := database.DB.Where("name = ?", "general").First(&defaultRoom).Error; err == nil {
				user.CurrentRoomID = &defaultRoom.ID
				database.DB.Save(user)
			}
		}
	} else {
		// No default room set, use general
		if err := database.DB.Where("name = ?", "general").First(&defaultRoom).Error; err == nil {
			user.CurrentRoomID = &defaultRoom.ID
			user.DefaultRoomID = &defaultRoom.ID // Set it as default for next time
			database.DB.Save(user)
		}
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

	// Deliver offline notifications
	deliverOfflineNotifications(client)

	// Show chat history (last 10 events)
	showChatHistory(channel, user)

	// Check for unread mentions and private messages
	showUnreadNotifications(channel, user)

	// Broadcast join message
	if user.CurrentRoomID != nil {
		broadcastToRoom(*user.CurrentRoomID, fmt.Sprintf("*** %s has joined the chat", displayName), user.ID)
		
		// Notify all admins about user join (regardless of their current room)
		var room models.Room
		if err := database.DB.First(&room, user.CurrentRoomID).Error; err == nil {
			sendNotificationToAdmins("user_joined", 
				fmt.Sprintf("%s joined #%s", displayName, room.Name), 
				&user.ID, user.CurrentRoomID)
		}
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
			words[0] == "/unhide" || words[0] == "/unhideroom" || words[0] == "/show" ||
			words[0] == "/move" || words[0] == "/moveuser" ||
			words[0] == "/setpassword" || words[0] == "/roompassword" || words[0] == "/setpass") && len(words) <= 2 {
			// Room name completion after room-related commands
			roomPrefix := strings.ToLower(wordToComplete)
			// Strip # prefix if present for matching
			if strings.HasPrefix(roomPrefix, "#") {
				roomPrefix = roomPrefix[1:]
			}
			var rooms []models.Room
			
			// Filter hidden rooms for non-admins on /join
			query := database.DB
			if !user.IsAdmin && (words[0] == "/join" || words[0] == "/j") {
				query = query.Where("is_hidden = ?", false)
			}
			
			query.Find(&rooms)
			for _, r := range rooms {
				if strings.HasPrefix(strings.ToLower(r.Name), roomPrefix) {
					// Add # prefix to room names in autocomplete
					completions = append(completions, "#"+r.Name)
				}
			}
		} else if len(words) > 0 {
			// Check if we're completing a help topic
			if (words[0] == "/help" || words[0] == "/h") && len(words) <= 2 {
				topicPrefix := strings.ToLower(wordToComplete)
				topics := []string{"rooms", "messaging", "user", "moderation", "admin"}
				for _, topic := range topics {
					if strings.HasPrefix(topic, topicPrefix) {
						completions = append(completions, topic)
					}
				}
				// Also add all command names for help
				for cmdName := range commands.Commands {
					if strings.HasPrefix(cmdName, topicPrefix) {
						completions = append(completions, cmdName)
					}
				}
			} else {
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

						// Add special completion options
						completions = append(completions, "@admin")
						completions = append(completions, "@everyone")
						completions = append(completions, "@me")

						var users []models.User
						// Use database filtering for efficiency
						database.DB.Where("username LIKE ?", userPrefix+"%").Limit(10).Find(&users)
						for _, u := range users {
							completions = append(completions, "@"+u.Username)
						}
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
				fmt.Fprintf(client.Terminal, "You are muted until %s\n", user.MuteExpiresAt.Format("2006-01-02 15:04:05"))
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
		var room models.Room
		database.DB.First(&room, user.CurrentRoomID)
		
		// Broadcast to room users
		broadcastToRoom(*user.CurrentRoomID, fmt.Sprintf("*** %s has left the chat", displayName), user.ID)
		
		// Notify all admins about user leave (regardless of their current room)
		sendNotificationToAdmins("user_left", 
			fmt.Sprintf("%s left #%s", displayName, room.Name), 
			&user.ID, user.CurrentRoomID)
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

	// Special handling for /signup command which requires interactive input
	if cmdName == "signup" || cmdName == "register" {
		if !client.User.IsGuest {
			fmt.Fprintf(client.Terminal, "This command is only available for guest users\n")
			return
		}
		handleSignupInteractive(client)
		return
	}

	// Special handling for /broadcast command which requires interactive input
	if cmdName == "broadcast" || cmdName == "schedulebroadcast" || cmdName == "announce" {
		if !client.User.IsAdmin {
			fmt.Fprintf(client.Terminal, "This command requires admin privileges\n")
			return
		}
		handleBroadcastInteractive(client)
		return
	}

	cmd := commands.GetCommand(cmdName)
	if cmd == nil {
		fmt.Fprintf(client.Terminal, "Unknown command: %s\n", cmdName)
		return
	}

	if cmd.AdminOnly && !client.User.IsAdmin {
		fmt.Fprintf(client.Terminal, "This command requires admin privileges\n")
		return
	}

	// Check if user is asking for help
	if len(args) > 0 && (args[0] == "?" || args[0] == "help" || args[0] == "--help") {
		fmt.Fprintf(client.Terminal, "Command: %s\n", cmd.Name)
		if len(cmd.Aliases) > 0 {
			fmt.Fprintf(client.Terminal, "Aliases: %s\n", strings.Join(cmd.Aliases, ", "))
		}
		fmt.Fprintf(client.Terminal, "Description: %s\n", cmd.Description)
		fmt.Fprintf(client.Terminal, "Usage: %s\n", cmd.Usage)
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
		fmt.Fprintf(client.Terminal, "Error: %v\n", err)
		return
	}

	// Handle post-command notifications
	if result != "" {
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
						(client.User.CurrentRoomID == nil || previousRoom.ID != *client.User.CurrentRoomID) {
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
			fmt.Fprintf(client.Terminal, "%s\n", result)
		}
	}
}

func handleAddKey(client *Client, args []string) {
	// Check if user already has an SSH key
	if client.User.SSHKey != "" {
		fmt.Fprintf(client.Terminal, "You already have an SSH key configured. To replace it, contact an admin.\n")
		return
	}

	// Check if user has a password - this ensures they have at least one auth method
	// if SSH key validation fails, preventing lockout
	if client.User.PasswordHash == "" {
		fmt.Fprintf(client.Terminal, "Error: Cannot add SSH key without a password set. Please contact an admin.\n")
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
			fmt.Fprintf(client.Terminal, "Unknown flag: %s\n", arg)
			fmt.Fprintf(client.Terminal, "Usage: /addkey [pp|preserve-password|keep-password] [mr|machine-readable]\n")
			return
		}
	}

	fmt.Fprintf(client.Terminal, "\nPaste your SSH public key below.\n")
	fmt.Fprintf(client.Terminal, "End with a line containing only 'END'\n")
	if !preservePassword {
		fmt.Fprintf(client.Terminal, "\nNote: Your password will be removed after adding the SSH key.\n")
		fmt.Fprintf(client.Terminal, "Use '/addkey pp' to keep your password.\n")
	}
	fmt.Fprintf(client.Terminal, "\n")

	// Store original prompt to restore later
	originalPrompt := "> "
	client.Terminal.SetPrompt("")
	var keyLines []string
	for {
		line, err := client.Terminal.ReadLine()
		if err != nil {
			fmt.Fprintf(client.Terminal, "\nError reading input: %v\n", err)
			client.Terminal.SetPrompt(originalPrompt)
			return
		}
		line = strings.TrimSpace(line)

		// Check for private key markers - prevent users from pasting private keys
		if isPrivateKeyMarker(line) {
			fmt.Fprintf(client.Terminal, "\n⚠️  WARNING: You appear to be pasting a PRIVATE key!\n")
			fmt.Fprintf(client.Terminal, "You should NEVER share your private key. Please paste your PUBLIC key instead.\n")
			fmt.Fprintf(client.Terminal, "Your public key file typically has a .pub extension (e.g., id_rsa.pub)\n\n")
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
		fmt.Fprintf(client.Terminal, "SSH key cannot be empty\n")
		client.Terminal.SetPrompt(originalPrompt)
		return
	}

	// Validate SSH key format
	_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshKey))
	if err != nil {
		fmt.Fprintf(client.Terminal, "Invalid SSH key format: %v\n", err)
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
		fmt.Fprintf(client.Terminal, "Failed to save SSH key: %v\n", err)
		client.Terminal.SetPrompt(originalPrompt)
		return
	}

	logAction(client.User, "addkey", "Added SSH key to account")

	// Output success message - machine-readable or human-readable
	if machineReadable {
		fmt.Fprintf(client.Terminal, "\nSUCCESS: SSH_KEY_ADDED\n")
	} else {
		fmt.Fprintf(client.Terminal, "\nSSH key added successfully!\n")
		if preservePassword {
			fmt.Fprintf(client.Terminal, "You can now login using either your password or SSH key.\n")
		} else {
			fmt.Fprintf(client.Terminal, "Your password has been removed. You can now only login using your SSH key.\n")
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
		fmt.Fprintf(client.Terminal, "Usage: /qr <text or URL>\n")
		return
	}

	// Join all arguments to support URLs and text with spaces
	data := strings.Join(args, " ")

	// Check if user is in a room
	if client.User.CurrentRoomID == nil {
		fmt.Fprintf(client.Terminal, "You are not in a room. Use /join <room> to join one.\n")
		return
	}

	// Check if user is muted
	if client.User.IsMuted && client.User.MuteExpiresAt != nil && client.User.MuteExpiresAt.After(time.Now()) {
		fmt.Fprintf(client.Terminal, "You are muted until %s\n", client.User.MuteExpiresAt.Format("2006-01-02 15:04:05"))
		return
	}

	// Generate QR code
	qr, err := qrcode.New(data, qrcode.Medium)
	if err != nil {
		fmt.Fprintf(client.Terminal, "Error generating QR code: %v\n", err)
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
	fmt.Fprintf(client.Terminal, "%s\n%s\n", announcement, qrString)

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

// handleBroadcastInteractive handles the interactive broadcast scheduling
func handleBroadcastInteractive(client *Client) {
	fmt.Fprintf(client.Terminal, "\n=== Schedule Broadcast Message ===\n\n")
	
	originalPrompt := "> "
	
	// Get base time
	client.Terminal.SetPrompt("Enter base time (YYYY-MM-DD HH:MM): ")
	baseTimeStr, err := client.Terminal.ReadLine()
	if err != nil {
		fmt.Fprintf(client.Terminal, "\nError reading input: %v\n", err)
		client.Terminal.SetPrompt(originalPrompt)
		return
	}
	baseTimeStr = strings.TrimSpace(baseTimeStr)
	
	// Parse base time
	baseTime, err := time.Parse("2006-01-02 15:04", baseTimeStr)
	if err != nil {
		fmt.Fprintf(client.Terminal, "\nInvalid time format. Please use: YYYY-MM-DD HH:MM\n")
		client.Terminal.SetPrompt(originalPrompt)
		return
	}
	
	// Ensure base time is in the future
	if baseTime.Before(time.Now()) {
		fmt.Fprintf(client.Terminal, "\nBase time must be in the future.\n")
		client.Terminal.SetPrompt(originalPrompt)
		return
	}
	
	// Get base time message
	client.Terminal.SetPrompt("Enter message for base time: ")
	baseMessage, err := client.Terminal.ReadLine()
	if err != nil {
		fmt.Fprintf(client.Terminal, "\nError reading input: %v\n", err)
		client.Terminal.SetPrompt(originalPrompt)
		return
	}
	baseMessage = strings.TrimSpace(baseMessage)
	
	if baseMessage == "" {
		fmt.Fprintf(client.Terminal, "\nMessage cannot be empty.\n")
		client.Terminal.SetPrompt(originalPrompt)
		return
	}
	
	// Create base time broadcast
	baseBroadcast := models.BroadcastMessage{
		CreatorID:    client.User.ID,
		BaseTime:     baseTime,
		BaseMessage:  baseMessage,
		ScheduledAt:  baseTime,
		Message:      baseMessage,
		MinuteOffset: 0,
		IsSent:       false,
	}
	
	var broadcasts []models.BroadcastMessage
	broadcasts = append(broadcasts, baseBroadcast)
	
	// Ask for reminders
	fmt.Fprintf(client.Terminal, "\n")
	for {
		client.Terminal.SetPrompt("Add a reminder? (y/n): ")
		addReminder, err := client.Terminal.ReadLine()
		if err != nil {
			fmt.Fprintf(client.Terminal, "\nError reading input: %v\n", err)
			client.Terminal.SetPrompt(originalPrompt)
			return
		}
		addReminder = strings.ToLower(strings.TrimSpace(addReminder))
		
		if addReminder != "y" && addReminder != "yes" {
			break
		}
		
		// Get offset
		client.Terminal.SetPrompt("Enter minutes offset (negative for before, positive for after): ")
		offsetStr, err := client.Terminal.ReadLine()
		if err != nil {
			fmt.Fprintf(client.Terminal, "\nError reading input: %v\n", err)
			client.Terminal.SetPrompt(originalPrompt)
			return
		}
		offsetStr = strings.TrimSpace(offsetStr)
		
		offset, err := strconv.Atoi(offsetStr)
		if err != nil {
			fmt.Fprintf(client.Terminal, "\nInvalid offset. Please enter a number.\n")
			continue
		}
		
		// Get reminder message
		client.Terminal.SetPrompt("Enter reminder message: ")
		reminderMsg, err := client.Terminal.ReadLine()
		if err != nil {
			fmt.Fprintf(client.Terminal, "\nError reading input: %v\n", err)
			client.Terminal.SetPrompt(originalPrompt)
			return
		}
		reminderMsg = strings.TrimSpace(reminderMsg)
		
		if reminderMsg == "" {
			fmt.Fprintf(client.Terminal, "\nMessage cannot be empty.\n")
			continue
		}
		
		// Calculate scheduled time
		scheduledAt := baseTime.Add(time.Duration(offset) * time.Minute)
		
		// Ensure scheduled time is in the future
		if scheduledAt.Before(time.Now()) {
			fmt.Fprintf(client.Terminal, "\nScheduled time would be in the past. Skipping.\n")
			continue
		}
		
		reminder := models.BroadcastMessage{
			CreatorID:    client.User.ID,
			BaseTime:     baseTime,
			BaseMessage:  baseMessage,
			ScheduledAt:  scheduledAt,
			Message:      reminderMsg,
			MinuteOffset: offset,
			IsSent:       false,
		}
		
		broadcasts = append(broadcasts, reminder)
		fmt.Fprintf(client.Terminal, "Reminder added for %s\n", scheduledAt.Format("2006-01-02 15:04:05"))
	}
	
	// Save all broadcasts
	for _, broadcast := range broadcasts {
		if err := database.DB.Create(&broadcast).Error; err != nil {
			fmt.Fprintf(client.Terminal, "\nError saving broadcast: %v\n", err)
			client.Terminal.SetPrompt(originalPrompt)
			return
		}
	}
	
	fmt.Fprintf(client.Terminal, "\nBroadcast scheduled successfully!\n")
	fmt.Fprintf(client.Terminal, "Base time: %s\n", baseTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(client.Terminal, "Total messages: %d\n\n", len(broadcasts))
	
	client.Terminal.SetPrompt(originalPrompt)
	
	logAction(client.User, "schedule_broadcast", fmt.Sprintf("Scheduled %d broadcast message(s)", len(broadcasts)))
}

// handleSignupInteractive converts a guest user to a full user account
func handleSignupInteractive(client *Client) {
	fmt.Fprintf(client.Terminal, "\n=== Convert Guest to Full Account ===\n\n")
	fmt.Fprintf(client.Terminal, "You are currently logged in as guest: %s\n", client.User.Nickname)
	fmt.Fprintf(client.Terminal, "Let's create a permanent account for you.\n\n")
	
	originalPrompt := "> "
	
	// Get desired username
	client.Terminal.SetPrompt("Enter your desired username: ")
	username, err := client.Terminal.ReadLine()
	if err != nil {
		fmt.Fprintf(client.Terminal, "\nError reading input: %v\n", err)
		client.Terminal.SetPrompt(originalPrompt)
		return
	}
	username = strings.TrimSpace(username)
	
	if username == "" {
		fmt.Fprintf(client.Terminal, "\nUsername cannot be empty.\n")
		client.Terminal.SetPrompt(originalPrompt)
		return
	}
	
	// Check if username already exists
	var existingUser models.User
	if err := database.DB.Where("username = ?", username).First(&existingUser).Error; err == nil {
		fmt.Fprintf(client.Terminal, "\nUsername '%s' is already taken. Please try another.\n", username)
		client.Terminal.SetPrompt(originalPrompt)
		return
	}
	
	// Choose authentication method
	fmt.Fprintf(client.Terminal, "\nChoose authentication method:\n")
	fmt.Fprintf(client.Terminal, "1. Password\n")
	fmt.Fprintf(client.Terminal, "2. SSH Key\n")
	client.Terminal.SetPrompt("Enter choice (1 or 2): ")
	
	choice, err := client.Terminal.ReadLine()
	if err != nil {
		fmt.Fprintf(client.Terminal, "\nError reading input: %v\n", err)
		client.Terminal.SetPrompt(originalPrompt)
		return
	}
	choice = strings.TrimSpace(choice)
	
	var password, sshKey string
	
	if choice == "1" {
		client.Terminal.SetPrompt("\nEnter password (visible): ")
		line, err := client.Terminal.ReadLine()
		if err != nil {
			fmt.Fprintf(client.Terminal, "\nError reading input: %v\n", err)
			client.Terminal.SetPrompt(originalPrompt)
			return
		}
		password = strings.TrimSpace(line)
		
		if password == "" {
			fmt.Fprintf(client.Terminal, "Password cannot be empty\n")
			client.Terminal.SetPrompt(originalPrompt)
			return
		}
	} else if choice == "2" {
		fmt.Fprintf(client.Terminal, "\nPaste your SSH public key (end with a line containing only 'END'):\n")
		client.Terminal.SetPrompt("")
		var keyLines []string
		for {
			line, err := client.Terminal.ReadLine()
			if err != nil {
				fmt.Fprintf(client.Terminal, "\nError reading input: %v\n", err)
				client.Terminal.SetPrompt(originalPrompt)
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
		sshKey = strings.Join(keyLines, " ")
		
		if sshKey == "" {
			fmt.Fprintf(client.Terminal, "SSH key cannot be empty\n")
			client.Terminal.SetPrompt(originalPrompt)
			return
		}
	} else {
		fmt.Fprintf(client.Terminal, "Invalid choice. Please enter 1 or 2.\n")
		client.Terminal.SetPrompt(originalPrompt)
		return
	}
	
	// Update the guest user to become a full user
	client.User.Username = username
	client.User.IsGuest = false
	
	if password != "" {
		hashedPassword, err := auth.HashPassword(password)
		if err != nil {
			fmt.Fprintf(client.Terminal, "\nFailed to hash password: %v\n", err)
			client.Terminal.SetPrompt(originalPrompt)
			return
		}
		client.User.PasswordHash = hashedPassword
	}
	
	if sshKey != "" {
		// Validate SSH key format
		_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshKey))
		if err != nil {
			fmt.Fprintf(client.Terminal, "\nInvalid SSH key format: %v\n", err)
			client.Terminal.SetPrompt(originalPrompt)
			return
		}
		client.User.SSHKey = sshKey
	}
	
	// Save the updated user
	if err := database.DB.Save(client.User).Error; err != nil {
		fmt.Fprintf(client.Terminal, "\nFailed to create account: %v\n", err)
		client.Terminal.SetPrompt(originalPrompt)
		return
	}
	
	fmt.Fprintf(client.Terminal, "\nAccount created successfully!\n")
	fmt.Fprintf(client.Terminal, "You are now a full user: %s\n", username)
	fmt.Fprintf(client.Terminal, "You can now access all rooms and features.\n\n")
	
	client.Terminal.SetPrompt(originalPrompt)
	
	logAction(client.User, "signup", fmt.Sprintf("Guest %s converted to user %s", client.User.Nickname, username))
}

func handleMessage(client *Client, message string) {
	// Restrict empty messages
	if strings.TrimSpace(message) == "" {
		return
	}

	// Check if user is in a room
	if client.User.CurrentRoomID == nil {
		fmt.Fprintf(client.Terminal, "You are not in a room. Use /join <room> to join one.\n")
		return
	}

	// Check if user is muted
	if client.User.IsMuted && client.User.MuteExpiresAt != nil && client.User.MuteExpiresAt.After(time.Now()) {
		fmt.Fprintf(client.Terminal, "You are muted until %s\n", client.User.MuteExpiresAt.Format("2006-01-02 15:04:05"))
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

	// Update room activity timestamp
	if client.User.CurrentRoomID != nil {
		database.DB.Model(&models.Room{}).Where("id = ?", *client.User.CurrentRoomID).
			Update("last_activity_at", time.Now())
	}

	// Check for mentions
	words := strings.Fields(message)
	for _, word := range words {
		if strings.HasPrefix(word, "@") && len(word) > 1 {
			// Strip trailing punctuation
			mentionedUsername := strings.TrimPrefix(word, "@")
			mentionedUsername = strings.TrimRight(mentionedUsername, ".,!?;:")

			// Handle @me - skip (doesn't make sense to mention yourself)
			if mentionedUsername == "me" {
				continue
			}

			// Handle @everyone - notify all users in the current room
			if mentionedUsername == "everyone" {
				var roomUsers []models.User
				database.DB.Where("current_room_id = ?", client.User.CurrentRoomID).Find(&roomUsers)
				for _, roomUser := range roomUsers {
					if roomUser.ID == client.User.ID {
						continue // Don't create mention for yourself
					}
					mention := models.Mention{
						UserID:    roomUser.ID,
						MessageID: chatMsg.ID,
					}
					database.DB.Create(&mention)

					// Send bell notification
					server.mutex.RLock()
					if userClient, ok := server.clients[roomUser.ID]; ok {
						userClient.Terminal.Write([]byte("\a"))
					}
					server.mutex.RUnlock()
				}
				continue
			}

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

// handleGuestMessage handles messages from guest users (restricted to guests room)
func handleGuestMessage(client *Client, message string) {
	// Restrict empty messages
	if strings.TrimSpace(message) == "" {
		return
	}

	// Guest users can only send messages in the guests room
	if client.User.CurrentRoomID == nil {
		fmt.Fprintf(client.Terminal, "Error: You are not in a room.\n")
		return
	}

	// Verify they are in the guests room
	var currentRoom models.Room
	if err := database.DB.First(&currentRoom, *client.User.CurrentRoomID).Error; err != nil {
		fmt.Fprintf(client.Terminal, "Error: Could not verify current room.\n")
		return
	}

	if currentRoom.Name != "guests" {
		fmt.Fprintf(client.Terminal, "Error: Guests can only chat in the guests room.\n")
		return
	}

	// Process message
	displayName := client.User.Nickname
	if displayName == "" {
		displayName = client.User.Username
	}

	formattedMsg := fmt.Sprintf("%s (guest): %s", displayName, message)

	// Save message to database
	chatMsg := models.ChatMessage{
		UserID:  client.User.ID,
		RoomID:  client.User.CurrentRoomID,
		Content: message,
	}
	database.DB.Create(&chatMsg)

	// Update room activity
	currentRoom.LastActivityAt = time.Now()
	database.DB.Save(&currentRoom)

	// Broadcast message to room
	broadcastToRoom(*client.User.CurrentRoomID, formattedMsg, client.User.ID)

	logAction(client.User, "guest_message", fmt.Sprintf("Guest sent message in room %d", *client.User.CurrentRoomID))
}

// handleGuestCommand handles commands from guest users (restricted subset)
func handleGuestCommand(client *Client, line string) {
	parts := strings.Fields(line[1:]) // Remove leading /
	if len(parts) == 0 {
		return
	}

	cmdName := strings.ToLower(parts[0])
	args := parts[1:]

	// Only allow specific commands for guests
	allowedCommands := map[string]bool{
		"help":     true,
		"h":        true,
		"?":        true,
		"users":    true,
		"me":       true,
		"mentions": true,
	}

	if !allowedCommands[cmdName] {
		fmt.Fprintf(client.Terminal, "Command not available for guests. Type /help for available commands.\n")
		return
	}

	// Handle help specially for guests
	if cmdName == "help" || cmdName == "h" || cmdName == "?" {
		fmt.Fprintf(client.Terminal, "\nAvailable commands for guests:\n")
		fmt.Fprintf(client.Terminal, "  /help          - Show this help message\n")
		fmt.Fprintf(client.Terminal, "  /users         - List users in the guests room\n")
		fmt.Fprintf(client.Terminal, "  /me <action>   - Send an emote\n")
		fmt.Fprintf(client.Terminal, "  /mentions      - View your unread mentions\n")
		fmt.Fprintf(client.Terminal, "\nTo get full access, please register an account.\n\n")
		return
	}

	// Handle /mentions
	if cmdName == "mentions" {
		var mentions []models.Mention
		if err := database.DB.Preload("Message").Preload("Message.User").
			Where("user_id = ? AND is_read = ?", client.User.ID, false).
			Find(&mentions).Error; err != nil {
			fmt.Fprintf(client.Terminal, "Error fetching mentions: %v\n", err)
			return
		}

		if len(mentions) == 0 {
			fmt.Fprintf(client.Terminal, "No unread mentions\n")
			return
		}

		fmt.Fprintf(client.Terminal, "\nUnread mentions:\n")
		for _, mention := range mentions {
			fmt.Fprintf(client.Terminal, "  From %s: %s\n",
				mention.Message.User.Username, mention.Message.Content)
		}
		fmt.Fprintf(client.Terminal, "\n")

		// Mark mentions as read
		database.DB.Model(&models.Mention{}).Where("user_id = ? AND is_read = ?", client.User.ID, false).
			Update("is_read", true)
		return
	}

	// Handle /me emote
	if cmdName == "me" {
		if len(args) == 0 {
			fmt.Fprintf(client.Terminal, "Usage: /me <action>\n")
			return
		}
		action := strings.Join(args, " ")
		displayName := client.User.Nickname
		if displayName == "" {
			displayName = client.User.Username
		}
		message := fmt.Sprintf("* %s (guest) %s", displayName, action)
		
		// Save to database
		chatMsg := models.ChatMessage{
			UserID:  client.User.ID,
			RoomID:  client.User.CurrentRoomID,
			Content: action,
		}
		database.DB.Create(&chatMsg)
		
		// Update room activity timestamp
		if client.User.CurrentRoomID != nil {
			database.DB.Model(&models.Room{}).Where("id = ?", *client.User.CurrentRoomID).
				Update("last_activity_at", time.Now())
		}
		
		// Broadcast
		if client.User.CurrentRoomID != nil {
			broadcastToRoom(*client.User.CurrentRoomID, message, client.User.ID)
		}
		return
	}

	// Handle /users
	if cmdName == "users" {
		if client.User.CurrentRoomID == nil {
			fmt.Fprintf(client.Terminal, "You are not in a room.\n")
			return
		}

		// Get users in current room
		var users []models.User
		database.DB.Where("current_room_id = ?", *client.User.CurrentRoomID).Find(&users)

		if len(users) == 0 {
			fmt.Fprintf(client.Terminal, "No users in this room.\n")
			return
		}

		fmt.Fprintf(client.Terminal, "\nUsers in guests room:\n")
		for _, u := range users {
			displayName := u.Username
			if u.Nickname != "" {
				displayName = u.Nickname
			}
			guestTag := ""
			if u.IsGuest {
				guestTag = " (guest)"
			}
			fmt.Fprintf(client.Terminal, "  - %s%s\n", displayName, guestTag)
		}
		fmt.Fprintf(client.Terminal, "\n")
		return
	}
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
			client.Terminal.Write([]byte(message + "\n"))
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
		// Don't notify admin about their own actions
		if relatedUser != nil && admin.ID == *relatedUser {
			continue
		}

		// Create notification in database
		createNotification(admin.ID, notifType, message, relatedUser, relatedRoom)

		// If admin is online, send immediately
		server.mutex.RLock()
		if client, ok := server.clients[admin.ID]; ok {
			client.Mutex.Lock()
			client.Terminal.Write([]byte(fmt.Sprintf("\n[ADMIN] %s\n", message)))
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
		client.Terminal.Write([]byte(fmt.Sprintf("\n[Notification] %s\n", message)))
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

	client.Terminal.Write([]byte("\n=== Notifications ===\n"))
	// Reverse order to show oldest first
	for i := len(notifications) - 1; i >= 0; i-- {
		notif := notifications[i]
		client.Terminal.Write([]byte(fmt.Sprintf("  %s\n", notif.Message)))
	}
	client.Terminal.Write([]byte(fmt.Sprintf("=== %d unread notification(s) ===\n\n", len(notifications))))

	// Mark delivered notifications as read using their specific IDs
	notificationIDs := make([]uint, len(notifications))
	for i, notif := range notifications {
		notificationIDs[i] = notif.ID
	}
	database.DB.Model(&models.Notification{}).
		Where("id IN ?", notificationIDs).
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

// cleanupExpiredRooms checks for rooms that have expired and disconnects all users
func cleanupExpiredRooms() {
	ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		// Find expired rooms
		var expiredRooms []models.Room
		if err := database.DB.Where("expires_at IS NOT NULL AND expires_at <= ?", now).
			Find(&expiredRooms).Error; err != nil {
			log.Printf("Error fetching expired rooms: %v", err)
			continue
		}

		for _, room := range expiredRooms {
			// Find all users in this room
			var users []models.User
			if err := database.DB.Where("current_room_id = ?", room.ID).Find(&users).Error; err != nil {
				log.Printf("Error fetching users in expired room %s: %v", room.Name, err)
				continue
			}

			// Move all users to the general room
			var generalRoom models.Room
			if err := database.DB.Where("name = ?", "general").First(&generalRoom).Error; err != nil {
				log.Printf("Error finding general room: %v", err)
				continue
			}

			for _, user := range users {
				// Update user's room
				user.CurrentRoomID = &generalRoom.ID
				if err := database.DB.Save(&user).Error; err != nil {
					log.Printf("Error moving user %s from expired room: %v", user.Username, err)
					continue
				}

				// Notify user if they are online
				server.mutex.RLock()
				if client, ok := server.clients[user.ID]; ok {
					client.Mutex.Lock()
					client.Terminal.Write([]byte(fmt.Sprintf("\n*** Room #%s has expired. You have been moved to #general.\n", room.Name)))
					client.Mutex.Unlock()
				}
				server.mutex.RUnlock()
			}

			// Delete the expired room
			if err := database.DB.Delete(&room).Error; err != nil {
				log.Printf("Error deleting expired room %s: %v", room.Name, err)
			} else {
				log.Printf("Deleted expired room: %s", room.Name)
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

// broadcastScheduler checks for scheduled broadcasts and sends them
func broadcastScheduler() {
	ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		// Find broadcasts that are due and not yet sent
		// Use a transaction to prevent race conditions
		var broadcasts []models.BroadcastMessage
		err := database.DB.Transaction(func(tx *gorm.DB) error {
			// Lock rows for update
			if err := tx.Where("is_sent = ? AND scheduled_at <= ?", false, now).
				Clauses(clause.Locking{Strength: "UPDATE"}).
				Find(&broadcasts).Error; err != nil {
				return err
			}

			// Mark them as sent immediately to prevent duplicate sends
			if len(broadcasts) > 0 {
				var ids []uint
				for _, b := range broadcasts {
					ids = append(ids, b.ID)
				}
				if err := tx.Model(&models.BroadcastMessage{}).
					Where("id IN ?", ids).
					Update("is_sent", true).Error; err != nil {
					return err
				}
			}

			return nil
		})

		if err != nil {
			log.Printf("Error fetching broadcasts: %v", err)
			continue
		}

		if len(broadcasts) == 0 {
			continue
		}

		// Check if there are any users online
		server.mutex.RLock()
		userCount := len(server.clients)
		server.mutex.RUnlock()

		if userCount == 0 {
			log.Printf("Skipping %d broadcast(s) - no users online", len(broadcasts))
			// Broadcasts remain marked as sent - they won't be retried
			continue
		}

		// Send broadcasts to all users
		for _, broadcast := range broadcasts {
			message := fmt.Sprintf("\n*** BROADCAST *** %s\n", broadcast.Message)
			
			server.mutex.RLock()
			for _, client := range server.clients {
				client.Mutex.Lock()
				client.Terminal.Write([]byte(message))
				client.Mutex.Unlock()
			}
			server.mutex.RUnlock()

			log.Printf("Sent broadcast %d to %d users", broadcast.ID, userCount)
		}
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
