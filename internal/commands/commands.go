package commands

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/denizsincar29/schat/internal/auth"
	"github.com/denizsincar29/schat/internal/database"
	"github.com/denizsincar29/schat/internal/models"
)

const (
	minDuration = 2 * time.Minute
	maxDuration = 24 * time.Hour
)

var (
	// Reserved names that cannot be used for rooms
	reservedRoomNames = []string{"general", "admin", "system", "all", "everyone", "here"}
)

type Command struct {
	Name        string
	Aliases     []string
	Description string
	Usage       string
	Handler     func(user *models.User, args []string) (string, error)
	AdminOnly   bool
}

var Commands = make(map[string]*Command)

func init() {
	registerCommand(&Command{
		Name:        "help",
		Aliases:     []string{"h", "?", "commands"},
		Description: "Show available commands",
		Usage:       "/help [command]",
		Handler:     handleHelp,
	})

	registerCommand(&Command{
		Name:        "rooms",
		Aliases:     []string{"r", "listrooms"},
		Description: "List available rooms",
		Usage:       "/rooms",
		Handler:     handleRooms,
	})

	registerCommand(&Command{
		Name:        "join",
		Aliases:     []string{"j", "room"},
		Description: "Join a room",
		Usage:       "/join #<room_name> [password]",
		Handler:     handleJoin,
	})

	registerCommand(&Command{
		Name:        "create",
		Aliases:     []string{"cr", "createroom"},
		Description: "Create a new room",
		Usage:       "/create #<room_name> [--password <password>] [description]",
		Handler:     handleCreate,
	})

	registerCommand(&Command{
		Name:        "createguestroom",
		Aliases:     []string{"cgr", "guestroom"},
		Description: "Create a guest room (allows unauthenticated access)",
		Usage:       "/createguestroom #<room_name> --expires-in <duration> [--max-participants <n>] [description]",
		Handler:     handleCreateGuestRoom,
	})

	registerCommand(&Command{
		Name:        "leave",
		Aliases:     []string{"l", "exit"},
		Description: "Leave current room and join general",
		Usage:       "/leave",
		Handler:     handleLeave,
	})

	registerCommand(&Command{
		Name:        "permanent",
		Aliases:     []string{"perm", "makepermanent"},
		Description: "Make a room permanent (admin only)",
		Usage:       "/permanent #<room_name>",
		Handler:     handlePermanent,
		AdminOnly:   true,
	})

	registerCommand(&Command{
		Name:        "hide",
		Aliases:     []string{"hideroom"},
		Description: "Hide a room from non-admins (admin only)",
		Usage:       "/hide #<room_name>",
		Handler:     handleHide,
		AdminOnly:   true,
	})

	registerCommand(&Command{
		Name:        "unhide",
		Aliases:     []string{"unhideroom", "show"},
		Description: "Unhide a room (admin only)",
		Usage:       "/unhide #<room_name>",
		Handler:     handleUnhide,
		AdminOnly:   true,
	})

	registerCommand(&Command{
		Name:        "msg",
		Aliases:     []string{"pm", "whisper", "w"},
		Description: "Send a private message",
		Usage:       "/msg <username> <message>",
		Handler:     handlePrivateMessage,
	})

	registerCommand(&Command{
		Name:        "nick",
		Aliases:     []string{"nickname"},
		Description: "Set your nickname",
		Usage:       "/nick <nickname>",
		Handler:     handleNickname,
	})

	registerCommand(&Command{
		Name:        "status",
		Aliases:     []string{"away", "afk"},
		Description: "Set your status message",
		Usage:       "/status <status_message>",
		Handler:     handleStatus,
	})

	registerCommand(&Command{
		Name:        "users",
		Aliases:     []string{"who", "list"},
		Description: "List users in current room or specified room",
		Usage:       "/users [#room_name or .]",
		Handler:     handleUsers,
	})

	registerCommand(&Command{
		Name:        "mentions",
		Aliases:     []string{"m"},
		Description: "List your unread mentions",
		Usage:       "/mentions",
		Handler:     handleMentions,
	})

	registerCommand(&Command{
		Name:        "bell",
		Aliases:     []string{"beep", "notify"},
		Description: "Toggle bell notifications",
		Usage:       "/bell",
		Handler:     handleBell,
	})

	registerCommand(&Command{
		Name:        "ban",
		Aliases:     []string{"b"},
		Description: "Ban a user for a duration",
		Usage:       "/ban <username> <duration> [reason]",
		Handler:     handleBan,
		AdminOnly:   true,
	})

	registerCommand(&Command{
		Name:        "kick",
		Aliases:     []string{"k"},
		Description: "Kick a user for a duration",
		Usage:       "/kick <username> <duration> [reason]",
		Handler:     handleKick,
		AdminOnly:   true,
	})

	registerCommand(&Command{
		Name:        "mute",
		Aliases:     []string{"silence"},
		Description: "Mute a user for a duration",
		Usage:       "/mute <username> <duration> [reason]",
		Handler:     handleMute,
		AdminOnly:   true,
	})

	registerCommand(&Command{
		Name:        "unban",
		Aliases:     []string{"ub"},
		Description: "Unban a user",
		Usage:       "/unban <username>",
		Handler:     handleUnban,
		AdminOnly:   true,
	})

	registerCommand(&Command{
		Name:        "unmute",
		Aliases:     []string{"um"},
		Description: "Unmute a user",
		Usage:       "/unmute <username>",
		Handler:     handleUnmute,
		AdminOnly:   true,
	})

	registerCommand(&Command{
		Name:        "promote",
		Aliases:     []string{"makeadmin"},
		Description: "Promote a user to admin",
		Usage:       "/promote <username>",
		Handler:     handlePromote,
		AdminOnly:   true,
	})

	registerCommand(&Command{
		Name:        "demote",
		Aliases:     []string{"removeadmin"},
		Description: "Remove admin privileges from a user",
		Usage:       "/demote <username>",
		Handler:     handleDemote,
		AdminOnly:   true,
	})

	registerCommand(&Command{
		Name:        "admins",
		Aliases:     []string{"listadmins"},
		Description: "List all admins",
		Usage:       "/admins",
		Handler:     handleListAdmins,
	})

	registerCommand(&Command{
		Name:        "deleteuser",
		Aliases:     []string{"deluser", "removeuser"},
		Description: "Delete a user (admin only)",
		Usage:       "/deleteuser <username>",
		Handler:     handleDeleteUser,
		AdminOnly:   true,
	})

	registerCommand(&Command{
		Name:        "me",
		Aliases:     []string{"emote", "action"},
		Description: "Send an emote action",
		Usage:       "/me <action> or text @me more text",
		Handler:     handleEmote,
	})

	registerCommand(&Command{
		Name:        "news",
		Aliases:     []string{"inbox", "notifications"},
		Description: "View your unread mentions and private messages",
		Usage:       "/news",
		Handler:     handleNews,
	})

	registerCommand(&Command{
		Name:        "report",
		Aliases:     []string{"reportuser"},
		Description: "Report a user to admins",
		Usage:       "/report @username <reason>",
		Handler:     handleReport,
	})

	registerCommand(&Command{
		Name:        "reports",
		Aliases:     []string{"viewreports"},
		Description: "View user reports (admin only)",
		Usage:       "/reports",
		Handler:     handleReports,
		AdminOnly:   true,
	})

	registerCommand(&Command{
		Name:        "markreports",
		Aliases:     []string{"readreports"},
		Description: "Mark all reports as read (admin only)",
		Usage:       "/markreports",
		Handler:     handleMarkReports,
		AdminOnly:   true,
	})

	registerCommand(&Command{
		Name:        "move",
		Aliases:     []string{"moveuser"},
		Description: "Move a user to a different room (admin only)",
		Usage:       "/move @<username> #<room_name>",
		Handler:     handleMove,
		AdminOnly:   true,
	})

	registerCommand(&Command{
		Name:        "listusers",
		Aliases:     []string{"allusers", "users"},
		Description: "List all user accounts (admin only)",
		Usage:       "/listusers",
		Handler:     handleListUsers,
		AdminOnly:   true,
	})

	registerCommand(&Command{
		Name:        "viewuser",
		Aliases:     []string{"userinfo"},
		Description: "View detailed user information (admin only)",
		Usage:       "/viewuser @<username>",
		Handler:     handleViewUser,
		AdminOnly:   true,
	})

	registerCommand(&Command{
		Name:        "setpassword",
		Aliases:     []string{"roompassword", "setpass"},
		Description: "Set or change room password (room creator or admin only)",
		Usage:       "/setpassword #<room_name> <password> (use 'none' to remove)",
		Handler:     handleSetPassword,
	})

	registerCommand(&Command{
		Name:        "signup",
		Aliases:     []string{"register"},
		Description: "Convert guest account to full user account (guests only)",
		Usage:       "/signup",
		Handler:     handleSignup,
	})

	registerCommand(&Command{
		Name:        "inactive",
		Aliases:     []string{"inactivity", "lastmessage"},
		Description: "Check inactivity time for current room or specific room",
		Usage:       "/inactive [#room_name]",
		Handler:     handleInactive,
	})

	registerCommand(&Command{
		Name:        "setdefault",
		Aliases:     []string{"defaultroom"},
		Description: "Set your default room to join on login",
		Usage:       "/setdefault [#room_name]",
		Handler:     handleSetDefault,
	})

	registerCommand(&Command{
		Name:        "broadcast",
		Aliases:     []string{"schedulebroadcast", "announce"},
		Description: "Schedule a broadcast message with reminders (admin only)",
		Usage:       "/broadcast",
		Handler:     handleBroadcast,
		AdminOnly:   true,
	})

	registerCommand(&Command{
		Name:        "broadcasts",
		Aliases:     []string{"listbroadcasts"},
		Description: "List scheduled broadcast messages (admin only)",
		Usage:       "/broadcasts",
		Handler:     handleListBroadcasts,
		AdminOnly:   true,
	})

	registerCommand(&Command{
		Name:        "cancelbroadcast",
		Aliases:     []string{"deletebroadcast", "removebroadcast"},
		Description: "Cancel a scheduled broadcast (admin only)",
		Usage:       "/cancelbroadcast <id>",
		Handler:     handleCancelBroadcast,
		AdminOnly:   true,
	})
}

func registerCommand(cmd *Command) {
	// Check if the command name is already registered
	if existing, ok := Commands[cmd.Name]; ok {
		log.Printf("WARNING: Command '%s' is already registered. Skipping duplicate registration.", cmd.Name)
		log.Printf("  Existing: %s", existing.Description)
		log.Printf("  New: %s", cmd.Description)
		return
	}
	
	Commands[cmd.Name] = cmd
	
	// Register all aliases, checking for conflicts
	for _, alias := range cmd.Aliases {
		if existing, ok := Commands[alias]; ok {
			// Check if this alias already points to this command (from a previous registration)
			if existing.Name == cmd.Name {
				continue // Already registered, skip
			}
			log.Printf("WARNING: Alias '%s' conflicts with existing command '%s'. Skipping alias.", alias, existing.Name)
			log.Printf("  Existing command: %s - %s", existing.Name, existing.Description)
			log.Printf("  New command: %s - %s", cmd.Name, cmd.Description)
			continue
		}
		Commands[alias] = cmd
	}
}

func GetCommand(name string) *Command {
	return Commands[name]
}

// stripPrefixes removes @ prefix from usernames and # prefix from room names
func stripPrefixes(name string) string {
	name = strings.TrimPrefix(name, "@")
	name = strings.TrimPrefix(name, "#")
	return name
}

func GetAllCommands() []*Command {
	seen := make(map[string]bool)
	var cmds []*Command
	for _, cmd := range Commands {
		if !seen[cmd.Name] {
			cmds = append(cmds, cmd)
			seen[cmd.Name] = true
		}
	}
	return cmds
}

// capitalizeFirst capitalizes the first letter of a string
func capitalizeFirst(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(string(s[0])) + s[1:]
}

func handleHelp(user *models.User, args []string) (string, error) {
	// Special commands not in the regular command system
	specialCommands := map[string]string{
		"addkey": "Add SSH key to account (use 'pp' to preserve password, 'mr' for machine-readable output)",
		"qr":     "Generate and send a QR code to the chat",
	}
	
	// Command categories
	type CommandTopic struct {
		Name     string
		Commands []string
	}
	
	topics := []CommandTopic{
		{
			Name:     "rooms",
			Commands: []string{"rooms", "join", "create", "leave", "users"},
		},
		{
			Name:     "messaging",
			Commands: []string{"msg", "mentions", "news", "me"},
		},
		{
			Name:     "user",
			Commands: []string{"nick", "status", "bell"},
		},
		{
			Name:     "moderation",
			Commands: []string{"ban", "kick", "mute", "unban", "unmute", "report", "reports", "markreports"},
		},
		{
			Name:     "admin",
			Commands: []string{"promote", "demote", "admins", "deleteuser", "permanent", "hide", "unhide"},
		},
	}

	if len(args) > 0 {
		topicOrCmd := strings.ToLower(args[0])
		
		// Check if it's a topic
		for _, topic := range topics {
			if topic.Name == topicOrCmd {
				var result strings.Builder
				result.WriteString(fmt.Sprintf("=== %s Commands ===\n", capitalizeFirst(topic.Name)))
				
				for _, cmdName := range topic.Commands {
					cmd := GetCommand(cmdName)
					if cmd != nil {
						if cmd.AdminOnly && !user.IsAdmin {
							continue
						}
						result.WriteString(fmt.Sprintf("  /%s - %s\n", cmd.Name, cmd.Description))
					}
				}
				
				result.WriteString("\nType /help <command> for more information")
				return result.String(), nil
			}
		}

		// Check if it's a special command
		if desc, ok := specialCommands[topicOrCmd]; ok {
			usage := fmt.Sprintf("/%s", topicOrCmd)
			if topicOrCmd == "addkey" {
				usage = "/addkey [pp] [mr]"
			} else if topicOrCmd == "qr" {
				usage = "/qr <text or URL>"
			}
			return fmt.Sprintf("%s: %s\nUsage: %s", topicOrCmd, desc, usage), nil
		}

		// Check if it's a regular command
		cmd := GetCommand(topicOrCmd)
		if cmd == nil {
			return "", fmt.Errorf("command or topic not found: %s", topicOrCmd)
		}
		aliases := strings.Join(cmd.Aliases, ", ")
		return fmt.Sprintf("%s: %s\nUsage: %s\nAliases: %s", cmd.Name, cmd.Description, cmd.Usage, aliases), nil
	}

	// Show all commands organized by topic
	var result strings.Builder
	result.WriteString("Available Commands by Topic:\n\n")
	
	for _, topic := range topics {
		// Skip admin topic if user is not admin
		hasVisibleCommands := false
		for _, cmdName := range topic.Commands {
			cmd := GetCommand(cmdName)
			if cmd != nil && (!cmd.AdminOnly || user.IsAdmin) {
				hasVisibleCommands = true
				break
			}
		}
		
		if !hasVisibleCommands {
			continue
		}
		
		result.WriteString(fmt.Sprintf("=== %s ===\n", capitalizeFirst(topic.Name)))
		for _, cmdName := range topic.Commands {
			cmd := GetCommand(cmdName)
			if cmd != nil {
				if cmd.AdminOnly && !user.IsAdmin {
					continue
				}
				result.WriteString(fmt.Sprintf("  /%s - %s\n", cmd.Name, cmd.Description))
			}
		}
		result.WriteString("\n")
	}
	
	// Add special commands
	result.WriteString("=== Special ===\n")
	for name, desc := range specialCommands {
		result.WriteString(fmt.Sprintf("  /%s - %s\n", name, desc))
	}
	
	result.WriteString("\nType /help <topic> to see commands in a topic (e.g., /help rooms)")
	result.WriteString("\nType /help <command> for detailed information")
	return result.String(), nil
}

func handleRooms(user *models.User, args []string) (string, error) {
	var rooms []models.Room
	
	// Filter hidden rooms for non-admins
	query := database.DB
	if !user.IsAdmin {
		query = query.Where("is_hidden = ?", false)
	}
	
	if err := query.Find(&rooms).Error; err != nil {
		return "", fmt.Errorf("failed to fetch rooms: %w", err)
	}

	var result strings.Builder
	result.WriteString("Available rooms:\n")
	for _, room := range rooms {
		marker := " "
		if user.CurrentRoomID != nil && *user.CurrentRoomID == room.ID {
			marker = "*"
		}
		
		// Add indicators for room properties
		indicators := ""
		if room.IsHidden {
			indicators += " [Hidden]"
		}
		if room.IsPermanent {
			indicators += " [Permanent]"
		}
		if room.Password != "" {
			indicators += " [Password-protected]"
		}
		
		result.WriteString(fmt.Sprintf("%s #%s - %s%s\n", marker, room.Name, room.Description, indicators))
	}
	return result.String(), nil
}

func handleJoin(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /join #<room_name> [password]")
	}

	roomName := stripPrefixes(args[0])
	var room models.Room
	if err := database.DB.Where("name = ?", roomName).First(&room).Error; err != nil {
		return "", fmt.Errorf("room not found: %s", roomName)
	}
	
	// Check if room is hidden and user is not admin
	if room.IsHidden && !user.IsAdmin {
		return "", fmt.Errorf("room not found: %s", roomName)
	}

	// Check if room has expired
	if room.ExpiresAt != nil && room.ExpiresAt.Before(time.Now()) {
		return "", fmt.Errorf("room #%s has expired", roomName)
	}

	// Check if room has max participants limit
	if room.MaxParticipants != nil {
		var currentCount int64
		database.DB.Model(&models.User{}).Where("current_room_id = ?", room.ID).Count(&currentCount)
		if int(currentCount) >= *room.MaxParticipants {
			return "", fmt.Errorf("room #%s is full (max %d participants)", roomName, *room.MaxParticipants)
		}
	}

	// Check if room has a password
	if room.Password != "" {
		// Room is password-protected
		if len(args) < 2 {
			return "", fmt.Errorf("this room requires a password. Usage: /join #<room_name> <password>")
		}
		password := args[1]
		// Verify password
		if !auth.VerifyPassword(password, room.Password) {
			return "", fmt.Errorf("incorrect password for room %s", roomName)
		}
	}

	user.CurrentRoomID = &room.ID
	if err := database.DB.Save(user).Error; err != nil {
		return "", fmt.Errorf("failed to join room: %w", err)
	}

	return fmt.Sprintf("Joined room: #%s", room.Name), nil
}

func handleCreate(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /create #<room_name> [--password <password>] [--max-participants <n>] [--expires-in <duration>] [description]")
	}

	roomName := stripPrefixes(args[0])
	
	// Validate room name - check for reserved names
	roomNameLower := strings.ToLower(roomName)
	for _, reserved := range reservedRoomNames {
		if roomNameLower == reserved {
			return "", fmt.Errorf("room name '%s' is reserved and cannot be used", roomName)
		}
	}

	// Check for minimum length
	if len(roomName) < 2 {
		return "", fmt.Errorf("room name must be at least 2 characters long")
	}

	// Check for maximum length
	if len(roomName) > 32 {
		return "", fmt.Errorf("room name must be at most 32 characters long")
	}

	// Parse arguments for password, max participants, expiration, and description
	var password string
	var maxParticipants *int
	var expiresAt *time.Time
	var descriptionParts []string
	i := 1
	for i < len(args) {
		if args[i] == "--password" || args[i] == "-p" {
			if i+1 >= len(args) {
				return "", fmt.Errorf("--password flag requires a password argument")
			}
			password = args[i+1]
			i += 2
		} else if args[i] == "--max-participants" || args[i] == "--max" {
			if i+1 >= len(args) {
				return "", fmt.Errorf("--max-participants flag requires a number argument")
			}
			maxPart, err := strconv.Atoi(args[i+1])
			if err != nil || maxPart < 1 {
				return "", fmt.Errorf("--max-participants must be a positive number")
			}
			if maxPart > 1000 {
				return "", fmt.Errorf("--max-participants cannot exceed 1000")
			}
			maxParticipants = &maxPart
			i += 2
		} else if args[i] == "--expires-in" || args[i] == "--expires" {
			if i+1 >= len(args) {
				return "", fmt.Errorf("--expires-in flag requires a duration argument (e.g., 30m, 2h, 1h30m)")
			}
			duration, err := time.ParseDuration(args[i+1])
			if err != nil {
				return "", fmt.Errorf("invalid duration format: %s (use format like 30m, 2h, 1h30m)", args[i+1])
			}
			if duration < 2*time.Minute {
				return "", fmt.Errorf("expiration time must be at least 2 minutes")
			}
			expireTime := time.Now().Add(duration)
			expiresAt = &expireTime
			i += 2
		} else {
			descriptionParts = append(descriptionParts, args[i])
			i++
		}
	}
	
	description := strings.Join(descriptionParts, " ")

	creatorID := user.ID
	room := models.Room{
		Name:            roomName,
		Description:     description,
		CreatorID:       &creatorID,
		MaxParticipants: maxParticipants,
		ExpiresAt:       expiresAt,
	}

	// Hash password if provided
	if password != "" {
		hashedPassword, err := auth.HashPassword(password)
		if err != nil {
			return "", fmt.Errorf("failed to hash password: %w", err)
		}
		room.Password = hashedPassword
	}

	if err := database.DB.Create(&room).Error; err != nil {
		return "", fmt.Errorf("failed to create room: %w", err)
	}

	// Build response message with room features
	response := fmt.Sprintf("Created room: #%s", roomName)
	if password != "" {
		response = fmt.Sprintf("Created password-protected room: #%s", roomName)
	}
	if maxParticipants != nil {
		response += fmt.Sprintf(" (max %d participants)", *maxParticipants)
	}
	if expiresAt != nil {
		response += fmt.Sprintf(" (expires at %s)", expiresAt.Format("2006-01-02 15:04"))
	}
	return response, nil
}

func handleCreateGuestRoom(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /createguestroom #<room_name> --expires-in <duration> [--max-participants <n>] [description]")
	}

	roomName := stripPrefixes(args[0])
	
	// Validate room name - check for reserved names
	roomNameLower := strings.ToLower(roomName)
	for _, reserved := range reservedRoomNames {
		if roomNameLower == reserved {
			return "", fmt.Errorf("room name '%s' is reserved and cannot be used", roomName)
		}
	}

	// Check for minimum length
	if len(roomName) < 2 {
		return "", fmt.Errorf("room name must be at least 2 characters long")
	}

	// Check for maximum length
	if len(roomName) > 32 {
		return "", fmt.Errorf("room name must be at most 32 characters long")
	}

	// Parse arguments for max participants, expiration, and description
	var maxParticipants *int
	var expiresAt *time.Time
	var descriptionParts []string
	i := 1
	for i < len(args) {
		if args[i] == "--max-participants" || args[i] == "--max" {
			if i+1 >= len(args) {
				return "", fmt.Errorf("--max-participants flag requires a number argument")
			}
			maxPart, err := strconv.Atoi(args[i+1])
			if err != nil || maxPart < 1 {
				return "", fmt.Errorf("--max-participants must be a positive number")
			}
			if maxPart > 1000 {
				return "", fmt.Errorf("--max-participants cannot exceed 1000")
			}
			maxParticipants = &maxPart
			i += 2
		} else if args[i] == "--expires-in" || args[i] == "--expires" {
			if i+1 >= len(args) {
				return "", fmt.Errorf("--expires-in flag is required for guest rooms (e.g., 30m, 2h, 1h30m)")
			}
			duration, err := time.ParseDuration(args[i+1])
			if err != nil {
				return "", fmt.Errorf("invalid duration format: %s (use format like 30m, 2h, 1h30m)", args[i+1])
			}
			if duration < 2*time.Minute {
				return "", fmt.Errorf("expiration time must be at least 2 minutes")
			}
			expireTime := time.Now().Add(duration)
			expiresAt = &expireTime
			i += 2
		} else {
			descriptionParts = append(descriptionParts, args[i])
			i++
		}
	}
	
	// Guest rooms must have an expiration time
	if expiresAt == nil {
		return "", fmt.Errorf("guest rooms must have an expiration time. Use --expires-in flag (e.g., --expires-in 2h)")
	}
	
	description := strings.Join(descriptionParts, " ")

	creatorID := user.ID
	room := models.Room{
		Name:            roomName,
		Description:     description,
		CreatorID:       &creatorID,
		MaxParticipants: maxParticipants,
		ExpiresAt:       expiresAt,
		IsGuestRoom:     true,
	}

	if err := database.DB.Create(&room).Error; err != nil {
		return "", fmt.Errorf("failed to create guest room: %w", err)
	}

	// Build response message with room features
	response := fmt.Sprintf("Created guest room: #%s", roomName)
	if maxParticipants != nil {
		response += fmt.Sprintf(" (max %d participants)", *maxParticipants)
	}
	response += fmt.Sprintf(" (expires at %s)", expiresAt.Format("2006-01-02 15:04"))
	response += fmt.Sprintf("\nGuests can join by typing the room name: %s", roomName)
	return response, nil
}

func handleLeave(user *models.User, args []string) (string, error) {
	if user.CurrentRoomID == nil {
		return "", fmt.Errorf("you are not in a room")
	}
	
	// Join the general room
	var generalRoom models.Room
	if err := database.DB.Where("name = ?", "general").First(&generalRoom).Error; err != nil {
		return "", fmt.Errorf("general room not found")
	}
	
	// Check if already in general
	if *user.CurrentRoomID == generalRoom.ID {
		return "You are already in the general room", nil
	}
	
	user.CurrentRoomID = &generalRoom.ID
	if err := database.DB.Save(user).Error; err != nil {
		return "", fmt.Errorf("failed to leave room: %w", err)
	}
	
	return "Left room and joined general", nil
}

func handlePermanent(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /permanent #<room_name>")
	}
	
	roomName := stripPrefixes(args[0])
	var room models.Room
	if err := database.DB.Where("name = ?", roomName).First(&room).Error; err != nil {
		return "", fmt.Errorf("room not found: %s", roomName)
	}
	
	if room.IsPermanent {
		return "", fmt.Errorf("room #%s is already permanent", roomName)
	}
	
	room.IsPermanent = true
	if err := database.DB.Save(&room).Error; err != nil {
		return "", fmt.Errorf("failed to make room permanent: %w", err)
	}
	
	logAction(user, "permanent", fmt.Sprintf("Made room %s permanent", roomName))
	return fmt.Sprintf("Room #%s is now permanent", roomName), nil
}

func handleHide(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /hide #<room_name>")
	}
	
	roomName := stripPrefixes(args[0])
	var room models.Room
	if err := database.DB.Where("name = ?", roomName).First(&room).Error; err != nil {
		return "", fmt.Errorf("room not found: %s", roomName)
	}
	
	if room.IsHidden {
		return "", fmt.Errorf("room #%s is already hidden", roomName)
	}
	
	room.IsHidden = true
	if err := database.DB.Save(&room).Error; err != nil {
		return "", fmt.Errorf("failed to hide room: %w", err)
	}
	
	logAction(user, "hide", fmt.Sprintf("Hid room %s", roomName))
	return fmt.Sprintf("Room #%s is now hidden", roomName), nil
}

func handleUnhide(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /unhide #<room_name>")
	}
	
	roomName := stripPrefixes(args[0])
	var room models.Room
	if err := database.DB.Where("name = ?", roomName).First(&room).Error; err != nil {
		return "", fmt.Errorf("room not found: %s", roomName)
	}
	
	if !room.IsHidden {
		return "", fmt.Errorf("room #%s is not hidden", roomName)
	}
	
	room.IsHidden = false
	if err := database.DB.Save(&room).Error; err != nil {
		return "", fmt.Errorf("failed to unhide room: %w", err)
	}
	
	logAction(user, "unhide", fmt.Sprintf("Unhid room %s", roomName))
	return fmt.Sprintf("Room #%s is now visible", roomName), nil
}

func handlePrivateMessage(user *models.User, args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("usage: /msg @username <message>")
	}

	username := strings.TrimPrefix(args[0], "@")

	// Handle @admin - send to all admins
	if username == "admin" {
		return sendToAllAdmins(user, strings.Join(args[1:], " "))
	}

	message := strings.Join(args[1:], " ")

	var recipient models.User
	if err := database.DB.Where("username = ?", username).First(&recipient).Error; err != nil {
		return "", fmt.Errorf("user not found: @%s", username)
	}

	chatMsg := models.ChatMessage{
		UserID:      user.ID,
		Content:     message,
		IsPrivate:   true,
		RecipientID: &recipient.ID,
	}

	if err := database.DB.Create(&chatMsg).Error; err != nil {
		return "", fmt.Errorf("failed to send message: %w", err)
	}

	// Check if PM logging is enabled
	var pmLoggingSetting models.Settings
	logPMs := false
	if err := database.DB.Where("key = ?", "log_private_messages").First(&pmLoggingSetting).Error; err == nil {
		logPMs = pmLoggingSetting.Value == "true"
	}

	if logPMs {
		logAction(user, "private_message", fmt.Sprintf("Sent PM to %s", username))
	}

	return fmt.Sprintf("Private message sent to @%s", username), nil
}

func handleNickname(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /nick <nickname>")
	}

	nickname := strings.Join(args, " ")
	user.Nickname = nickname
	if err := database.DB.Save(user).Error; err != nil {
		return "", fmt.Errorf("failed to set nickname: %w", err)
	}

	return fmt.Sprintf("Nickname set to: %s", nickname), nil
}

func handleStatus(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		user.Status = ""
	} else {
		user.Status = strings.Join(args, " ")
	}

	if err := database.DB.Save(user).Error; err != nil {
		return "", fmt.Errorf("failed to set status: %w", err)
	}

	if user.Status == "" {
		return "Status cleared", nil
	}
	return fmt.Sprintf("Status set to: %s", user.Status), nil
}

func handleUsers(user *models.User, args []string) (string, error) {
	var roomID *uint
	var roomName string
	
	// Parse arguments to determine which room to query
	if len(args) > 0 {
		roomArg := args[0]
		
		// Handle "." as current room
		if roomArg == "." {
			if user.CurrentRoomID == nil {
				return "", fmt.Errorf("you are not in a room")
			}
			roomID = user.CurrentRoomID
		} else {
			// Strip # prefix if present
			roomArg = stripPrefixes(roomArg)
			
			// Find the room by name
			var room models.Room
			if err := database.DB.Where("name = ?", roomArg).First(&room).Error; err != nil {
				return "", fmt.Errorf("room not found: %s", roomArg)
			}
			roomID = &room.ID
			roomName = room.Name
		}
	} else {
		// No arguments - use current room
		if user.CurrentRoomID == nil {
			return "", fmt.Errorf("you are not in a room")
		}
		roomID = user.CurrentRoomID
	}
	
	// Get room name if not already set
	if roomName == "" {
		var room models.Room
		if err := database.DB.First(&room, *roomID).Error; err == nil {
			roomName = room.Name
		}
	}

	// Fetch users in the specified room
	var users []models.User
	if err := database.DB.Where("current_room_id = ?", roomID).Find(&users).Error; err != nil {
		return "", fmt.Errorf("failed to fetch users: %w", err)
	}

	var result strings.Builder
	if roomName != "" {
		result.WriteString(fmt.Sprintf("Users in #%s:\n", roomName))
	} else {
		result.WriteString("Users in this room:\n")
	}
	
	for _, u := range users {
		displayName := u.Username
		if u.Nickname != "" {
			displayName = fmt.Sprintf("%s (%s)", u.Nickname, u.Username)
		}
		if u.Status != "" {
			displayName = fmt.Sprintf("%s - %s", displayName, u.Status)
		}
		if u.IsAdmin {
			displayName = fmt.Sprintf("%s [Admin]", displayName)
		}
		result.WriteString(fmt.Sprintf("  %s\n", displayName))
	}
	
	return result.String(), nil
}

func handleMentions(user *models.User, args []string) (string, error) {
	var mentions []models.Mention
	if err := database.DB.Preload("Message").Preload("Message.User").
		Where("user_id = ? AND is_read = ?", user.ID, false).
		Find(&mentions).Error; err != nil {
		return "", fmt.Errorf("failed to fetch mentions: %w", err)
	}

	if len(mentions) == 0 {
		return "No unread mentions", nil
	}

	var result strings.Builder
	result.WriteString("Unread mentions:\n")
	for _, mention := range mentions {
		result.WriteString(fmt.Sprintf("  From %s: %s\n",
			mention.Message.User.Username, mention.Message.Content))
	}

	// Mark mentions as read
	database.DB.Model(&models.Mention{}).Where("user_id = ? AND is_read = ?", user.ID, false).
		Update("is_read", true)

	return result.String(), nil
}

func handleBell(user *models.User, args []string) (string, error) {
	user.BellEnabled = !user.BellEnabled
	if err := database.DB.Save(user).Error; err != nil {
		return "", fmt.Errorf("failed to toggle bell: %w", err)
	}

	if user.BellEnabled {
		return "Bell notifications enabled", nil
	}
	return "Bell notifications disabled", nil
}

func handleBan(user *models.User, args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("usage: /ban @username <duration> [reason]")
	}

	username := strings.TrimPrefix(args[0], "@")
	durationStr := args[1]
	reason := ""
	if len(args) > 2 {
		reason = strings.Join(args[2:], " ")
	}

	duration, err := parseDuration(durationStr)
	if err != nil {
		return "", fmt.Errorf("invalid duration: %w", err)
	}

	// Try to find user by username first
	var targetUser models.User
	err = database.DB.Where("username = ?", username).First(&targetUser).Error
	
	// If not found by username, try to find guest by nickname
	if err != nil {
		err = database.DB.Where("nickname = ? AND is_guest = ?", username, true).First(&targetUser).Error
		if err != nil {
			return "", fmt.Errorf("user not found: @%s", username)
		}
	}

	if targetUser.IsAdmin {
		return "", fmt.Errorf("cannot ban an admin")
	}

	expiresAt := time.Now().Add(duration)
	targetUser.IsBanned = true
	targetUser.BanExpiresAt = &expiresAt
	if err := database.DB.Save(&targetUser).Error; err != nil {
		return "", fmt.Errorf("failed to ban user: %w", err)
	}

	ban := models.Ban{
		UserID:     targetUser.ID,
		BannedByID: user.ID,
		Reason:     reason,
		ExpiresAt:  expiresAt,
		IsActive:   true,
	}
	database.DB.Create(&ban)

	userType := "user"
	if targetUser.IsGuest {
		userType = "guest"
	}
	logAction(user, "ban", fmt.Sprintf("Banned %s %s for %s: %s", userType, username, durationStr, reason))

	return fmt.Sprintf("Banned @%s until %s", username, expiresAt.Format("2006-01-02 15:04:05")), nil
}

func handleKick(user *models.User, args []string) (string, error) {
	// Kick is essentially a temporary ban
	return handleBan(user, args)
}

func handleMute(user *models.User, args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("usage: /mute @username <duration> [reason]")
	}

	username := strings.TrimPrefix(args[0], "@")
	durationStr := args[1]
	reason := ""
	if len(args) > 2 {
		reason = strings.Join(args[2:], " ")
	}

	duration, err := parseDuration(durationStr)
	if err != nil {
		return "", fmt.Errorf("invalid duration: %w", err)
	}

	var targetUser models.User
	if err := database.DB.Where("username = ?", username).First(&targetUser).Error; err != nil {
		return "", fmt.Errorf("user not found: @%s", username)
	}

	if targetUser.IsAdmin {
		return "", fmt.Errorf("cannot mute an admin")
	}

	expiresAt := time.Now().Add(duration)
	targetUser.IsMuted = true
	targetUser.MuteExpiresAt = &expiresAt
	if err := database.DB.Save(&targetUser).Error; err != nil {
		return "", fmt.Errorf("failed to mute user: %w", err)
	}

	mute := models.Mute{
		UserID:    targetUser.ID,
		MutedByID: user.ID,
		Reason:    reason,
		ExpiresAt: expiresAt,
		IsActive:  true,
	}
	database.DB.Create(&mute)

	logAction(user, "mute", fmt.Sprintf("Muted %s for %s: %s", username, durationStr, reason))

	return fmt.Sprintf("Muted @%s until %s", username, expiresAt.Format("2006-01-02 15:04:05")), nil
}

func handleUnban(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /unban @username")
	}

	username := strings.TrimPrefix(args[0], "@")
	
	// Try to find user by username first
	var targetUser models.User
	err := database.DB.Where("username = ?", username).First(&targetUser).Error
	
	// If not found by username, try to find guest by nickname
	if err != nil {
		err = database.DB.Where("nickname = ? AND is_guest = ?", username, true).First(&targetUser).Error
		if err != nil {
			return "", fmt.Errorf("user not found: @%s", username)
		}
	}

	targetUser.IsBanned = false
	targetUser.BanExpiresAt = nil
	if err := database.DB.Save(&targetUser).Error; err != nil {
		return "", fmt.Errorf("failed to unban user: %w", err)
	}

	database.DB.Model(&models.Ban{}).Where("user_id = ? AND is_active = ?", targetUser.ID, true).
		Update("is_active", false)

	logAction(user, "unban", fmt.Sprintf("Unbanned %s", username))

	return fmt.Sprintf("Unbanned @%s", username), nil
}

func handleUnmute(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /unmute @username")
	}

	username := strings.TrimPrefix(args[0], "@")
	var targetUser models.User
	if err := database.DB.Where("username = ?", username).First(&targetUser).Error; err != nil {
		return "", fmt.Errorf("user not found: @%s", username)
	}

	targetUser.IsMuted = false
	targetUser.MuteExpiresAt = nil
	if err := database.DB.Save(&targetUser).Error; err != nil {
		return "", fmt.Errorf("failed to unmute user: %w", err)
	}

	database.DB.Model(&models.Mute{}).Where("user_id = ? AND is_active = ?", targetUser.ID, true).
		Update("is_active", false)

	logAction(user, "unmute", fmt.Sprintf("Unmuted %s", username))

	return fmt.Sprintf("Unmuted @%s", username), nil
}

func handleEmote(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /me <action>")
	}

	return "@me " + strings.Join(args, " "), nil
}

// parseDuration parses a colon-separated duration (e.g., "2:30" for 2 minutes 30 seconds)
// or a simple format like "5m", "2h", "30s"
func parseDuration(s string) (time.Duration, error) {
	// Try standard Go duration format first
	if d, err := time.ParseDuration(s); err == nil {
		// Validate duration is between minDuration and maxDuration
		if d < minDuration {
			return 0, fmt.Errorf("duration must be at least %v", minDuration)
		}
		if d > maxDuration {
			return 0, fmt.Errorf("duration must be at most %v", maxDuration)
		}
		return d, nil
	}

	// Try colon-separated format
	if strings.Contains(s, ":") {
		parts := strings.Split(s, ":")
		if len(parts) > 3 {
			return 0, fmt.Errorf("invalid duration format")
		}

		var hours, minutes, seconds int64
		var err error

		switch len(parts) {
		case 2: // MM:SS
			minutes, err = strconv.ParseInt(parts[0], 10, 64)
			if err != nil {
				return 0, err
			}
			seconds, err = strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return 0, err
			}
		case 3: // HH:MM:SS
			hours, err = strconv.ParseInt(parts[0], 10, 64)
			if err != nil {
				return 0, err
			}
			minutes, err = strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return 0, err
			}
			seconds, err = strconv.ParseInt(parts[2], 10, 64)
			if err != nil {
				return 0, err
			}
		}

		duration := time.Duration(hours)*time.Hour +
			time.Duration(minutes)*time.Minute +
			time.Duration(seconds)*time.Second

		if duration < minDuration {
			return 0, fmt.Errorf("duration must be at least %v", minDuration)
		}
		if duration > maxDuration {
			return 0, fmt.Errorf("duration must be at most %v", maxDuration)
		}

		return duration, nil
	}

	return 0, fmt.Errorf("invalid duration format. Use formats like '5m', '2h', or '1:30' (MM:SS)")
}

func logAction(user *models.User, action string, details string) {
	log := models.AuditLog{
		UserID:  user.ID,
		Action:  action,
		Details: details,
	}
	database.DB.Create(&log)
}

func handlePromote(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /promote @username")
	}

	username := strings.TrimPrefix(args[0], "@")
	var targetUser models.User
	if err := database.DB.Where("username = ?", username).First(&targetUser).Error; err != nil {
		return "", fmt.Errorf("user not found: @%s", username)
	}

	if targetUser.IsAdmin {
		return "", fmt.Errorf("@%s is already an admin", username)
	}

	targetUser.IsAdmin = true
	if err := database.DB.Save(&targetUser).Error; err != nil {
		return "", fmt.Errorf("failed to promote user: %w", err)
	}

	logAction(user, "promote", fmt.Sprintf("Promoted %s to admin", username))
	return fmt.Sprintf("@%s has been promoted to admin", username), nil
}

func handleDemote(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /demote @username")
	}

	username := strings.TrimPrefix(args[0], "@")
	var targetUser models.User
	if err := database.DB.Where("username = ?", username).First(&targetUser).Error; err != nil {
		return "", fmt.Errorf("user not found: @%s", username)
	}

	if !targetUser.IsAdmin {
		return "", fmt.Errorf("@%s is not an admin", username)
	}

	// Prevent demoting the only admin (whether it's yourself or someone else)
	var adminCount int64
	database.DB.Model(&models.User{}).Where("is_admin = ?", true).Count(&adminCount)
	if adminCount == 1 {
		return "", fmt.Errorf("cannot demote the only admin")
	}

	targetUser.IsAdmin = false
	if err := database.DB.Save(&targetUser).Error; err != nil {
		return "", fmt.Errorf("failed to demote user: %w", err)
	}

	logAction(user, "demote", fmt.Sprintf("Demoted %s from admin", username))
	return fmt.Sprintf("@%s has been demoted from admin", username), nil
}

func handleListAdmins(user *models.User, args []string) (string, error) {
	var admins []models.User
	if err := database.DB.Where("is_admin = ?", true).Find(&admins).Error; err != nil {
		return "", fmt.Errorf("failed to fetch admins: %w", err)
	}

	if len(admins) == 0 {
		return "No admins found", nil
	}

	var result strings.Builder
	result.WriteString("Admins:\n")
	for i, admin := range admins {
		displayName := admin.Username
		if admin.Nickname != "" {
			displayName = fmt.Sprintf("%s (%s)", admin.Nickname, admin.Username)
		}
		result.WriteString(fmt.Sprintf("%d. %s", i+1, displayName))
		if admin.ID == user.ID {
			result.WriteString(" (you)")
		}
		result.WriteString("\n")
	}
	return result.String(), nil
}

func handleDeleteUser(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /deleteuser @username")
	}

	username := strings.TrimPrefix(args[0], "@")

	// Prevent deleting yourself
	if username == user.Username {
		return "", fmt.Errorf("you cannot delete yourself")
	}

	var targetUser models.User
	if err := database.DB.Where("username = ?", username).First(&targetUser).Error; err != nil {
		return "", fmt.Errorf("user not found: @%s", username)
	}

	// Prevent deleting the only admin
	if targetUser.IsAdmin {
		var adminCount int64
		database.DB.Model(&models.User{}).Where("is_admin = ?", true).Count(&adminCount)
		if adminCount == 1 {
			return "", fmt.Errorf("cannot delete the only admin")
		}
	}

	// Delete user's related data (hard delete)
	database.DB.Unscoped().Where("user_id = ?", targetUser.ID).Delete(&models.Ban{})
	database.DB.Unscoped().Where("banned_by_id = ?", targetUser.ID).Delete(&models.Ban{})
	database.DB.Unscoped().Where("user_id = ?", targetUser.ID).Delete(&models.Mute{})
	database.DB.Unscoped().Where("muted_by_id = ?", targetUser.ID).Delete(&models.Mute{})
	database.DB.Unscoped().Where("user_id = ?", targetUser.ID).Delete(&models.Mention{})
	database.DB.Unscoped().Where("user_id = ?", targetUser.ID).Delete(&models.AuditLog{})
	database.DB.Unscoped().Where("user_id = ?", targetUser.ID).Delete(&models.ChatMessage{})
	database.DB.Unscoped().Where("recipient_id = ?", targetUser.ID).Delete(&models.ChatMessage{})

	// Delete the user (hard delete to allow re-registration with same username)
	if err := database.DB.Unscoped().Delete(&targetUser).Error; err != nil {
		return "", fmt.Errorf("failed to delete user: %w", err)
	}

	logAction(user, "deleteuser", fmt.Sprintf("Deleted user %s", username))
	return fmt.Sprintf("User @%s has been deleted", username), nil
}

func handleNews(user *models.User, args []string) (string, error) {
	var result strings.Builder
	hasContent := false

	// Get unread mentions
	var mentions []models.Mention
	if err := database.DB.Preload("Message").Preload("Message.User").
		Where("user_id = ? AND is_read = ?", user.ID, false).
		Find(&mentions).Error; err == nil && len(mentions) > 0 {
		hasContent = true
		result.WriteString("=== Unread Mentions ===\n")
		for _, mention := range mentions {
			senderName := mention.Message.User.Username
			if mention.Message.User.Nickname != "" {
				senderName = mention.Message.User.Nickname
			}
			result.WriteString(fmt.Sprintf("From %s: %s\n", senderName, mention.Message.Content))
		}
		result.WriteString("\n")

		// Mark mentions as read
		database.DB.Model(&models.Mention{}).Where("user_id = ? AND is_read = ?", user.ID, false).
			Update("is_read", true)
	}

	// Get unread private messages
	var messages []models.ChatMessage
	if err := database.DB.Preload("User").
		Where("recipient_id = ? AND is_private = ? AND created_at > ?", user.ID, true, user.LastSeenAt).
		Order("created_at ASC").
		Find(&messages).Error; err == nil && len(messages) > 0 {
		hasContent = true
		result.WriteString("=== Unread Private Messages ===\n")
		for _, msg := range messages {
			senderName := msg.User.Username
			if msg.User.Nickname != "" {
				senderName = msg.User.Nickname
			}
			result.WriteString(fmt.Sprintf("From %s: %s\n", senderName, msg.Content))
		}
		result.WriteString("\n")
	}

	if !hasContent {
		return "No unread mentions or private messages", nil
	}

	return result.String(), nil
}

func handleReport(user *models.User, args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("usage: /report @username <reason>")
	}

	username := strings.TrimPrefix(args[0], "@")
	reason := strings.Join(args[1:], " ")

	var targetUser models.User
	if err := database.DB.Where("username = ?", username).First(&targetUser).Error; err != nil {
		return "", fmt.Errorf("user not found: @%s", username)
	}

	// Create report
	report := models.Report{
		ReporterID: user.ID,
		ReportedID: targetUser.ID,
		Reason:     reason,
		IsRead:     false,
	}
	if err := database.DB.Create(&report).Error; err != nil {
		return "", fmt.Errorf("failed to create report: %w", err)
	}

	// Save report to file in mounted folder
	reportsDir := getEnv("REPORTS_DIR", "./reports")
	// Create reports directory if it doesn't exist
	if err := ensureDir(reportsDir); err != nil {
		logAction(user, "report", fmt.Sprintf("Reported %s but failed to create report file: %v", username, err))
	} else {
		reportFile := fmt.Sprintf("%s/report@%s.log", reportsDir, username)
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		reportContent := fmt.Sprintf("[%s] Reported by @%s: %s\n", timestamp, user.Username, reason)

		// Append to report file
		f, err := openFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			f.WriteString(reportContent)
			f.Close()
		}
	}

	logAction(user, "report", fmt.Sprintf("Reported %s: %s", username, reason))

	return fmt.Sprintf("Report submitted for @%s", username), nil
}

func handleReports(user *models.User, args []string) (string, error) {
	var reports []models.Report
	if err := database.DB.Preload("Reporter").Preload("Reported").
		Where("is_read = ?", false).
		Order("created_at ASC").
		Find(&reports).Error; err != nil {
		return "", fmt.Errorf("failed to fetch reports: %w", err)
	}

	if len(reports) == 0 {
		return "No unread reports", nil
	}

	var result strings.Builder
	result.WriteString("=== Unread Reports ===\n")
	for i, report := range reports {
		result.WriteString(fmt.Sprintf("%d. @%s reported @%s: %s\n",
			i+1, report.Reporter.Username, report.Reported.Username, report.Reason))
	}
	result.WriteString("\nUse /markreports to mark all as read\n")

	return result.String(), nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func ensureDir(dir string) error {
	return os.MkdirAll(dir, 0755)
}

func openFile(path string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag, perm)
}

func sendToAllAdmins(user *models.User, message string) (string, error) {
	var admins []models.User
	if err := database.DB.Where("is_admin = ?", true).Find(&admins).Error; err != nil {
		return "", fmt.Errorf("failed to fetch admins: %w", err)
	}

	if len(admins) == 0 {
		return "", fmt.Errorf("no admins found")
	}

	count := 0
	for _, admin := range admins {
		if admin.ID == user.ID {
			continue // Don't send to yourself
		}

		chatMsg := models.ChatMessage{
			UserID:      user.ID,
			Content:     message,
			IsPrivate:   true,
			RecipientID: &admin.ID,
		}

		if err := database.DB.Create(&chatMsg).Error; err == nil {
			count++
		}
	}

	if count == 0 {
		return "No other admins to message", nil
	}

	return fmt.Sprintf("Private message sent to %d admin(s)", count), nil
}

func handleMarkReports(user *models.User, args []string) (string, error) {
	result := database.DB.Model(&models.Report{}).Where("is_read = ?", false).Update("is_read", true)
	if result.Error != nil {
		return "", fmt.Errorf("failed to mark reports as read: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return "No unread reports to mark", nil
	}

	return fmt.Sprintf("Marked %d report(s) as read", result.RowsAffected), nil
}

func handleMove(user *models.User, args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("usage: /move @<username> #<room_name>")
	}

	username := stripPrefixes(args[0])
	roomName := stripPrefixes(args[1])

	// Find the target user
	var targetUser models.User
	if err := database.DB.Where("username = ?", username).First(&targetUser).Error; err != nil {
		return "", fmt.Errorf("user not found: %s", username)
	}

	// Find the target room
	var room models.Room
	if err := database.DB.Where("name = ?", roomName).First(&room).Error; err != nil {
		return "", fmt.Errorf("room not found: %s", roomName)
	}

	// Move the user (even if room is hidden, as per requirement)
	targetUser.CurrentRoomID = &room.ID
	if err := database.DB.Save(&targetUser).Error; err != nil {
		return "", fmt.Errorf("failed to move user: %w", err)
	}

	return fmt.Sprintf("Moved @%s to room #%s", username, roomName), nil
}

func handleListUsers(user *models.User, args []string) (string, error) {
	var users []models.User
	if err := database.DB.Order("username").Find(&users).Error; err != nil {
		return "", fmt.Errorf("failed to fetch users: %w", err)
	}

	if len(users) == 0 {
		return "No users found", nil
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("Total users: %d\n\n", len(users)))
	result.WriteString("Username          | Admin | Banned | Muted | Last Seen\n")
	result.WriteString("------------------+-------+--------+-------+-----------\n")

	for _, u := range users {
		admin := " "
		if u.IsAdmin {
			admin = "Y"
		}
		banned := " "
		if u.IsBanned {
			banned = "Y"
		}
		muted := " "
		if u.IsMuted {
			muted = "Y"
		}
		lastSeen := "Never"
		if !u.LastSeenAt.IsZero() {
			lastSeen = u.LastSeenAt.Format("2006-01-02 15:04")
		}
		result.WriteString(fmt.Sprintf("%-17s | %-5s | %-6s | %-5s | %s\n",
			u.Username, admin, banned, muted, lastSeen))
	}

	return result.String(), nil
}

func handleViewUser(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /viewuser @<username>")
	}

	username := stripPrefixes(args[0])

	var targetUser models.User
	if err := database.DB.Preload("CurrentRoom").Where("username = ?", username).First(&targetUser).Error; err != nil {
		return "", fmt.Errorf("user not found: %s", username)
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("=== User Information: %s ===\n\n", targetUser.Username))
	result.WriteString(fmt.Sprintf("ID: %d\n", targetUser.ID))
	result.WriteString(fmt.Sprintf("Username: %s\n", targetUser.Username))
	
	if targetUser.Nickname != "" {
		result.WriteString(fmt.Sprintf("Nickname: %s\n", targetUser.Nickname))
	}
	
	if targetUser.Status != "" {
		result.WriteString(fmt.Sprintf("Status: %s\n", targetUser.Status))
	}

	result.WriteString(fmt.Sprintf("Is Admin: %v\n", targetUser.IsAdmin))
	result.WriteString(fmt.Sprintf("Is Banned: %v\n", targetUser.IsBanned))
	if targetUser.IsBanned && targetUser.BanExpiresAt != nil {
		result.WriteString(fmt.Sprintf("Ban Expires: %s\n", targetUser.BanExpiresAt.Format("2006-01-02 15:04:05")))
	}
	
	result.WriteString(fmt.Sprintf("Is Muted: %v\n", targetUser.IsMuted))
	if targetUser.IsMuted && targetUser.MuteExpiresAt != nil {
		result.WriteString(fmt.Sprintf("Mute Expires: %s\n", targetUser.MuteExpiresAt.Format("2006-01-02 15:04:05")))
	}

	result.WriteString(fmt.Sprintf("Bell Enabled: %v\n", targetUser.BellEnabled))
	
	if targetUser.CurrentRoom != nil {
		result.WriteString(fmt.Sprintf("Current Room: #%s\n", targetUser.CurrentRoom.Name))
	} else {
		result.WriteString("Current Room: None\n")
	}

	if !targetUser.LastSeenAt.IsZero() {
		result.WriteString(fmt.Sprintf("Last Seen: %s\n", targetUser.LastSeenAt.Format("2006-01-02 15:04:05")))
	}

	result.WriteString(fmt.Sprintf("Created: %s\n", targetUser.CreatedAt.Format("2006-01-02 15:04:05")))
	result.WriteString(fmt.Sprintf("Updated: %s\n", targetUser.UpdatedAt.Format("2006-01-02 15:04:05")))

	hasPassword := "No"
	if targetUser.PasswordHash != "" {
		hasPassword = "Yes"
	}
	result.WriteString(fmt.Sprintf("Has Password: %s\n", hasPassword))

	hasSSHKey := "No"
	if targetUser.SSHKey != "" {
		hasSSHKey = "Yes"
	}
	result.WriteString(fmt.Sprintf("Has SSH Key: %s\n", hasSSHKey))

	return result.String(), nil
}

func handleSetPassword(user *models.User, args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("usage: /setpassword #<room_name> <password> (use 'none' to remove)")
	}

	roomName := stripPrefixes(args[0])
	password := args[1]

	// Find the room
	var room models.Room
	if err := database.DB.Where("name = ?", roomName).First(&room).Error; err != nil {
		return "", fmt.Errorf("room not found: %s", roomName)
	}

	// Check if user is the creator or an admin
	if room.CreatorID == nil || (*room.CreatorID != user.ID && !user.IsAdmin) {
		return "", fmt.Errorf("only the room creator or admins can set the password")
	}

	// Handle password removal
	if password == "none" || password == "" {
		room.Password = ""
		if err := database.DB.Save(&room).Error; err != nil {
			return "", fmt.Errorf("failed to remove password: %w", err)
		}
		return fmt.Sprintf("Password removed from room: #%s", roomName), nil
	}

	// Hash the new password
	hashedPassword, err := auth.HashPassword(password)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	room.Password = hashedPassword
	if err := database.DB.Save(&room).Error; err != nil {
		return "", fmt.Errorf("failed to set password: %w", err)
	}

	return fmt.Sprintf("Password set for room: #%s", roomName), nil
}

func handleSignup(user *models.User, args []string) (string, error) {
	// This command is handled interactively in server.go
	// This handler should not be called
	return "", fmt.Errorf("this command requires interactive mode")
}

func handleInactive(user *models.User, args []string) (string, error) {
	var room models.Room
	var roomName string

	if len(args) > 0 {
		// Check specific room
		roomName = stripPrefixes(args[0])
		if err := database.DB.Where("name = ?", roomName).First(&room).Error; err != nil {
			return "", fmt.Errorf("room not found: %s", roomName)
		}
	} else {
		// Check current room
		if user.CurrentRoomID == nil {
			return "", fmt.Errorf("you are not in a room. Usage: /inactive [#room_name]")
		}
		if err := database.DB.First(&room, *user.CurrentRoomID).Error; err != nil {
			return "", fmt.Errorf("could not find current room")
		}
		roomName = room.Name
	}

	// Calculate inactivity time
	if room.LastActivityAt.IsZero() {
		return fmt.Sprintf("Room #%s has no recorded activity", roomName), nil
	}

	inactivity := time.Since(room.LastActivityAt)
	
	// Format inactivity duration
	days := int(inactivity.Hours() / 24)
	hours := int(inactivity.Hours()) % 24
	minutes := int(inactivity.Minutes()) % 60

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%d day(s)", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%d hour(s)", hours))
	}
	if minutes > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%d minute(s)", minutes))
	}

	inactivityStr := strings.Join(parts, ", ")
	lastActivity := room.LastActivityAt.Format("2006-01-02 15:04:05")

	return fmt.Sprintf("Room #%s has been inactive for %s\nLast activity: %s", 
		roomName, inactivityStr, lastActivity), nil
}

func handleSetDefault(user *models.User, args []string) (string, error) {
	if len(args) == 0 {
		// Show current default room
		if user.DefaultRoomID == nil {
			return "You have no default room set. Currently using 'general'.", nil
		}
		var room models.Room
		if err := database.DB.First(&room, *user.DefaultRoomID).Error; err != nil {
			return "Your default room no longer exists. Currently using 'general'.", nil
		}
		return fmt.Sprintf("Your default room is: #%s", room.Name), nil
	}

	roomName := stripPrefixes(args[0])

	// Find the room
	var room models.Room
	if err := database.DB.Where("name = ?", roomName).First(&room).Error; err != nil {
		return "", fmt.Errorf("room not found: %s", roomName)
	}

	// Check if room is hidden and user is not admin
	if room.IsHidden && !user.IsAdmin {
		return "", fmt.Errorf("room not found: %s", roomName)
	}

	// Set as default room
	user.DefaultRoomID = &room.ID
	if err := database.DB.Save(user).Error; err != nil {
		return "", fmt.Errorf("failed to set default room: %v", err)
	}

	return fmt.Sprintf("Default room set to: #%s", roomName), nil
}

func handleBroadcast(user *models.User, args []string) (string, error) {
	// This command is handled interactively in server.go
	// This handler should not be called
	return "", fmt.Errorf("this command requires interactive mode")
}

func handleListBroadcasts(user *models.User, args []string) (string, error) {
	var broadcasts []models.BroadcastMessage
	if err := database.DB.Where("is_sent = ?", false).Order("scheduled_at ASC").Find(&broadcasts).Error; err != nil {
		return "", fmt.Errorf("failed to fetch broadcasts: %v", err)
	}

	if len(broadcasts) == 0 {
		return "No scheduled broadcasts.", nil
	}

	var result strings.Builder
	result.WriteString("Scheduled Broadcasts:\n\n")

	for _, broadcast := range broadcasts {
		result.WriteString(fmt.Sprintf("ID: %d\n", broadcast.ID))
		result.WriteString(fmt.Sprintf("Scheduled: %s\n", broadcast.ScheduledAt.Format("2006-01-02 15:04:05")))
		result.WriteString(fmt.Sprintf("Base Time: %s\n", broadcast.BaseTime.Format("2006-01-02 15:04:05")))
		result.WriteString(fmt.Sprintf("Offset: %d minutes\n", broadcast.MinuteOffset))
		result.WriteString(fmt.Sprintf("Message: %s\n", broadcast.Message))
		result.WriteString("\n")
	}

	return result.String(), nil
}

func handleCancelBroadcast(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /cancelbroadcast <id>")
	}

	broadcastID, err := strconv.ParseUint(args[0], 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid broadcast ID: %s", args[0])
	}

	// Delete the broadcast
	result := database.DB.Delete(&models.BroadcastMessage{}, broadcastID)
	if result.Error != nil {
		return "", fmt.Errorf("failed to cancel broadcast: %v", result.Error)
	}

	if result.RowsAffected == 0 {
		return "", fmt.Errorf("broadcast not found: %d", broadcastID)
	}

	return fmt.Sprintf("Cancelled broadcast ID: %d", broadcastID), nil
}

