package commands

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/denizsincar29/schat/internal/database"
	"github.com/denizsincar29/schat/internal/models"
)

const (
	minDuration = 2 * time.Minute
	maxDuration = 24 * time.Hour
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
		Usage:       "/join <room_name>",
		Handler:     handleJoin,
	})

	registerCommand(&Command{
		Name:        "create",
		Aliases:     []string{"cr", "createroom"},
		Description: "Create a new room",
		Usage:       "/create <room_name> [description]",
		Handler:     handleCreate,
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
		Usage:       "/permanent <room_name>",
		Handler:     handlePermanent,
		AdminOnly:   true,
	})

	registerCommand(&Command{
		Name:        "hide",
		Aliases:     []string{"hideroom"},
		Description: "Hide a room from non-admins (admin only)",
		Usage:       "/hide <room_name>",
		Handler:     handleHide,
		AdminOnly:   true,
	})

	registerCommand(&Command{
		Name:        "unhide",
		Aliases:     []string{"unhideroom", "show"},
		Description: "Unhide a room (admin only)",
		Usage:       "/unhide <room_name>",
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
		Description: "List users in current room",
		Usage:       "/users",
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
}

func registerCommand(cmd *Command) {
	Commands[cmd.Name] = cmd
	for _, alias := range cmd.Aliases {
		Commands[alias] = cmd
	}
}

func GetCommand(name string) *Command {
	return Commands[name]
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
				topicTitle := topic.Name
				if len(topic.Name) > 0 {
					topicTitle = strings.ToUpper(string(topic.Name[0])) + topic.Name[1:]
				}
				result.WriteString(fmt.Sprintf("=== %s Commands ===\n", topicTitle))
				
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
		
		topicTitle := topic.Name
		if len(topic.Name) > 0 {
			topicTitle = strings.ToUpper(string(topic.Name[0])) + topic.Name[1:]
		}
		result.WriteString(fmt.Sprintf("=== %s ===\n", topicTitle))
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
		
		result.WriteString(fmt.Sprintf("%s %s - %s%s\n", marker, room.Name, room.Description, indicators))
	}
	return result.String(), nil
}

func handleJoin(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /join <room_name>")
	}

	roomName := args[0]
	var room models.Room
	if err := database.DB.Where("name = ?", roomName).First(&room).Error; err != nil {
		return "", fmt.Errorf("room not found: %s", roomName)
	}
	
	// Check if room is hidden and user is not admin
	if room.IsHidden && !user.IsAdmin {
		return "", fmt.Errorf("room not found: %s", roomName)
	}

	user.CurrentRoomID = &room.ID
	if err := database.DB.Save(user).Error; err != nil {
		return "", fmt.Errorf("failed to join room: %w", err)
	}

	return fmt.Sprintf("Joined room: %s", room.Name), nil
}

func handleCreate(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /create <room_name> [description]")
	}

	roomName := args[0]
	description := ""
	if len(args) > 1 {
		description = strings.Join(args[1:], " ")
	}

	creatorID := user.ID
	room := models.Room{
		Name:        roomName,
		Description: description,
		CreatorID:   &creatorID,
	}

	if err := database.DB.Create(&room).Error; err != nil {
		return "", fmt.Errorf("failed to create room: %w", err)
	}

	return fmt.Sprintf("Created room: %s", roomName), nil
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
		return "", fmt.Errorf("usage: /permanent <room_name>")
	}
	
	roomName := args[0]
	var room models.Room
	if err := database.DB.Where("name = ?", roomName).First(&room).Error; err != nil {
		return "", fmt.Errorf("room not found: %s", roomName)
	}
	
	if room.IsPermanent {
		return "", fmt.Errorf("room %s is already permanent", roomName)
	}
	
	room.IsPermanent = true
	if err := database.DB.Save(&room).Error; err != nil {
		return "", fmt.Errorf("failed to make room permanent: %w", err)
	}
	
	logAction(user, "permanent", fmt.Sprintf("Made room %s permanent", roomName))
	return fmt.Sprintf("Room %s is now permanent", roomName), nil
}

func handleHide(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /hide <room_name>")
	}
	
	roomName := args[0]
	var room models.Room
	if err := database.DB.Where("name = ?", roomName).First(&room).Error; err != nil {
		return "", fmt.Errorf("room not found: %s", roomName)
	}
	
	if room.IsHidden {
		return "", fmt.Errorf("room %s is already hidden", roomName)
	}
	
	room.IsHidden = true
	if err := database.DB.Save(&room).Error; err != nil {
		return "", fmt.Errorf("failed to hide room: %w", err)
	}
	
	logAction(user, "hide", fmt.Sprintf("Hid room %s", roomName))
	return fmt.Sprintf("Room %s is now hidden", roomName), nil
}

func handleUnhide(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /unhide <room_name>")
	}
	
	roomName := args[0]
	var room models.Room
	if err := database.DB.Where("name = ?", roomName).First(&room).Error; err != nil {
		return "", fmt.Errorf("room not found: %s", roomName)
	}
	
	if !room.IsHidden {
		return "", fmt.Errorf("room %s is not hidden", roomName)
	}
	
	room.IsHidden = false
	if err := database.DB.Save(&room).Error; err != nil {
		return "", fmt.Errorf("failed to unhide room: %w", err)
	}
	
	logAction(user, "unhide", fmt.Sprintf("Unhid room %s", roomName))
	return fmt.Sprintf("Room %s is now visible", roomName), nil
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
	if user.CurrentRoomID == nil {
		return "", fmt.Errorf("you are not in a room")
	}

	var users []models.User
	if err := database.DB.Where("current_room_id = ?", user.CurrentRoomID).Find(&users).Error; err != nil {
		return "", fmt.Errorf("failed to fetch users: %w", err)
	}

	var result strings.Builder
	result.WriteString("Users in this room:\n")
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

	var targetUser models.User
	if err := database.DB.Where("username = ?", username).First(&targetUser).Error; err != nil {
		return "", fmt.Errorf("user not found: @%s", username)
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

	logAction(user, "ban", fmt.Sprintf("Banned %s for %s: %s", username, durationStr, reason))

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
	var targetUser models.User
	if err := database.DB.Where("username = ?", username).First(&targetUser).Error; err != nil {
		return "", fmt.Errorf("user not found: @%s", username)
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
