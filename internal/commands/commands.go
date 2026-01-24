package commands

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/denizsincar29/schat/internal/database"
	"github.com/denizsincar29/schat/internal/models"
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
		Name:        "me",
		Aliases:     []string{"emote", "action"},
		Description: "Send an emote action",
		Usage:       "/me <action> or text @me more text",
		Handler:     handleEmote,
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
	if len(args) > 0 {
		cmd := GetCommand(args[0])
		if cmd == nil {
			return "", fmt.Errorf("command not found: %s", args[0])
		}
		aliases := strings.Join(cmd.Aliases, ", ")
		return fmt.Sprintf("%s: %s\nUsage: %s\nAliases: %s", cmd.Name, cmd.Description, cmd.Usage, aliases), nil
	}

	var result strings.Builder
	result.WriteString("Available commands:\n")
	for _, cmd := range GetAllCommands() {
		if cmd.AdminOnly && !user.IsAdmin {
			continue
		}
		result.WriteString(fmt.Sprintf("  /%s - %s\n", cmd.Name, cmd.Description))
	}
	result.WriteString("\nType /help <command> for more information")
	return result.String(), nil
}

func handleRooms(user *models.User, args []string) (string, error) {
	var rooms []models.Room
	if err := database.DB.Find(&rooms).Error; err != nil {
		return "", fmt.Errorf("failed to fetch rooms: %w", err)
	}

	var result strings.Builder
	result.WriteString("Available rooms:\n")
	for _, room := range rooms {
		marker := " "
		if user.CurrentRoomID != nil && *user.CurrentRoomID == room.ID {
			marker = "*"
		}
		result.WriteString(fmt.Sprintf("%s %s - %s\n", marker, room.Name, room.Description))
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

	room := models.Room{
		Name:        roomName,
		Description: description,
		CreatorID:   user.ID,
	}

	if err := database.DB.Create(&room).Error; err != nil {
		return "", fmt.Errorf("failed to create room: %w", err)
	}

	return fmt.Sprintf("Created room: %s", roomName), nil
}

func handlePrivateMessage(user *models.User, args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("usage: /msg <username> <message>")
	}

	username := args[0]
	message := strings.Join(args[1:], " ")

	var recipient models.User
	if err := database.DB.Where("username = ?", username).First(&recipient).Error; err != nil {
		return "", fmt.Errorf("user not found: %s", username)
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

	return fmt.Sprintf("Private message sent to %s", username), nil
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
		return "", fmt.Errorf("usage: /ban <username> <duration> [reason]")
	}

	username := args[0]
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
		return "", fmt.Errorf("user not found: %s", username)
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

	return fmt.Sprintf("Banned %s until %s", username, expiresAt.Format("2006-01-02 15:04:05")), nil
}

func handleKick(user *models.User, args []string) (string, error) {
	// Kick is essentially a temporary ban
	return handleBan(user, args)
}

func handleMute(user *models.User, args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("usage: /mute <username> <duration> [reason]")
	}

	username := args[0]
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
		return "", fmt.Errorf("user not found: %s", username)
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
		UserID:     targetUser.ID,
		MutedByID:  user.ID,
		Reason:     reason,
		ExpiresAt:  expiresAt,
		IsActive:   true,
	}
	database.DB.Create(&mute)

	logAction(user, "mute", fmt.Sprintf("Muted %s for %s: %s", username, durationStr, reason))

	return fmt.Sprintf("Muted %s until %s", username, expiresAt.Format("2006-01-02 15:04:05")), nil
}

func handleUnban(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /unban <username>")
	}

	username := args[0]
	var targetUser models.User
	if err := database.DB.Where("username = ?", username).First(&targetUser).Error; err != nil {
		return "", fmt.Errorf("user not found: %s", username)
	}

	targetUser.IsBanned = false
	targetUser.BanExpiresAt = nil
	if err := database.DB.Save(&targetUser).Error; err != nil {
		return "", fmt.Errorf("failed to unban user: %w", err)
	}

	database.DB.Model(&models.Ban{}).Where("user_id = ? AND is_active = ?", targetUser.ID, true).
		Update("is_active", false)

	logAction(user, "unban", fmt.Sprintf("Unbanned %s", username))

	return fmt.Sprintf("Unbanned %s", username), nil
}

func handleUnmute(user *models.User, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: /unmute <username>")
	}

	username := args[0]
	var targetUser models.User
	if err := database.DB.Where("username = ?", username).First(&targetUser).Error; err != nil {
		return "", fmt.Errorf("user not found: %s", username)
	}

	targetUser.IsMuted = false
	targetUser.MuteExpiresAt = nil
	if err := database.DB.Save(&targetUser).Error; err != nil {
		return "", fmt.Errorf("failed to unmute user: %w", err)
	}

	database.DB.Model(&models.Mute{}).Where("user_id = ? AND is_active = ?", targetUser.ID, true).
		Update("is_active", false)

	logAction(user, "unmute", fmt.Sprintf("Unmuted %s", username))

	return fmt.Sprintf("Unmuted %s", username), nil
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
		// Validate duration is between 2 minutes and 24 hours
		if d < 2*time.Minute {
			return 0, fmt.Errorf("duration must be at least 2 minutes")
		}
		if d > 24*time.Hour {
			return 0, fmt.Errorf("duration must be at most 24 hours")
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

		if duration < 2*time.Minute {
			return 0, fmt.Errorf("duration must be at least 2 minutes")
		}
		if duration > 24*time.Hour {
			return 0, fmt.Errorf("duration must be at most 24 hours")
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
