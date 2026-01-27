package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/denizsincar29/schat/internal/database"
	"github.com/denizsincar29/schat/internal/models"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh"
)

const (
	saltSize = 16
	keySize  = 32
	timeCost = 1
	memory   = 64 * 1024
	threads  = 4
)

var (
	// Reserved usernames that cannot be used for new accounts
	reservedUsernames = []string{"me", "admin", "help", "system", "root", "all", "everyone", "here"}
)

// HashPassword creates a secure hash of the password
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, keySize)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("%s$%s", b64Salt, b64Hash), nil
}

// VerifyPassword checks if the password matches the hash
func VerifyPassword(password, hashedPassword string) bool {
	parts := strings.Split(hashedPassword, "$")
	if len(parts) != 2 {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	computedHash := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, keySize)

	return subtle.ConstantTimeCompare(hash, computedHash) == 1
}

// AuthenticateUser authenticates a user with username and password or SSH key
func AuthenticateUser(username string, password string, publicKey ssh.PublicKey) (*models.User, error) {
	var user models.User

	if err := database.DB.Where("username = ?", username).First(&user).Error; err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Check if user is banned
	if user.IsBanned && user.BanExpiresAt != nil && user.BanExpiresAt.After(time.Now()) {
		return nil, fmt.Errorf("user is banned until %s", user.BanExpiresAt.Format("2006-01-02 15:04:05"))
	}

	// Try SSH key authentication first
	if publicKey != nil && user.SSHKey != "" {
		authorizedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(user.SSHKey))
		if err == nil {
			if subtle.ConstantTimeCompare(publicKey.Marshal(), authorizedKey.Marshal()) == 1 {
				return &user, nil
			}
		}
	}

	// Try password authentication
	if password != "" && user.PasswordHash != "" {
		if VerifyPassword(password, user.PasswordHash) {
			return &user, nil
		}
	}

	return nil, fmt.Errorf("authentication failed")
}

// CreateUser creates a new user
func CreateUser(username string, password string, sshKey string, isAdmin bool) (*models.User, error) {
	// Validate username - check for reserved names
	usernameLower := strings.ToLower(username)
	for _, reserved := range reservedUsernames {
		if usernameLower == reserved {
			return nil, fmt.Errorf("username '%s' is reserved and cannot be used", username)
		}
	}

	// Check for minimum length
	if len(username) < 2 {
		return nil, fmt.Errorf("username must be at least 2 characters long")
	}

	// Check for maximum length
	if len(username) > 32 {
		return nil, fmt.Errorf("username must be at most 32 characters long")
	}

	var existingUser models.User
	if err := database.DB.Where("username = ?", username).First(&existingUser).Error; err == nil {
		return nil, fmt.Errorf("username already exists")
	}

	user := models.User{
		Username:    username,
		IsAdmin:     isAdmin,
		BellEnabled: true,
	}

	if password != "" {
		hashedPassword, err := HashPassword(password)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		user.PasswordHash = hashedPassword
	}

	if sshKey != "" {
		// Validate SSH key format
		_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshKey))
		if err != nil {
			return nil, fmt.Errorf("invalid SSH key format: %w", err)
		}
		user.SSHKey = sshKey
	}

	if user.PasswordHash == "" && user.SSHKey == "" {
		return nil, fmt.Errorf("either password or SSH key must be provided")
	}

	if err := database.DB.Create(&user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &user, nil
}
