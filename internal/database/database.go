package database

import (
	"fmt"
	"log"
	"os"

	"github.com/denizsincar29/schat/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// Init initializes the database connection
func Init() error {
	host := getEnv("DB_HOST", "localhost")
	port := getEnv("DB_PORT", "5432")
	user := getEnv("DB_USER", "postgres")
	password := getEnv("DB_PASSWORD", "postgres")
	dbname := getEnv("DB_NAME", "schat")
	sslmode := getEnv("DB_SSLMODE", "disable")

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode)

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger:                                   logger.Default.LogMode(logger.Info),
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	log.Println("Database connection established")
	return nil
}

// Migrate runs database migrations
func Migrate() error {
	log.Println("Running database migrations...")

	// Migrate tables in dependency order
	// With DisableForeignKeyConstraintWhenMigrating=true, GORM won't create FK constraints,
	// allowing us to migrate tables with circular dependencies

	// Settings table (no dependencies)
	if err := DB.AutoMigrate(&models.Settings{}); err != nil {
		return fmt.Errorf("failed to migrate settings: %w", err)
	}

	// User and Room tables have circular dependency (User.CurrentRoom <-> Room.Creator)
	// Migrate them in sequence - User first, then Room
	if err := DB.AutoMigrate(&models.User{}, &models.Room{}); err != nil {
		return fmt.Errorf("failed to migrate users and rooms: %w", err)
	}

	// Migrate remaining tables that depend on User and/or Room
	if err := DB.AutoMigrate(
		&models.ChatMessage{},
		&models.Ban{},
		&models.Mute{},
		&models.Mention{},
		&models.AuditLog{},
		&models.Report{},
		&models.Notification{},
		&models.BroadcastMessage{},
	); err != nil {
		return fmt.Errorf("failed to migrate dependent tables: %w", err)
	}

	// Create default rooms if they don't exist
	if err := createDefaultRooms(); err != nil {
		return fmt.Errorf("failed to create default rooms: %w", err)
	}

	log.Println("Database migrations completed")

	// Clean up soft-deleted users to prevent unique constraint violations
	if err := cleanupSoftDeletedUsers(); err != nil {
		log.Printf("Warning: failed to cleanup soft-deleted users: %v", err)
		// Don't return error - this is a cleanup operation, not critical for startup
	}

	return nil
}

// cleanupSoftDeletedUsers removes soft-deleted users and their related data
// This prevents unique constraint violations when trying to re-register with deleted usernames
func cleanupSoftDeletedUsers() error {
	log.Println("Cleaning up soft-deleted users...")

	// Find all soft-deleted users (where deleted_at IS NOT NULL)
	var softDeletedUsers []models.User
	if err := DB.Unscoped().Where("deleted_at IS NOT NULL").Find(&softDeletedUsers).Error; err != nil {
		return fmt.Errorf("failed to find soft-deleted users: %w", err)
	}

	if len(softDeletedUsers) == 0 {
		log.Println("No soft-deleted users found")
		return nil
	}

	log.Printf("Found %d soft-deleted user(s), cleaning up...", len(softDeletedUsers))

	// Delete each user's related data and the user record (hard delete)
	for _, user := range softDeletedUsers {
		// Delete user's related data (hard delete)
		DB.Unscoped().Where("user_id = ?", user.ID).Delete(&models.Ban{})
		DB.Unscoped().Where("banned_by_id = ?", user.ID).Delete(&models.Ban{})
		DB.Unscoped().Where("user_id = ?", user.ID).Delete(&models.Mute{})
		DB.Unscoped().Where("muted_by_id = ?", user.ID).Delete(&models.Mute{})
		DB.Unscoped().Where("user_id = ?", user.ID).Delete(&models.Mention{})
		DB.Unscoped().Where("user_id = ?", user.ID).Delete(&models.AuditLog{})
		DB.Unscoped().Where("user_id = ?", user.ID).Delete(&models.ChatMessage{})
		DB.Unscoped().Where("recipient_id = ?", user.ID).Delete(&models.ChatMessage{})

		// Delete the user (hard delete)
		if err := DB.Unscoped().Delete(&user).Error; err != nil {
			log.Printf("Warning: failed to hard delete user %s (ID: %d): %v", user.Username, user.ID, err)
			continue
		}

		log.Printf("Cleaned up soft-deleted user: %s (ID: %d)", user.Username, user.ID)
	}

	log.Printf("Successfully cleaned up %d soft-deleted user(s)", len(softDeletedUsers))
	return nil
}

// createDefaultRooms creates the default preserved rooms (general, guests, dev)
func createDefaultRooms() error {
	log.Println("Setting up default rooms...")

	// Define default rooms
	defaultRooms := []models.Room{
		{
			Name:        "general",
			Description: "Default chat room",
			IsPrivate:   false,
			IsHidden:    false,
			IsPermanent: true,
		},
		{
			Name:        "dev",
			Description: "Developer room (hidden)",
			IsPrivate:   false,
			IsHidden:    true,
			IsPermanent: true,
		},
	}

	// Create or update each room
	for _, room := range defaultRooms {
		var existingRoom models.Room
		result := DB.Where("name = ?", room.Name).First(&existingRoom)

		if result.Error == nil {
			// Room exists, update its properties
			DB.Model(&existingRoom).Updates(map[string]interface{}{
				"description":  room.Description,
				"is_private":   room.IsPrivate,
				"is_hidden":    room.IsHidden,
				"is_permanent": room.IsPermanent,
			})
			log.Printf("Updated room: %s", room.Name)
		} else {
			// Room doesn't exist, create it
			if err := DB.Create(&room).Error; err != nil {
				return fmt.Errorf("failed to create room %s: %w", room.Name, err)
			}
			log.Printf("Created room: %s", room.Name)
		}
	}

	log.Println("Default rooms setup completed")
	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
