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
		Logger: logger.Default.LogMode(logger.Info),
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

	// Migrate models in dependency order
	// First, create tables without foreign key relationships
	err := DB.AutoMigrate(
		&models.Settings{},
	)
	if err != nil {
		return fmt.Errorf("failed to run migrations for settings: %w", err)
	}

	// Create User and Room tables (they have circular FK, but GORM handles this with constraints)
	err = DB.AutoMigrate(
		&models.User{},
		&models.Room{},
	)
	if err != nil {
		return fmt.Errorf("failed to run migrations for users and rooms: %w", err)
	}

	// Then create tables that depend on User and Room
	err = DB.AutoMigrate(
		&models.ChatMessage{},
		&models.Ban{},
		&models.Mute{},
		&models.Mention{},
		&models.AuditLog{},
	)
	if err != nil {
		return fmt.Errorf("failed to run migrations for dependent tables: %w", err)
	}

	// Create default room
	var count int64
	DB.Model(&models.Room{}).Count(&count)
	if count == 0 {
		defaultRoom := models.Room{
			Name:        "general",
			Description: "Default chat room",
			IsPrivate:   false,
		}
		if err := DB.Create(&defaultRoom).Error; err != nil {
			return fmt.Errorf("failed to create default room: %w", err)
		}
		log.Println("Created default 'general' room")
	}

	log.Println("Database migrations completed")
	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
