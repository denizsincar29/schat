package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username       string `gorm:"unique;not null"`
	PasswordHash   string
	SSHKey         string `gorm:"type:text"`
	IsAdmin        bool   `gorm:"default:false"`
	IsGuest        bool   `gorm:"default:false"`
	Nickname       string
	Status         string
	BellEnabled    bool  `gorm:"default:true"`
	CurrentRoomID  *uint `gorm:"constraint:OnDelete:SET NULL;"`
	CurrentRoom    *Room `gorm:"foreignKey:CurrentRoomID"`
	DefaultRoomID  *uint `gorm:"constraint:OnDelete:SET NULL;"`
	DefaultRoom    *Room `gorm:"foreignKey:DefaultRoomID"`
	IsBanned       bool  `gorm:"default:false"`
	BanExpiresAt   *time.Time
	IsMuted        bool `gorm:"default:false"`
	MuteExpiresAt  *time.Time
	LastSeenAt     time.Time
}

type Room struct {
	gorm.Model
	Name            string `gorm:"unique;not null"`
	Description     string
	IsPrivate       bool `gorm:"default:false"`
	IsHidden        bool `gorm:"default:false"`
	IsPermanent     bool `gorm:"default:false"`
	IsGuestRoom     bool `gorm:"default:false"` // Guest rooms allow unauthenticated access
	CreatorID       *uint
	Creator         *User  `gorm:"foreignKey:CreatorID;constraint:OnDelete:SET NULL;"`
	Password        string // Password for passworded rooms (hashed)
	LastActivityAt  time.Time
	MaxParticipants *int       // Maximum number of participants (nil = unlimited)
	ExpiresAt       *time.Time // Room expiration time (nil = never expires)
}

type ChatMessage struct {
	gorm.Model
	UserID      uint
	User        User `gorm:"foreignKey:UserID"`
	RoomID      *uint
	Room        *Room  `gorm:"foreignKey:RoomID"`
	Content     string `gorm:"not null"`
	IsPrivate   bool   `gorm:"default:false"`
	RecipientID *uint
	Recipient   *User `gorm:"foreignKey:RecipientID"`
}

type Ban struct {
	gorm.Model
	UserID     uint
	User       User `gorm:"foreignKey:UserID"`
	BannedByID uint
	BannedBy   User `gorm:"foreignKey:BannedByID"`
	Reason     string
	ExpiresAt  time.Time
	IsActive   bool `gorm:"default:true"`
}

type Mute struct {
	gorm.Model
	UserID    uint
	User      User `gorm:"foreignKey:UserID"`
	MutedByID uint
	MutedBy   User `gorm:"foreignKey:MutedByID"`
	Reason    string
	ExpiresAt time.Time
	IsActive  bool `gorm:"default:true"`
}

type Mention struct {
	gorm.Model
	UserID    uint
	User      User `gorm:"foreignKey:UserID"`
	MessageID uint
	Message   ChatMessage `gorm:"foreignKey:MessageID"`
	IsRead    bool        `gorm:"default:false"`
}

type AuditLog struct {
	gorm.Model
	UserID  uint
	User    User   `gorm:"foreignKey:UserID"`
	Action  string `gorm:"not null"`
	Details string `gorm:"type:text"`
}

type Settings struct {
	gorm.Model
	Key   string `gorm:"unique;not null"`
	Value string
}

type Report struct {
	gorm.Model
	ReporterID uint
	Reporter   User `gorm:"foreignKey:ReporterID"`
	ReportedID uint
	Reported   User   `gorm:"foreignKey:ReportedID"`
	Reason     string `gorm:"type:text"`
	IsRead     bool   `gorm:"default:false"`
}

type Notification struct {
	gorm.Model
	UserID      uint
	User        User   `gorm:"foreignKey:UserID"`
	Type        string `gorm:"not null"` // user_registered, room_created, user_joined_room, user_left_room
	Message     string `gorm:"type:text"`
	IsRead      bool   `gorm:"default:false"`
	RelatedUser *uint  // User who performed the action
	RelatedRoom *uint  // Room related to the action
}

// BroadcastMessage stores scheduled broadcast messages
type BroadcastMessage struct {
	gorm.Model
	CreatorID    uint
	Creator      User      `gorm:"foreignKey:CreatorID"`
	BaseTime     time.Time `gorm:"not null"` // The main event time
	BaseMessage  string    `gorm:"type:text;not null"`
	ScheduledAt  time.Time `gorm:"not null;index"` // When to send this particular message
	Message      string    `gorm:"type:text;not null"`
	IsSent       bool      `gorm:"default:false"`
	MinuteOffset int       // Minutes relative to BaseTime (negative = before, positive = after)
}

