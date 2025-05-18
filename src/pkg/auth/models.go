package auth

import (
	"time"
)

// Structure représentant un ticket Kerberos
type Ticket struct {
	ClientID      string
	ServerID      string
	Address       string
	Timestamp     time.Time
	Lifetime      time.Duration
	SessionKey    []byte
	Authenticator *Authenticator
}

// Structure représentant un authenticateur
type Authenticator struct {
	ClientID  string
	Timestamp time.Time
}

// Structure du serveur d'authentification (AS)
type AuthServer struct {
	UserDB map[string][]byte 
	TGSKey []byte            
}

// Structure du serveur de tickets (TGS)
type TicketGrantingServer struct {
	Key       []byte
	ServiceDB map[string][]byte 
}

// Structure du client
type Client struct {
	ID      string
	Key     []byte
	Address string
}

// Structure du service
type Service struct {
	ID  string
	Key []byte
}
