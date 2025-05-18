package auth

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/Namhto/kerberos/src/pkg/crypto"
)

// Authentification du client auprès d'un service
func (s *Service) Authenticate(serviceTicketEncrypted string, authenticatorEncrypted string) (bool, error) {
	ticketData, err := crypto.Decrypt(s.Key, serviceTicketEncrypted)
	if err != nil {
		return false, fmt.Errorf("ticket de service invalide")
	}

	parts := SplitString(string(ticketData), "|")
	if len(parts) != 5 || parts[1] != s.ID {
		return false, fmt.Errorf("ticket non valide pour ce service")
	}

	clientID := parts[0]
	sessionKeyBytes, _ := base64.StdEncoding.DecodeString(parts[2])

	authenticatorData, err := crypto.Decrypt(sessionKeyBytes, authenticatorEncrypted)
	if err != nil {
		return false, fmt.Errorf("authenticateur invalide")
	}

	authParts := SplitString(string(authenticatorData), "|")
	if len(authParts) != 2 || authParts[0] != clientID {
		return false, fmt.Errorf("authenticateur non valide pour ce client")
	}

	authTimestamp, _ := time.Parse(time.RFC3339, authParts[1])
	if time.Since(authTimestamp) > 5*time.Minute {
		return false, fmt.Errorf("authenticateur expiré")
	}

	return true, nil
}
