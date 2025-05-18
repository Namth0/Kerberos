package auth

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/Namhto/kerberos/src/pkg/crypto"
)

// Demande de ticket de service auprès du TGS
func (tgs *TicketGrantingServer) RequestServiceTicket(tgtEncrypted string, authenticatorEncrypted string, serviceID string) (string, error) {
	tgtData, err := crypto.Decrypt(tgs.Key, tgtEncrypted)
	if err != nil {
		return "", fmt.Errorf("ticket TGT invalide: %v", err)
	}

	parts := SplitString(string(tgtData), "|")
	if len(parts) != 5 {
		return "", fmt.Errorf("format de ticket invalide")
	}

	clientID := parts[0]
	sessionKeyBytes, _ := base64.StdEncoding.DecodeString(parts[2])

	authenticatorData, err := crypto.Decrypt(sessionKeyBytes, authenticatorEncrypted)
	if err != nil {
		return "", fmt.Errorf("authenticateur invalide")
	}

	authParts := SplitString(string(authenticatorData), "|")
	if len(authParts) != 2 || authParts[0] != clientID {
		return "", fmt.Errorf("authenticateur non valide pour ce client")
	}

	serviceKey, exists := tgs.ServiceDB[serviceID]
	if !exists {
		return "", fmt.Errorf("service non trouvé")
	}

	serviceSessionKey := crypto.GenerateSessionKey()

	serviceTicket := Ticket{
		ClientID:   clientID,
		ServerID:   serviceID,
		Timestamp:  time.Now(),
		Lifetime:   2 * time.Hour,
		SessionKey: serviceSessionKey,
	}

	ticketData := fmt.Sprintf("%s|%s|%s|%v|%v",
		serviceTicket.ClientID,
		serviceTicket.ServerID,
		base64.StdEncoding.EncodeToString(serviceTicket.SessionKey),
		serviceTicket.Timestamp.Unix(),
		serviceTicket.Lifetime.Seconds())

	ticketEncrypted, err := crypto.Encrypt(serviceKey, []byte(ticketData))
	if err != nil {
		return "", err
	}

	clientData := fmt.Sprintf("%s|%s",
		base64.StdEncoding.EncodeToString(serviceSessionKey),
		ticketEncrypted)

	clientEncrypted, err := crypto.Encrypt(sessionKeyBytes, []byte(clientData))
	if err != nil {
		return "", err
	}

	return clientEncrypted, nil
}
