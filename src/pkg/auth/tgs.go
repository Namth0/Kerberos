package auth

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/Namhto/kerberos/src/pkg/crypto"
)

// Demande de ticket de service auprès du TGS
func (tgs *TicketGrantingServer) RequestServiceTicket(tgtEncrypted string, authenticatorEncrypted string, serviceID string) (string, error) {
	// Déchiffrer le TGT
	tgtData, err := crypto.Decrypt(tgs.Key, tgtEncrypted) // Use the key from instance
	if err != nil {
		return "", fmt.Errorf("ticket TGT invalide: %v", err)
	}

	// Parsing du TGT (simplifié)
	parts := SplitString(string(tgtData), "|")
	if len(parts) != 5 {
		return "", fmt.Errorf("format de ticket invalide")
	}

	clientID := parts[0]
	sessionKeyBytes, _ := base64.StdEncoding.DecodeString(parts[2])

	// Vérifier l'authenticateur
	authenticatorData, err := crypto.Decrypt(sessionKeyBytes, authenticatorEncrypted)
	if err != nil {
		return "", fmt.Errorf("authenticateur invalide")
	}

	// Parsing de l'authenticateur (simplifié)
	authParts := SplitString(string(authenticatorData), "|")
	if len(authParts) != 2 || authParts[0] != clientID {
		return "", fmt.Errorf("authenticateur non valide pour ce client")
	}

	// Vérifier que le service existe
	serviceKey, exists := tgs.ServiceDB[serviceID]
	if !exists {
		return "", fmt.Errorf("service non trouvé")
	}

	// Générer une clé de session pour le service
	serviceSessionKey := crypto.GenerateSessionKey()

	// Créer un ticket de service
	serviceTicket := Ticket{
		ClientID:   clientID,
		ServerID:   serviceID,
		Timestamp:  time.Now(),
		Lifetime:   2 * time.Hour,
		SessionKey: serviceSessionKey,
	}

	// Sérialisation du ticket (simplifiée)
	ticketData := fmt.Sprintf("%s|%s|%s|%v|%v",
		serviceTicket.ClientID,
		serviceTicket.ServerID,
		base64.StdEncoding.EncodeToString(serviceTicket.SessionKey),
		serviceTicket.Timestamp.Unix(),
		serviceTicket.Lifetime.Seconds())

	// Chiffrer le ticket avec la clé du service
	ticketEncrypted, err := crypto.Encrypt(serviceKey, []byte(ticketData))
	if err != nil {
		return "", err
	}

	// Données à envoyer au client, chiffrées avec la clé de session TGS
	clientData := fmt.Sprintf("%s|%s",
		base64.StdEncoding.EncodeToString(serviceSessionKey),
		ticketEncrypted)

	clientEncrypted, err := crypto.Encrypt(sessionKeyBytes, []byte(clientData))
	if err != nil {
		return "", err
	}

	return clientEncrypted, nil
}
