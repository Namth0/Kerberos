package auth

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/Namhto/kerberos/src/pkg/crypto"
)

// Authentification auprès du serveur d'authentification (AS)
func (as *AuthServer) Authenticate(clientID string) (string, string, error) {
	// Vérification que l'utilisateur existe
	clientKey, exists := as.UserDB[clientID]
	if !exists {
		return "", "", fmt.Errorf("utilisateur non trouvé")
	}

	// Génération d'une clé de session pour TGS
	tgsSessionKey := crypto.GenerateSessionKey()

	// Création du ticket TGT (Ticket Granting Ticket)
	tgt := Ticket{
		ClientID:   clientID,
		ServerID:   "tgs",
		Timestamp:  time.Now(),
		Lifetime:   8 * time.Hour,
		SessionKey: tgsSessionKey,
	}

	// Sérialisation et chiffrement du ticket (simplifiée ici)
	tgtData := fmt.Sprintf("%s|%s|%s|%v|%v",
		tgt.ClientID,
		tgt.ServerID,
		base64.StdEncoding.EncodeToString(tgt.SessionKey),
		tgt.Timestamp.Unix(),
		tgt.Lifetime.Seconds())

	// Dans un système réel, nous utiliserions une meilleure sérialisation (protobuf, JSON, etc.)
	tgtEncrypted, err := crypto.Encrypt(as.TGSKey, []byte(tgtData)) // Use the key from instance
	if err != nil {
		return "", "", err
	}

	// Données à envoyer au client, chiffrées avec sa clé
	clientData := fmt.Sprintf("%s|%s",
		base64.StdEncoding.EncodeToString(tgsSessionKey),
		tgtEncrypted)

	clientEncrypted, err := crypto.Encrypt(clientKey, []byte(clientData))
	if err != nil {
		return "", "", err
	}

	return clientEncrypted, tgtEncrypted, nil
}
