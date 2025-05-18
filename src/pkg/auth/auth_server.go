package auth

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/Namhto/kerberos/src/pkg/crypto"
)

// Authentification auprès du serveur d'authentification (AS)
func (as *AuthServer) Authenticate(clientID string) (string, string, error) {
	clientKey, exists := as.UserDB[clientID]
	if !exists {
		return "", "", fmt.Errorf("utilisateur non trouvé")
	}
	
	tgsSessionKey := crypto.GenerateSessionKey()

	tgt := Ticket{
		ClientID:   clientID,
		ServerID:   "tgs",
		Timestamp:  time.Now(),
		Lifetime:   8 * time.Hour,
		SessionKey: tgsSessionKey,
	}

	tgtData := fmt.Sprintf("%s|%s|%s|%v|%v",
		tgt.ClientID,
		tgt.ServerID,
		base64.StdEncoding.EncodeToString(tgt.SessionKey),
		tgt.Timestamp.Unix(),
		tgt.Lifetime.Seconds())

	tgtEncrypted, err := crypto.Encrypt(as.TGSKey, []byte(tgtData)) 
	if err != nil {
		return "", "", err
	}
	
	clientData := fmt.Sprintf("%s|%s",
		base64.StdEncoding.EncodeToString(tgsSessionKey),
		tgtEncrypted)

	clientEncrypted, err := crypto.Encrypt(clientKey, []byte(clientData))
	if err != nil {
		return "", "", err
	}

	return clientEncrypted, tgtEncrypted, nil
}
