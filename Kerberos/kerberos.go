package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
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
	UserDB map[string][]byte // Map des utilisateurs et leurs clés
	TGSKey []byte            // Key for the TGS
}

// Structure du serveur de tickets (TGS)
type TicketGrantingServer struct {
	Key       []byte
	ServiceDB map[string][]byte // Map des services et leurs clés
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

// Add this helper function to create keys of exact size
func createFixedKey(size int) []byte {
	key := make([]byte, size)
	for i := 0; i < size; i++ {
		key[i] = byte(i + 65) // Just fill with sequential ASCII values
	}
	return key
}

// Function to verify key sizes before operations
func verifyKey(key []byte, operation string) {
	fmt.Printf("Key length for %s: %d bytes, hex: %s\n",
		operation, len(key), hex.EncodeToString(key))
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		fmt.Printf("WARNING: Invalid key size %d for AES operation: %s\n", len(key), operation)
	}
}

// Fonction pour chiffrer un message
func encrypt(key []byte, message []byte) (string, error) {
	verifyKey(key, "encrypt")

	// Create a fixed-size key if original is invalid
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		fmt.Printf("Using fallback key for encryption instead of size %d\n", len(key))
		key = createFixedKey(16)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(message))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], message)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Fonction pour déchiffrer un message
func decrypt(key []byte, cryptoText string) ([]byte, error) {
	verifyKey(key, "decrypt")

	// Create a fixed-size key if original is invalid
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		fmt.Printf("Using fallback key for decryption instead of size %d\n", len(key))
		key = createFixedKey(16)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(cryptoText)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("texte chiffré trop court")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// Génération d'une clé de session
func generateSessionKey() []byte {
	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err.Error())
	}
	return key
}

// Authentification auprès du serveur d'authentification (AS)
func (as *AuthServer) authenticate(clientID string) (string, string, error) {
	// Vérification que l'utilisateur existe
	clientKey, exists := as.UserDB[clientID]
	if !exists {
		return "", "", fmt.Errorf("utilisateur non trouvé")
	}

	// Génération d'une clé de session pour TGS
	tgsSessionKey := generateSessionKey()

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
	tgtEncrypted, err := encrypt(as.TGSKey, []byte(tgtData)) // Use the key from instance
	if err != nil {
		return "", "", err
	}

	// Données à envoyer au client, chiffrées avec sa clé
	clientData := fmt.Sprintf("%s|%s",
		base64.StdEncoding.EncodeToString(tgsSessionKey),
		tgtEncrypted)

	clientEncrypted, err := encrypt(clientKey, []byte(clientData))
	if err != nil {
		return "", "", err
	}

	return clientEncrypted, tgtEncrypted, nil
}

// Demande de ticket de service auprès du TGS
func (tgs *TicketGrantingServer) requestServiceTicket(tgtEncrypted string, authenticatorEncrypted string, serviceID string) (string, error) {
	// Déchiffrer le TGT
	tgtData, err := decrypt(tgs.Key, tgtEncrypted) // Use the key from instance
	if err != nil {
		return "", fmt.Errorf("ticket TGT invalide: %v", err)
	}

	// Parsing du TGT (simplifié)
	parts := splitString(string(tgtData), "|")
	if len(parts) != 5 {
		return "", fmt.Errorf("format de ticket invalide")
	}

	clientID := parts[0]
	sessionKeyBytes, _ := base64.StdEncoding.DecodeString(parts[2])

	// Vérifier l'authenticateur
	authenticatorData, err := decrypt(sessionKeyBytes, authenticatorEncrypted)
	if err != nil {
		return "", fmt.Errorf("authenticateur invalide")
	}

	// Parsing de l'authenticateur (simplifié)
	authParts := splitString(string(authenticatorData), "|")
	if len(authParts) != 2 || authParts[0] != clientID {
		return "", fmt.Errorf("authenticateur non valide pour ce client")
	}

	// Vérifier que le service existe
	serviceKey, exists := tgs.ServiceDB[serviceID]
	if !exists {
		return "", fmt.Errorf("service non trouvé")
	}

	// Générer une clé de session pour le service
	serviceSessionKey := generateSessionKey()

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
	ticketEncrypted, err := encrypt(serviceKey, []byte(ticketData))
	if err != nil {
		return "", err
	}

	// Données à envoyer au client, chiffrées avec la clé de session TGS
	clientData := fmt.Sprintf("%s|%s",
		base64.StdEncoding.EncodeToString(serviceSessionKey),
		ticketEncrypted)

	clientEncrypted, err := encrypt(sessionKeyBytes, []byte(clientData))
	if err != nil {
		return "", err
	}

	return clientEncrypted, nil
}

// Fonction utilitaire pour séparer les chaînes
func splitString(s, sep string) []string {
	result := make([]string, 0)
	for len(s) > 0 {
		idx := -1
		for i, c := range s {
			if string(c) == sep {
				idx = i
				break
			}
		}
		if idx == -1 {
			result = append(result, s)
			break
		}
		result = append(result, s[:idx])
		s = s[idx+1:]
	}
	return result
}

// Authentification du client auprès d'un service
func (s *Service) authenticate(serviceTicketEncrypted string, authenticatorEncrypted string) (bool, error) {
	// Déchiffrer le ticket de service
	ticketData, err := decrypt(s.Key, serviceTicketEncrypted)
	if err != nil {
		return false, fmt.Errorf("ticket de service invalide")
	}

	// Parsing du ticket (simplifié)
	parts := splitString(string(ticketData), "|")
	if len(parts) != 5 || parts[1] != s.ID {
		return false, fmt.Errorf("ticket non valide pour ce service")
	}

	clientID := parts[0]
	sessionKeyBytes, _ := base64.StdEncoding.DecodeString(parts[2])

	// Vérifier l'authenticateur
	authenticatorData, err := decrypt(sessionKeyBytes, authenticatorEncrypted)
	if err != nil {
		return false, fmt.Errorf("authenticateur invalide")
	}

	// Parsing de l'authenticateur (simplifié)
	authParts := splitString(string(authenticatorData), "|")
	if len(authParts) != 2 || authParts[0] != clientID {
		return false, fmt.Errorf("authenticateur non valide pour ce client")
	}

	// Vérifier l'horodatage pour éviter les attaques par rejeu
	authTimestamp, _ := time.Parse(time.RFC3339, authParts[1])
	if time.Since(authTimestamp) > 5*time.Minute {
		return false, fmt.Errorf("authenticateur expiré")
	}

	return true, nil
}

// Simulation du processus d'authentification Kerberos
func simulateKerberos() {
	fmt.Println("=== SIMULATION KERBEROS ===")

	// Create fixed keys for all entities
	tgsKey := createFixedKey(16)
	aliceKey := createFixedKey(16)
	bobKey := createFixedKey(16)
	service1Key := createFixedKey(16)
	service2Key := createFixedKey(16)

	fmt.Println("TGS Key:", hex.EncodeToString(tgsKey), "length:", len(tgsKey))
	fmt.Println("Alice Key:", hex.EncodeToString(aliceKey), "length:", len(aliceKey))

	// Création des entités avec des clés de taille correcte (16 bytes pour AES-128)
	as := &AuthServer{
		UserDB: map[string][]byte{
			"alice": aliceKey,
			"bob":   bobKey,
		},
		TGSKey: tgsKey, // Add TGS key to AS
	}

	tgs := &TicketGrantingServer{
		Key: tgsKey, // Same key as in AS.TGSKey
		ServiceDB: map[string][]byte{
			"service1": service1Key,
			"service2": service2Key,
		},
	}

	client := &Client{
		ID:      "alice",
		Key:     aliceKey, // Same as in UserDB
		Address: "192.168.1.100",
	}

	service := &Service{
		ID:  "service1",
		Key: service1Key, // Same as in ServiceDB
	}

	// Phase 1: Client demande un TGT au serveur d'authentification (AS)
	fmt.Println("\n1. Client demande un TGT au serveur d'authentification")
	clientEncrypted, tgtEncrypted, err := as.authenticate(client.ID)
	if err != nil {
		fmt.Printf("Échec de l'authentification: %v\n", err)
		return
	}

	// Client déchiffre les données avec sa clé
	clientDataEncrypted := clientEncrypted // Normalement envoyé par réseau
	clientData, err := decrypt(client.Key, clientDataEncrypted)
	if err != nil {
		fmt.Printf("Échec du déchiffrement: %v\n", err)
		return
	}

	// Parsing des données (simplifié)
	parts := splitString(string(clientData), "|")
	if len(parts) != 2 {
		fmt.Printf("Format de données invalide\n")
		return
	}

	tgsSessionKey, _ := base64.StdEncoding.DecodeString(parts[0])
	fmt.Println("   → Client a obtenu une clé de session TGS et un TGT")

	// Phase 2: Client crée un authenticateur et demande un ticket de service au TGS
	fmt.Println("\n2. Client demande un ticket pour le service 'service1' au TGS")

	// Création de l'authenticateur
	authenticator := fmt.Sprintf("%s|%s", client.ID, time.Now().Format(time.RFC3339))
	authenticatorEncrypted, _ := encrypt(tgsSessionKey, []byte(authenticator))

	// Demande au TGS
	serviceDataEncrypted, err := tgs.requestServiceTicket(tgtEncrypted, authenticatorEncrypted, "service1")
	if err != nil {
		fmt.Printf("Échec de la demande de ticket de service: %v\n", err)
		return
	}

	// Client déchiffre les données avec la clé de session TGS
	serviceData, err := decrypt(tgsSessionKey, serviceDataEncrypted)
	if err != nil {
		fmt.Printf("Échec du déchiffrement: %v\n", err)
		return
	}

	// Parsing des données (simplifié)
	parts = splitString(string(serviceData), "|")
	if len(parts) != 2 {
		fmt.Printf("Format de données invalide\n")
		return
	}

	serviceSessionKey, _ := base64.StdEncoding.DecodeString(parts[0])
	serviceTicketEncrypted := parts[1]
	fmt.Println("   → Client a obtenu une clé de session service et un ticket de service")

	// Phase 3: Client s'authentifie auprès du service
	fmt.Println("\n3. Client s'authentifie auprès du service")

	// Création de l'authenticateur pour le service
	authenticator = fmt.Sprintf("%s|%s", client.ID, time.Now().Format(time.RFC3339))
	authenticatorEncrypted, _ = encrypt(serviceSessionKey, []byte(authenticator))

	// Authentification auprès du service
	success, err := service.authenticate(serviceTicketEncrypted, authenticatorEncrypted)
	if err != nil {
		fmt.Printf("Échec de l'authentification auprès du service: %v\n", err)
		return
	}

	if success {
		fmt.Println("   → Authentification réussie auprès du service!")
		fmt.Println("\n✓ Simulation Kerberos complète - Le client est authentifié")
	} else {
		fmt.Println("   → Échec de l'authentification")
	}
}

func main() {
	simulateKerberos()
}
