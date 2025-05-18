package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Namhto/kerberos/src/pkg/auth"
	"github.com/Namhto/kerberos/src/pkg/crypto"
)

func simulateKerberos() {
	fmt.Println("=== SIMULATION KERBEROS ===")

	tgsKey := crypto.CreateFixedKey(16)
	aliceKey := crypto.CreateFixedKey(16)
	bobKey := crypto.CreateFixedKey(16)
	service1Key := crypto.CreateFixedKey(16)
	service2Key := crypto.CreateFixedKey(16)

	fmt.Println("TGS Key:", hex.EncodeToString(tgsKey), "length:", len(tgsKey))
	fmt.Println("Alice Key:", hex.EncodeToString(aliceKey), "length:", len(aliceKey))

	as := &auth.AuthServer{
		UserDB: map[string][]byte{
			"alice": aliceKey,
			"bob":   bobKey,
		},
		TGSKey: tgsKey,
	}

	tgs := &auth.TicketGrantingServer{
		Key: tgsKey,
		ServiceDB: map[string][]byte{
			"service1": service1Key,
			"service2": service2Key,
		},
	}

	client := &auth.Client{
		ID:      "alice",
		Key:     aliceKey,
		Address: "192.168.1.100",
	}

	service := &auth.Service{
		ID:  "service1",
		Key: service1Key,
	}

	fmt.Println("\n1. Client demande un TGT au serveur d'authentification")
	clientEncrypted, tgtEncrypted, err := as.Authenticate(client.ID)
	if err != nil {
		fmt.Printf("Échec de l'authentification: %v\n", err)
		return
	}

	clientDataEncrypted := clientEncrypted
	clientData, err := crypto.Decrypt(client.Key, clientDataEncrypted)
	if err != nil {
		fmt.Printf("Échec du déchiffrement: %v\n", err)
		return
	}

	parts := auth.SplitString(string(clientData), "|")
	if len(parts) != 2 {
		fmt.Printf("Format de données invalide\n")
		return
	}

	tgsSessionKey, _ := base64.StdEncoding.DecodeString(parts[0])
	fmt.Println("   → Client a obtenu une clé de session TGS et un TGT")

	fmt.Println("\n2. Client demande un ticket pour le service 'service1' au TGS")

	authenticator := fmt.Sprintf("%s|%s", client.ID, time.Now().Format(time.RFC3339))
	authenticatorEncrypted, _ := crypto.Encrypt(tgsSessionKey, []byte(authenticator))

	serviceDataEncrypted, err := tgs.RequestServiceTicket(tgtEncrypted, authenticatorEncrypted, "service1")
	if err != nil {
		fmt.Printf("Échec de la demande de ticket de service: %v\n", err)
		return
	}

	serviceData, err := crypto.Decrypt(tgsSessionKey, serviceDataEncrypted)
	if err != nil {
		fmt.Printf("Échec du déchiffrement: %v\n", err)
		return
	}

	parts = auth.SplitString(string(serviceData), "|")
	if len(parts) != 2 {
		fmt.Printf("Format de données invalide\n")
		return
	}

	serviceSessionKey, _ := base64.StdEncoding.DecodeString(parts[0])
	serviceTicketEncrypted := parts[1]
	fmt.Println("   → Client a obtenu une clé de session service et un ticket de service")

	fmt.Println("\n3. Client s'authentifie auprès du service")

	authenticator = fmt.Sprintf("%s|%s", client.ID, time.Now().Format(time.RFC3339))
	authenticatorEncrypted, _ = crypto.Encrypt(serviceSessionKey, []byte(authenticator))

	success, err := service.Authenticate(serviceTicketEncrypted, authenticatorEncrypted)
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
