package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// Fonction utilitaire pour créer des clés de taille exacte
func CreateFixedKey(size int) []byte {
	key := make([]byte, size)
	for i := 0; i < size; i++ {
		key[i] = byte(i + 65) // Remplir simplement avec des valeurs ASCII séquentielles
	}
	return key
}

// Fonction pour vérifier la taille des clés avant les opérations
func verifyKey(key []byte, operation string) {
	fmt.Printf("Key length for %s: %d bytes, hex: %s\n",
		operation, len(key), hex.EncodeToString(key))
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		fmt.Printf("WARNING: Invalid key size %d for AES operation: %s\n", len(key), operation)
	}
}

// Fonction pour chiffrer un message
func Encrypt(key []byte, message []byte) (string, error) {
	verifyKey(key, "encrypt")

	// Créer une clé de taille fixe si l'originale n'est pas valide
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		fmt.Printf("Using fallback key for encryption instead of size %d\n", len(key))
		key = CreateFixedKey(16)
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
func Decrypt(key []byte, cryptoText string) ([]byte, error) {
	verifyKey(key, "decrypt")

	// Créer une clé de taille fixe si l'originale n'est pas valide
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		fmt.Printf("Using fallback key for decryption instead of size %d\n", len(key))
		key = CreateFixedKey(16)
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
func GenerateSessionKey() []byte {
	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err.Error())
	}
	return key
}
