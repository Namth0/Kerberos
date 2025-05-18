# Kerberos Implementation in Go

Ce projet est une implémentation éducative du protocole Kerberos en Go. Il démontre les principes fondamentaux de l'authentification Kerberos à travers une simulation complète.

## Structure du projet

## 📋 Table des matières

- [À propos](#à-propos)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Fonctionnement du protocole Kerberos](#fonctionnement-du-protocole-kerberos)
- [Structure du code](#structure-du-code)
- [Personnalisation et extensions](#personnalisation-et-extensions)
- [Licence](#licence)

## 🔍 À propos

Ce projet est une implémentation pédagogique du protocole d'authentification Kerberos en Go. Il vise à illustrer le fonctionnement interne du protocole Kerberos à travers une simulation locale, sans nécessiter d'infrastructure réseau complexe.

### Caractéristiques

- Simulation complète du flux d'authentification Kerberos
- Implémentation des principales composantes (AS, TGS, Client, Service)
- Utilisation d'AES pour le chiffrement/déchiffrement
- Affichage détaillé des échanges pour comprendre chaque étape
- Exécution locale pour faciliter l'apprentissage et les tests

## 💾 Installation

### Prérequis

- Go 1.21 ou plus récent

### Installation

```bash
# Cloner le dépôt (remplacez par votre URL de dépôt si différente)
git clone https://github.com/Namhto/Kerberos.git
cd Kerberos

# S'assurer que les dépendances sont à jour (facultatif si aucune dépendance externe)
go mod tidy
```

## 🚀 Utilisation

Exécutez la simulation Kerberos en action :

```bash
# Méthode 1: Exécuter directement le module principal
go run src/cmd/main.go

# Méthode 2: Compiler puis exécuter
# Construire l'exécutable (le nommera 'Kerberos' par défaut ou le nom du module)
go build src/cmd/main.go 
# Exécuter (le nom peut varier selon votre OS, ex: ./main ou ./main.exe)
./main 
```

Le programme affichera une simulation étape par étape du processus d'authentification Kerberos, avec des explications sur chaque phase.

### Exemple de sortie

```
=== SIMULATION KERBEROS ===
TGS Key: 4142434445464748494a4b4c4d4e4f50 length: 16
Alice Key: 4142434445464748494a4b4c4d4e4f50 length: 16

1. Client demande un TGT au serveur d'authentification
   → Client a obtenu une clé de session TGS et un TGT

2. Client demande un ticket pour le service 'service1' au TGS
   → Client a obtenu une clé de session service et un ticket de service

3. Client s'authentifie auprès du service
   → Authentification réussie auprès du service!

✓ Simulation Kerberos complète - Le client est authentifié
```

## 📖 Fonctionnement du protocole Kerberos

Le simulateur démontre les trois phases principales du protocole Kerberos :

### Phase 1: Authentification initiale (Authentication Service Exchange)
- Le client demande un Ticket Granting Ticket (TGT) au serveur d'authentification (AS)
- L'AS vérifie l'identité du client et lui retourne un TGT chiffré avec la clé du TGS
- Le client reçoit également une clé de session pour communiquer avec le TGS

### Phase 2: Demande de ticket de service (Ticket Granting Service Exchange)
- Le client crée un authenticateur chiffré avec la clé de session TGS
- Le client envoie l'authenticateur et le TGT au TGS pour demander un ticket de service
- Le TGS vérifie l'authenticité et génère un ticket de service chiffré avec la clé du service cible

### Phase 3: Client/Server Exchange
- Le client s'authentifie auprès du service en présentant le ticket de service
- Le client crée un nouvel authenticateur chiffré avec la clé de session du service
- Le service vérifie le ticket et l'authenticateur, puis accorde l'accès si tout est valide

## 🧩 Structure du code

Le code est organisé autour des composants principaux du protocole Kerberos :

- **AuthServer**: Serveur d'authentification qui gère les identités des utilisateurs
- **TicketGrantingServer**: Serveur de distribution de tickets pour les services
- **Client**: Utilisateur qui souhaite accéder aux services
- **Service**: Service auquel le client veut accéder
- **Ticket**: Structure représentant un ticket Kerberos
- **Authenticator**: Structure représentant un authentificateur

Des fonctions utilitaires sont également disponibles pour :
- Le chiffrement/déchiffrement (AES)
- La génération de clés de session
- La sérialisation/désérialisation des données

## 🔧 Personnalisation et extensions

Vous pouvez personnaliser le simulateur pour explorer différents aspects du protocole :

### Modification des paramètres de sécurité

```go
// Changer la durée de vie des tickets
tgt.Lifetime = 24 * time.Hour

// Utiliser un algorithme de chiffrement différent
// (nécessite de modifier les fonctions encrypt/decrypt)
```

### Ajouter de nouveaux scénarios

```go
// Ajouter un nouveau service
tgs.ServiceDB["service3"] = createFixedKey(16)

// Simuler une attaque par rejeu
// Réutiliser un authenticateur précédent
```

### Implémenter des fonctionnalités avancées

- Ajout du préauthentification
- Support pour le renouvellement de tickets
- Implémentation des délégations
- Gestion de plusieurs domaines (cross-realm)

## 📄 Licence

Ce projet est sous licence [MIT](LICENSE) - voir le fichier LICENSE pour plus de détails. 