# API Integration Specifications (`aurion-api`)

This document details the data structures (JSON payloads), required HTTP headers, and endpoint behaviors for the Go REST API.

## 📄 Table of Contents
1. [Authentication](#1-authentication)
   - `POST /api/auth/login`
2. [PGP Vault](#2-pgp-vault)
   - `GET /api/vault`
   - `POST /api/vault`
3. [Ephemeral Bridge (RAM Store)](#3-ephemeral-bridge-ram-store)
   - `POST /api/bridge/secret`
   - `GET /api/bridge/secret/{id}`
4. [Health & Monitoring](#4-health--monitoring)
   - `GET /health`



## 1. Authentication

### `POST /api/auth/login`
Authenticates a user via LDAP credentials and retrieves a JWT bearer token.

* **Authentication Required:** No (Public)
* **Headers:**
  * `Content-Type: application/json`

#### Request Body
```json
{
  "email": "user@domain.com",
  "password": "SecretPassword123"
}

```

#### Response Body (`200 OK`)

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
    "email": "user@domain.com",
    "created_at": "2026-03-30T14:22:10Z"
  }
}

```

#### Possible Error Responses

* `400 Bad Request`: `{"error":"Format JSON invalide"}`
* `401 Unauthorized`: `{"error":"Identifiants invalides"}`
* `500 Internal Server Error`: `{"error":"Erreur lors de la synchronisation du compte"}` or `{"error":"Erreur lors de la génération du token"}`


## 2. PGP Vault

> ⚠️ **All endpoints in this section require the header:**  
> `Authorization: Bearer <JWT_TOKEN>`

---

### `GET /api/vault`

Retrieves the complete state of the user's vault (encrypted PGP keys and message cache).

* **Authentication Required:** Yes (JWT)

#### Response Body (`200 OK`)

```json
{
  "format": "openpgp-plugin-backup",
  "version": 7,
  "createdAt": "2026-03-30T14:22:10Z",
  "keys": [
    {
      "id": "key_9b2f3a1e",
      "email": "user@domain.com",
      "publicKey": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...",
      "encryptedPrivateKey": "a3f890b...",
      "salt": "e1f2a3...",
      "iv": "c2f1e0...",
      "kdfIterations": 100000,
      "issuer": "Aurion CA",
      "subject": "user@domain.com",
      "serialNumber": "123456789",
      "notBefore": "2026-01-01T00:00:00Z",
      "notAfter": "2028-01-01T00:00:00Z",
      "fingerprint": "9B2F3A1E4C5D6E7F",
      "algorithm": "RSA-4096",
      "capabilities": {
        "canSign": true,
        "canEncrypt": true
      },
      "default": true,
      "aesSalt": "f8e7d6..."
    }
  ],
  "messageCache": [
    {
      "id": "msg_123456",
      "encryptedPayload": "a3f890b...",
      "iv": "c2f1e0..."
    }
  ]
}

```

> **Note:** If no vault exists in the database for the requesting user, the API returns an initial default structure with `keys: []` and `messageCache: []`.

#### Possible Error Responses

* `401 Unauthorized`: `{"error":"Utilisateur non identifié"}`
* `500 Internal Server Error`: `{"error":"Erreur lors de la lecture du coffre"}`

---

### `POST /api/vault`

Synchronizes and overrides the user's PGP key vault and message cache.

* **Authentication Required:** Yes (JWT)
* **Headers:**
* `Content-Type: application/json`



#### Request Body

```json
{
  "format": "openpgp-plugin-backup",
  "version": 7,
  "createdAt": "2026-03-30T14:22:10Z",
  "keys": [
    {
      "id": "key_9b2f3a1e",
      "email": "user@domain.com",
      "publicKey": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...",
      "encryptedPrivateKey": "a3f890b...",
      "salt": "e1f2a3...",
      "iv": "c2f1e0...",
      "kdfIterations": 100000,
      "issuer": "Aurion CA",
      "subject": "user@domain.com",
      "serialNumber": "123456789",
      "notBefore": "2026-01-01T00:00:00Z",
      "notAfter": "2028-01-01T00:00:00Z",
      "fingerprint": "9B2F3A1E4C5D6E7F",
      "algorithm": "RSA-4096",
      "capabilities": {
        "canSign": true,
        "canEncrypt": true
      },
      "default": true,
      "aesSalt": "f8e7d6..."
    }
  ],
  "messageCache": [
    {
      "id": "msg_123456",
      "encryptedPayload": "a3f890b...",
      "iv": "c2f1e0..."
    },
    {
      "id": "msg_789012",
      "encryptedPayload": "d4e5f6...",
      "iv": "f1a2b3..."
    }
  ]
}

```

#### Response Body (`200 OK`)

```json
{
  "status": "synced"
}

```

#### Possible Error Responses

* `400 Bad Request`: `{"error":"Format JSON invalide"}`
* `401 Unauthorized`: `{"error":"Utilisateur non identifié"}`
* `500 Internal Server Error`: `{"error":"Erreur de sauvegarde du coffre"}` or `{"error":"Erreur lors du traitement du cache de messages"}`
## 3. Ephemeral Bridge (RAM Store)

A Zero-Knowledge (ZK) mechanism for temporary in-memory data exchange without persistent disk storage.



### `POST /api/bridge/secret`

Stores an encrypted secret in RAM.

* **Authentication Required:** Yes (JWT)
* **Headers:**
* `Content-Type: application/json`



#### Request Body

```json
{
  "encryptedData": "PGP MESSAGE OR ZERO-KNOWLEDGE CIPHERTEXT...",
  "ttlSeconds": 300
}

```

* `ttlSeconds` *(Optional)*: Expiration time in seconds (Default: `300`s / 5 min, Maximum: `3600`s / 1 hour).

#### Response Body (`201 Created`)

```json
{
  "id": "c39a28b0-8f6a-4d23-933e-11bc9171a82f",
  "expiresAt": "2026-03-30T14:27:10Z"
}

```

#### Possible Error Responses

* `400 Bad Request`: `{"error":"Contenu chiffré invalide ou absent"}`
* `401 Unauthorized`: `{"error":"Utilisateur non identifié"}`
* `500 Internal Server Error`: `{"error":"Erreur lors de la réservation en mémoire"}`



### `GET /api/bridge/secret/{id}`

Retrieves and consumes a stored secret from RAM. **Burn After Reading policy:** The secret is permanently deleted from memory upon being read.

* **Authentication Required:** No (Public)

#### URL Parameters

* `id`: The UUID secret identifier generated during the `POST` request.

#### Response Body (`200 OK`)

```json
{
  "id": "c39a28b0-8f6a-4d23-933e-11bc9171a82f",
  "encryptedData": "PGP MESSAGE OR ZERO-KNOWLEDGE CIPHERTEXT..."
}

```

#### Possible Error Responses

* `400 Bad Request`: `{"error":"ID du secret manquant"}`
* `404 Not Found`: `{"error":"Secret introuvable, déjà consommé ou expiré"}`