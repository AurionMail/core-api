package opaquei

import (
	"encoding/hex"
	"fmt"

	"github.com/bytemare/opaque"
)

func InitOpaqueServer(oprfSeedHex, privateKeyHex, serverID string) (*opaque.Server, error) {
	conf := opaque.DefaultConfiguration()

	// 1. Décoder le Seed OPRF (Hex -> []byte)
	oprfSeed, err := hex.DecodeString(oprfSeedHex)
	if err != nil {
		return nil, fmt.Errorf("erreur décodage OPAQUE_OPRF_SEED: %w", err)
	}

	// 2. Décoder la clé privée (Hex -> []byte -> *ecc.Scalar)
	privKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("erreur décodage OPAQUE_SERVER_PRIVATE_KEY: %w", err)
	}

	// Récupération du groupe de la suite cryptographique (par défaut Ristretto255 / Group 1)
	group := conf.AKE.Group()

	// Instanciation du Scalar et décodage
	serverPrivateKey := group.NewScalar()
	if err := serverPrivateKey.Decode(privKeyBytes); err != nil {
		return nil, fmt.Errorf("erreur reconstruction de la clé privée ECC: %w", err)
	}

	// 3. Recalculer la clé publique à partir de la clé privée (g^x)
	serverPublicKey := group.Base().Multiply(serverPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error when calculating pub key: %w", err)
	}

	// 4. Construire le ServerKeyMaterial
	skm := &opaque.ServerKeyMaterial{
		Identity:       []byte(serverID),
		PrivateKey:     serverPrivateKey,
		PublicKeyBytes: serverPublicKey.Encode(),
		OPRFGlobalSeed: oprfSeed,
	}

	// 5. Initialiser le serveur et appliquer le KeyMaterial
	server, err := conf.Server()
	if err != nil {
		return nil, fmt.Errorf("impossible de créer le serveur: %w", err)
	}

	if err := server.SetKeyMaterial(skm); err != nil {
		return nil, fmt.Errorf("impossible d'appliquer le key material: %w", err)
	}

	return server, nil
}
