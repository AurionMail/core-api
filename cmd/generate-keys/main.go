package generatekeys

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/bytemare/opaque"
)

func main() {
	conf := opaque.DefaultConfiguration()
	oprfSeed := conf.GenerateOPRFSeed()

	serverPrivateKey, serverPublicKey := conf.KeyGen()
	if serverPrivateKey == nil || serverPublicKey == nil || oprfSeed == nil {
		log.Fatalf("error when generating OPAQUE keys")
	}

	oprfSeedHex := hex.EncodeToString(oprfSeed)
	privateKeyHex := hex.EncodeToString(serverPrivateKey.Encode())

	fmt.Println("=== Paste these lines in .env ===")
	fmt.Printf("OPAQUE_OPRF_SEED=%s\n", oprfSeedHex)
	fmt.Printf("OPAQUE_SERVER_PRIVATE_KEY=%s\n", privateKeyHex)
}
