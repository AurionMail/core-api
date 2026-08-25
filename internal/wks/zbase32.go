package wks

import (
	"crypto/sha1"
	"strings"
)

const zBase32Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"

func HashLocalPart(username string) string {
	localPart := strings.ToLower(username)
	hasher := sha1.New()
	hasher.Write([]byte(localPart))
	digest := hasher.Sum(nil)

	return encodeZBase32(digest)
}

func encodeZBase32(src []byte) string {
	var result strings.Builder
	var bitBuffer uint64
	var bitCount uint

	for _, b := range src {
		bitBuffer = (bitBuffer << 8) | uint64(b)
		bitCount += 8

		for bitCount >= 5 {
			bitCount -= 5
			index := (bitBuffer >> bitCount) & 0x1F
			result.WriteByte(zBase32Alphabet[index])
		}
	}

	if bitCount > 0 {
		index := (bitBuffer << (5 - bitCount)) & 0x1F
		result.WriteByte(zBase32Alphabet[index])
	}

	return result.String()
}
