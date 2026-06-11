package authn

import (
	"crypto/rand"
	"encoding/hex"
)

func testGeneratedSecret() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
