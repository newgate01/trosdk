package crypto

import (
	"github.com/newgate01/trosdk/pkg/common"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Error("GenerateKey failed")
	}
	private := PrivateKeyToHexString(key)

	t.Log("private key:", private)

	public := PublicKeyToAddress(key.PublicKey)
	t.Log("public key:", common.EncodeCheck(public.Bytes()))
}
