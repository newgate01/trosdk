package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"

	cryptoeth "github.com/ethereum/go-ethereum/crypto"
)

const AddressLength = 21

type Address [AddressLength]byte

func (a Address) Bytes() []byte {
	return a[:]
}

func (a *Address) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
}

func BytesToAddress(b []byte) Address {
	var a Address
	a.SetBytes(b)
	return a
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(cryptoeth.S256(), rand.Reader)
}

func GetPrivateKeyByHexString(privateKeyHexString string) (*ecdsa.PrivateKey,
	error) {
	return cryptoeth.HexToECDSA(privateKeyHexString)
}

func PrivateKeyToHexString(key *ecdsa.PrivateKey) string {
	return hex.EncodeToString(cryptoeth.FromECDSA(key))
}

func PublicKeyToAddress(p ecdsa.PublicKey) Address {
	address := cryptoeth.PubkeyToAddress(p)
	addressTron := append([]byte{0x41}, address.Bytes()...)
	return BytesToAddress(addressTron)
}
