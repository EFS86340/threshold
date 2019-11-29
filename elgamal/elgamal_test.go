package elgamal

import (
	"testing"

	"go.dedis.ch/kyber/v4/group/edwards25519"
)

func TestDecrypt(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	priKey := suite.Scalar().Pick(suite.RandomStream())
	pubKey := suite.Point().Mul(priKey, nil)

	rawMsg := []byte("hello, world!")

	t.Log("Decrypt a simple string.")
	{
		K, C, _ := Encrypt(suite, pubKey, rawMsg)

		decMsg, err := Decrypt(suite, priKey, K, C)
		if err != nil {
			t.Fatal(err)
		}

		if string(rawMsg) != string(decMsg) {
			t.Fatal("WRONG decrypt result.")
		}
	}
}

func TestMaxLengthCipher(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	priKey := suite.Scalar().Pick(suite.RandomStream())
	pubKey := suite.Point().Mul(priKey, nil)

	rawMsg := []byte("aaaaBaaaaBaaaaBaaaaBaaaaBaaaaBaaaaBaaaaB")

	t.Log("Decrypt a 40-byte long []byte")
	{
		K, C, _ := Encrypt(suite, pubKey, rawMsg)

		decMsg, err := Decrypt(suite, priKey, K, C)
		if err != nil {
			t.Fatal(err)
		}

		if string(rawMsg) != string(decMsg) {
			t.Errorf("Should get 40-byte long []byte, only get %d-byte", len(decMsg))
		}
	}
}
