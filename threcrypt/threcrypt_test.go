package threcrypt

import (
	"testing"

	"go.dedis.ch/kyber/v4/group/edwards25519"
)

func TestThreshDecrypt(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	t.Log("Test n=5, t=3 nodes of secret sharing")
	sKeys, pKeys := GenNodesPriKey(5, suite)

	rawMsg := []byte("hello world!")

	K, C, _ := ThreshEnc(suite, pKeys, rawMsg)

	allShares := ThreshShare(suite, 3, 5, sKeys)

	threshKeys := ThreshRecover(suite, 3, 5, allShares)

	decMsg, err := ThreshDec(suite, threshKeys, K, C)
	if err != nil {
		t.Fatal(err)
	}

	if string(rawMsg) != string(decMsg) {
		t.Errorf("Threshold decryption failed")
	}
}

func TestNotEnoughShare(t *testing.T) {

}
