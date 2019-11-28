package threcrypt

import (
	"bytes"
	"encoding/binary"

	"threshold/elgamal"

	"go.dedis.ch/kyber/v4"
)

type Config struct {
	group	kyber.Group	// elliptic curve
	n		int			// user number
	t		int			// threshold

	pubKeys []kyber.Scalar
	priKeys []kyber.Point

	pubKeyFile	string		// file that stores the public keys
	priKeyFile	string		// directory contains each node's private key
}


// generate n random key-pairs for nodes
func genNodesPriKey(n int, suite kyber.Suite) {

}

// writePublicKey write node's public key to local file to simulate public keys broadcasting
func writePublicKey() {

}

func writePriPoly()
func readPriPoly()

// ThreshEnc encrypt the message in ElGamal encryption
func ThreshEnc(secret []byte) {

}

// ThreshDec decrypt the message in ElGamal encryption
func ThreshDec(secret []byte) {

}

//
func ThreshShare() {

}