package main

import (
	"fmt"

	"threshold/elgamal"

	"go.dedis.ch/kyber/v4/group/edwards25519"
)

/*
This example illustrates how the crypto toolkit may be used
to perform "pure" ElGamal encryption,
in which the message to be encrypted is small enough to be embedded
directly within a group element (e.g., in an elliptic curve point).
For basic background on ElGamal encryption see for example
http://en.wikipedia.org/wiki/ElGamal_encryption.

Most public-key crypto libraries tend not to support embedding data in points,
in part because for "vanilla" public-key encryption you don't need it:
one would normally just generate an ephemeral Diffie-Hellman secret
and use that to seed a symmetric-key crypto algorithm such as AES,
which is much more efficient per bit and works for arbitrary-length messages.
However, in many advanced public-key crypto algorithms it is often useful
to be able to embedded data directly into points and compute with them:
as just one of many examples,
the proactively verifiable anonymous messaging scheme prototyped in Verdict
(see http://dedis.cs.yale.edu/dissent/papers/verdict-abs).

For fancier versions of ElGamal encryption implemented in this toolkit
see for example anon.Encrypt, which encrypts a message for
one of several possible receivers forming an explicit anonymity set.
*/
func main() {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Create a public/private keypair
	a := suite.Scalar().Pick(suite.RandomStream()) // Alice's private key
	A := suite.Point().Mul(a, nil)                 // Alice's public key

	// ElGamal-encrypt a message using the public key.
	m := []byte("aaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaab")
	K, C, _ := elgamal.Encrypt(suite, A, m)

	// Decrypt it using the corresponding private key.
	mm, err := elgamal.Decrypt(suite, a, K, C)

	// Make sure it worked!
	if err != nil {
		fmt.Println("decryption failed: " + err.Error())
	}
	if string(mm) != string(m) {
		// fmt.Println("decryption produced wrong output: " + string(mm))
		fmt.Println("Only support 29 bytes long")
	}
	fmt.Println("Decryption succeeded: " + string(mm))

}
