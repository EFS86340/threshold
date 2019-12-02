// package threcrypt, reference: https://zhuanlan.zhihu.com/p/38148593
package threcrypt

import (
	"log"
	"threshold/elgamal"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/share"
)

type Config struct {
	group kyber.Group // elliptic curve
	n     int         // user number
	t     int         // threshold

	// 	pubKeys []kyber.Scalar
	// 	priKeys []kyber.Point
	//
	// 	pubKeyFile	string		// file that stores the public keys
	// 	priKeyFile	string		// directory contains each node's private key
}

func NewConfig(g kyber.Group, n int, t int) *Config {
	return &Config{g, n, t}
}

// generate n random key-pairs for nodes
func GenNodesPriKey(n int, suite *edwards25519.SuiteEd25519) ([]kyber.Scalar, []kyber.Point) {
	sKeys := make([]kyber.Scalar, n)
	pKeys := make([]kyber.Point, n)
	for i := 0; i < n; i++ {
		sKeys[i] = suite.Scalar().Pick(suite.RandomStream())
		pKeys[i] = suite.Point().Mul(sKeys[i], nil)
	}
	// TODO: write to persistent file
	return sKeys, pKeys
}

// ThreshEnc encrypt the message in ElGamal encryption
func ThreshEnc(group kyber.Group, pKeys []kyber.Point, msg []byte) (K, C kyber.Point, cipher []byte) {
	masterPK := pKeys[0] // master elgamal public key
	// if len(pKeys) ...
	// combine public keys
	for i := 1; i < len(pKeys); i++ {
		masterPK = group.Point().Add(masterPK, pKeys[i])
	}
	// encrypt message using master public key
	return elgamal.Encrypt(group, masterPK, msg)
}

// ThreshDec decrypt the message in ElGamal encryption
func ThreshDec(group kyber.Group, sKeys []kyber.Scalar, K, C kyber.Point) (msg []byte, err error) {
	// recover master private key using Shamir's secret sharing scheme

	// extract each user's private key
	masterPriKey := sKeys[0]
	for i := 1; i < len(sKeys); i++ {
		masterPriKey = group.Scalar().Add(masterPriKey, sKeys[i])
	}

	msg, err = elgamal.Decrypt(group, masterPriKey, K, C)

	return

}

// share each user's secret key by Shamir's secret sharing scheme
func ThreshShare(group *edwards25519.SuiteEd25519, t int, n int, sKeys []kyber.Scalar) [][]*share.PriShare {
	// each user gens a polynomial
	allShares := make([][]*share.PriShare, n)
	for i := 0; i < n; i++ {
		pripoly := share.NewPriPoly(group, t, sKeys[i], group.RandomStream())
		allShares[i] = pripoly.Shares(n)
		// write shares to persistent file
	}
	// write shares to persister
	return allShares
}

func ThreshRecover(group kyber.Group, t int, n int, allShares [][]*share.PriShare) []kyber.Scalar {
	// recover each user's private key
	sKeys := make([]kyber.Scalar, n)
	var err error
	for i := 0; i < n; i++ {
		sKeys[i], err = share.RecoverSecret(group, allShares[i], t, n)
		if err != nil {
			log.Fatal(err)
		}
	}
	return sKeys
}
