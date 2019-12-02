package threaes

import "testing"

import "encoding/base64"

// encoding unalignment
// func TestEnc(t *testing.T) {
// 	text := []byte("aaaabaaaabaaaaba")
// 	key := []byte("0123456789ABCDEF")
// 	// right ouput
// 	rresult := []byte("XQUCJg/0ZeoV+rJfJogJhhgPtlXLZWYwUgWsj82AUy8=")
// 	raw := Enc(text, key)
// 	encresult := base64.StdEncoding.EncodeToString(raw)
// 	if encresult != string(rresult) {
// 		t.Errorf("Encrytion WRONG. Get %s compared to answer %s", encresult, string(rresult))
// 	} else {
// 		t.Logf("Encryption RIGHT. Get %s compared to answer %s", encresult, string(rresult))
// 	}
// }

func TestDec(t *testing.T) {
	ciphercoded := []byte("nKtXDFy91S2Oiv2AlXRsUlJ5VHPSR+lRpBN7tMzxZmFPU5BNGzZmv+Za6a4=")
	key := []byte("0123456789ABCDEF")

	rawCipher, _ := base64.StdEncoding.DecodeString(string(ciphercoded))
	rresult := []byte("aaaabaaaabaaaaba")
	decresult := Dec(rawCipher, key)

	if string(decresult) != string(rresult) {
		t.Errorf("Decryption WRONG. Get %s compared to answer %s", string(decresult), string(rresult))
	} else {
		t.Logf("Decryption RIGHT. Get %s compared to answer %s", string(decresult), string(rresult))
	}

}
