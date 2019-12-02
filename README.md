### package threshold
package threshold implements Threshold ElGamal Cryptosystem based on package [_kyber_](https://godoc.org/github.com/dedis/kyber)

Due to the limit of [ElGamal](https://en.wikipedia.org/wiki/ElGamal_encryption) encryption(elliptic curve), only 29-byte long message could be encrypted. See the detail of the test result of package _threshold/elgamal_.

sample test result:
```
=== RUN   TestDecrypt
--- PASS: TestDecrypt (0.01s)
    elgamal_test.go:17: Decrypt a simple string.
=== RUN   TestMaxLengthCipher
--- FAIL: TestMaxLengthCipher (0.00s)
    elgamal_test.go:40: Decrypt a 40-byte long []byte
    elgamal_test.go:50: Should get 40-byte long []byte, only get 29-byte
FAIL
exit status 1
FAIL    threshold/elgamal       0.010s
```


Add wrapper AES-128-GCM for large-size message en/decryption.
ElGamal encrypts only the encryption key for AES-128-GCM, a.k.a 16-byte long block cipher key.