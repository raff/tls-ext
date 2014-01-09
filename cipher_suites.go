// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/x509"
	"hash"
)

// a KeyAgreement implements the client and server side of a TLS key agreement
// protocol by generating and processing key exchange messages.
type KeyAgreement interface {
	// On the server side, the first two methods are called in order.

	// In the case that the key agreement protocol doesn't use a
	// ServerKeyExchange message, generateServerKeyExchange can return nil,
	// nil.
	GenerateServerKeyExchange(*Config, *Certificate, *ClientHelloMsg, *ServerHelloMsg) (*ServerKeyExchangeMsg, error)
	ProcessClientKeyExchange(*Config, *Certificate, *ClientKeyExchangeMsg, uint16) ([]byte, error)

	// On the client side, the next two methods are called in order.

	// This method may not be called if the server doesn't send a
	// ServerKeyExchange message.
	ProcessServerKeyExchange(*Config, *ClientHelloMsg, *ServerHelloMsg, *x509.Certificate, *ServerKeyExchangeMsg) error
	GenerateClientKeyExchange(*Config, *ClientHelloMsg, *x509.Certificate) ([]byte, *ClientKeyExchangeMsg, error)
}

const (
	// SuiteECDH indicates that the cipher suite involves elliptic curve
	// Diffie-Hellman. This means that it should only be selected when the
	// client indicates that it supports ECC with a curve and point format
	// that we're happy with.
	SuiteECDHE = 1 << iota
	// SuiteECDSA indicates that the cipher suite involves an ECDSA
	// signature and therefore may only be selected when the server's
	// certificate is ECDSA. If this is not set then the cipher suite is
	// RSA based.
	SuiteECDSA
	// SuiteTLS12 indicates that the cipher suite should only be advertised
	// and accepted when using TLS 1.2.
	SuiteTLS12
	// SuiteNoCerts indicates that the cipher suite doesn't use certificate exchange
	// (anonymous ciphersuites or pre-shared-secret)
	SuiteNoCerts
)

// A CipherSuite is a specific combination of key agreement, cipher and MAC
// function. All cipher suites currently assume RSA key agreement.
type CipherSuite struct {
	Id uint16
	// the lengths, in bytes, of the key material needed for each component.
	KeyLen int
	MacLen int
	IvLen  int
	Ka     func(version uint16) KeyAgreement
	// flags is a bitmask of the suite* values, above.
	Flags  int
	Cipher func(key, iv []byte, isRead bool) interface{}
	Mac    func(version uint16, macKey []byte) macFunction
	Aead   func(key, fixedNonce []byte) cipher.AEAD
}

var cipherSuites = []*CipherSuite{
	// Ciphersuite order is chosen so that ECDHE comes before plain RSA
	// and RC4 comes before AES (because of the Lucky13 attack).
	{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdheRSAKA, SuiteECDHE | SuiteTLS12, nil, nil, aeadAESGCM},
	{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdheECDSAKA, SuiteECDHE | SuiteECDSA | SuiteTLS12, nil, nil, aeadAESGCM},
	{TLS_ECDHE_RSA_WITH_RC4_128_SHA, 16, 20, 0, ecdheRSAKA, SuiteECDHE, CipherRC4, MacSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, 16, 20, 0, ecdheECDSAKA, SuiteECDHE | SuiteECDSA, CipherRC4, MacSHA1, nil},
	{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdheRSAKA, SuiteECDHE, CipherAES, MacSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdheECDSAKA, SuiteECDHE | SuiteECDSA, CipherAES, MacSHA1, nil},
	{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdheRSAKA, SuiteECDHE, CipherAES, MacSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdheECDSAKA, SuiteECDHE | SuiteECDSA, CipherAES, MacSHA1, nil},
	{TLS_RSA_WITH_RC4_128_SHA, 16, 20, 0, rsaKA, 0, CipherRC4, MacSHA1, nil},
	{TLS_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, rsaKA, 0, CipherAES, MacSHA1, nil},
	{TLS_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, rsaKA, 0, CipherAES, MacSHA1, nil},
	{TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, ecdheRSAKA, SuiteECDHE, Cipher3DES, MacSHA1, nil},
	{TLS_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, rsaKA, 0, Cipher3DES, MacSHA1, nil},
}

// RegisterCipherSuites registers additional cipher suites
func RegisterCipherSuites(c ...*CipherSuite) {
	cipherSuites = append(cipherSuites, c...)
}

func CipherRC4(key, iv []byte, isRead bool) interface{} {
	cipher, _ := rc4.NewCipher(key)
	return cipher
}

func Cipher3DES(key, iv []byte, isRead bool) interface{} {
	block, _ := des.NewTripleDESCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func CipherAES(key, iv []byte, isRead bool) interface{} {
	block, _ := aes.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

// MacSHA1 returns a macFunction for the given protocol version.
func MacSHA1(version uint16, key []byte) macFunction {
	if version == VersionSSL30 {
		mac := ssl30MAC{
			h:   sha1.New(),
			key: make([]byte, len(key)),
		}
		copy(mac.key, key)
		return mac
	}
	return tls10MAC{hmac.New(sha1.New, key)}
}

type macFunction interface {
	Size() int
	MAC(digestBuf, seq, header, data []byte) []byte
}

// fixedNonceAEAD wraps an AEAD and prefixes a fixed portion of the nonce to
// each call.
type fixedNonceAEAD struct {
	// sealNonce and openNonce are buffers where the larger nonce will be
	// constructed. Since a seal and open operation may be running
	// concurrently, there is a separate buffer for each.
	sealNonce, openNonce []byte
	aead                 cipher.AEAD
}

func (f *fixedNonceAEAD) NonceSize() int { return 8 }
func (f *fixedNonceAEAD) Overhead() int  { return f.aead.Overhead() }

func (f *fixedNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	copy(f.sealNonce[len(f.sealNonce)-8:], nonce)
	return f.aead.Seal(out, f.sealNonce, plaintext, additionalData)
}

func (f *fixedNonceAEAD) Open(out, nonce, plaintext, additionalData []byte) ([]byte, error) {
	copy(f.openNonce[len(f.openNonce)-8:], nonce)
	return f.aead.Open(out, f.openNonce, plaintext, additionalData)
}

func aeadAESGCM(key, fixedNonce []byte) cipher.AEAD {
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	nonce1, nonce2 := make([]byte, 12), make([]byte, 12)
	copy(nonce1, fixedNonce)
	copy(nonce2, fixedNonce)

	return &fixedNonceAEAD{nonce1, nonce2, aead}
}

// ssl30MAC implements the SSLv3 MAC function, as defined in
// www.mozilla.org/projects/security/pki/nss/ssl/draft302.txt section 5.2.3.1
type ssl30MAC struct {
	h   hash.Hash
	key []byte
}

func (s ssl30MAC) Size() int {
	return s.h.Size()
}

var ssl30Pad1 = [48]byte{0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36}

var ssl30Pad2 = [48]byte{0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c}

func (s ssl30MAC) MAC(digestBuf, seq, header, data []byte) []byte {
	padLength := 48
	if s.h.Size() == 20 {
		padLength = 40
	}

	s.h.Reset()
	s.h.Write(s.key)
	s.h.Write(ssl30Pad1[:padLength])
	s.h.Write(seq)
	s.h.Write(header[:1])
	s.h.Write(header[3:5])
	s.h.Write(data)
	digestBuf = s.h.Sum(digestBuf[:0])

	s.h.Reset()
	s.h.Write(s.key)
	s.h.Write(ssl30Pad2[:padLength])
	s.h.Write(digestBuf)
	return s.h.Sum(digestBuf[:0])
}

// tls10MAC implements the TLS 1.0 MAC function. RFC 2246, section 6.2.3.
type tls10MAC struct {
	h hash.Hash
}

func (s tls10MAC) Size() int {
	return s.h.Size()
}

func (s tls10MAC) MAC(digestBuf, seq, header, data []byte) []byte {
	s.h.Reset()
	s.h.Write(seq)
	s.h.Write(header)
	s.h.Write(data)
	return s.h.Sum(digestBuf[:0])
}

func rsaKA(version uint16) KeyAgreement {
	return rsaKeyAgreement{}
}

func ecdheECDSAKA(version uint16) KeyAgreement {
	return &ecdheKeyAgreement{
		sigType: signatureECDSA,
		version: version,
	}
}

func ecdheRSAKA(version uint16) KeyAgreement {
	return &ecdheKeyAgreement{
		sigType: signatureRSA,
		version: version,
	}
}

// mutualCipherSuite returns a CipherSuite given a list of supported
// ciphersuites and the id requested by the peer.
func mutualCipherSuite(have []uint16, want uint16) *CipherSuite {
	for _, id := range have {
		if id == want {
			for _, suite := range cipherSuites {
				if suite.Id == want {
					return suite
				}
			}
			return nil
		}
	}
	return nil
}

// A list of the possible cipher suite ids. Taken from
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml
const (
	TLS_RSA_WITH_RC4_128_SHA                uint16 = 0x0005
	TLS_RSA_WITH_3DES_EDE_CBC_SHA           uint16 = 0x000a
	TLS_RSA_WITH_AES_128_CBC_SHA            uint16 = 0x002f
	TLS_RSA_WITH_AES_256_CBC_SHA            uint16 = 0x0035
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA        uint16 = 0xc007
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    uint16 = 0xc009
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    uint16 = 0xc00a
	TLS_ECDHE_RSA_WITH_RC4_128_SHA          uint16 = 0xc011
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA     uint16 = 0xc012
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      uint16 = 0xc013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      uint16 = 0xc014
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   uint16 = 0xc02f
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 uint16 = 0xc02b
)
