// From: https://raw.githubusercontent.com/goreleaser/nfpm/main/internal/sign/rsa.go
// SPDX-License-Identifier: MIT

package signature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1" //nolint:gosec
	_ "crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

var (
	errNoPemBlock   = errors.New("no PEM block found")
	errDigestLength = errors.New("digest has unexpected length")
	errNoPassphrase = errors.New("key is encrypted but no passphrase was provided")
	errNoRSAKey     = errors.New("key is not an RSA key")
)

// RSASignDigest signs the provided message digest. The key file must
// be in the PEM format and can either be encrypted or not.
func RSASignDigest(digest []byte, digestType crypto.Hash, keyFile, passphrase string) ([]byte, error) {
	if len(digest) != digestType.Size() {
		return nil, errDigestLength
	}

	keyFileContent, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	block, _ := pem.Decode(keyFileContent)
	if block == nil {
		return nil, errNoPemBlock
	}

	blockData := block.Bytes
	if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck
		if passphrase == "" {
			return nil, errNoPassphrase
		}

		var decryptedBlockData []byte

		decryptedBlockData, err = x509.DecryptPEMBlock(block, []byte(passphrase)) //nolint:staticcheck
		if err != nil {
			return nil, fmt.Errorf("decrypt private key PEM block: %w", err)
		}

		blockData = decryptedBlockData
	}

	priv, err := x509.ParsePKCS1PrivateKey(blockData)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS1 private key: %w", err)
	}

	signature, err := priv.Sign(rand.Reader, digest, digestType)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	return signature, nil
}

// RSAVerifyDigest is exported for use in tests and verifies a
// signature over the provided hash of a message. The key file must be
// in the PEM format.
func RSAVerifyDigest(digest []byte, digestType crypto.Hash, signature []byte, publicKey []byte) error {
	if len(digest) != digestType.Size() {
		return errDigestLength
	}

	block, _ := pem.Decode(publicKey)
	if block == nil {
		return errNoPemBlock
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse PKIX public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return errNoRSAKey
	}

	err = rsa.VerifyPKCS1v15(rsaPub, digestType, digest, signature)
	if err != nil {
		return fmt.Errorf("verify PKCS1v15 signature: %w", err)
	}

	return nil
}
