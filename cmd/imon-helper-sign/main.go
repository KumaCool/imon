// imon-helper-sign creates release metadata for bundled Linux host helpers.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"imon/internal/helperupdate"
)

func readSigningKey() (ed25519.PrivateKey, error) {
	path := os.Getenv("IMON_HELPER_SIGNING_KEY_FILE")
	if path == "" {
		return nil, errors.New("set IMON_HELPER_SIGNING_KEY_FILE to an Ed25519 PKCS#8 PEM")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("could not read helper signing key")
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("helper signing key must be a PKCS#8 PEM")
	}
	decoded, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("could not parse helper signing key")
	}
	key, ok := decoded.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("helper signing key must use Ed25519")
	}
	return key, nil
}

func run(args []string) error {
	key, err := readSigningKey()
	if err != nil {
		return err
	}
	public := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	switch {
	case len(args) == 1 && args[0] == "public":
		_, err := fmt.Fprintln(os.Stdout, public)
		return err
	case len(args) == 4 && args[0] == "sign":
		binary, err := os.ReadFile(args[3])
		if err != nil {
			return err
		}
		_, signature, err := helperupdate.Sign(binary, args[1], args[2], key)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(struct {
			Release   string `json:"release"`
			PublicKey string `json:"public_key"`
			Signature string `json:"signature"`
		}{args[1], public, signature})
	default:
		return errors.New("usage: imon-helper-sign public | sign <RELEASE> <ARCH> <BINARY>")
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
