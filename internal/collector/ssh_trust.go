package collector

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKeyConfirmation describes a server that has no matching known_hosts entry.
// Key is internal proof material and must never come from the browser.
type HostKeyConfirmation struct {
	Role, Address, Fingerprint, Key string
}

func (e *HostKeyConfirmation) Error() string { return "host_key_confirmation_required" }

type lookupKey struct{}

func (lookupKey) Type() string                        { return "invalid-host-key-type" }
func (lookupKey) Marshal() []byte                     { return nil }
func (lookupKey) Verify([]byte, *ssh.Signature) error { return errors.New("not an SSH key") }

type knownHostAddress string

func (knownHostAddress) Network() string  { return "tcp" }
func (a knownHostAddress) String() string { return string(a) }

func sshHostTrust(address, pin, role string, learnKeys bool) (ssh.HostKeyCallback, []string, error) {
	if pin != "" {
		key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(pin))
		if err != nil || len(bytes.TrimSpace(rest)) != 0 {
			return nil, nil, fail("invalid_host_key")
		}
		fixed := ssh.FixedHostKey(key)
		return func(host string, remote net.Addr, presented ssh.PublicKey) error {
			if fixed(host, remote, presented) != nil {
				return fail("identity_changed")
			}
			if cert, ok := presented.(*ssh.Certificate); ok {
				name, _, _ := net.SplitHostPort(host)
				if err := new(ssh.CertChecker).CheckCert(name, cert); err != nil {
					return fail("host_key_untrusted")
				}
			}
			return nil
		}, hostKeyAlgorithms(key.Type()), nil
	}
	if !learnKeys {
		return nil, nil, fail("invalid_host_key")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, fail("known_hosts_unreadable")
	}
	var paths []string
	for _, name := range []string{"known_hosts", "known_hosts2"} {
		path := filepath.Join(home, ".ssh", name)
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			return nil, nil, fail("known_hosts_unreadable")
		}
		paths = append(paths, path)
	}
	known, err := knownhosts.New(paths...)
	if err != nil {
		return nil, nil, fail("known_hosts_unreadable")
	}
	var preferred []string
	var entries *knownhosts.KeyError
	// Query with an invalid key to get the recorded algorithms before negotiation.
	if errors.As(known(address, knownHostAddress(address), lookupKey{}), &entries) {
		for _, entry := range entries.Want {
			for _, alg := range hostKeyAlgorithms(entry.Key.Type()) {
				if !slices.Contains(preferred, alg) {
					preferred = append(preferred, alg)
				}
			}
		}
	}
	for _, alg := range ssh.SupportedAlgorithms().HostKeys {
		if !slices.Contains(preferred, alg) {
			preferred = append(preferred, alg)
		}
	}
	return func(host string, remote net.Addr, presented ssh.PublicKey) error {
		err := known(host, remote, presented)
		if err == nil {
			return nil
		}
		var keys *knownhosts.KeyError
		if errors.As(err, &keys) {
			if len(keys.Want) != 0 {
				return fail("identity_changed")
			}
			return &HostKeyConfirmation{Role: role, Address: address, Fingerprint: ssh.FingerprintSHA256(presented), Key: string(ssh.MarshalAuthorizedKey(presented))}
		}
		return fail("host_key_untrusted")
	}, preferred, nil
}

func hostKeyAlgorithms(keyType string) []string {
	switch keyType {
	case ssh.KeyAlgoRSA:
		return []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512}
	case ssh.CertAlgoRSAv01:
		return []string{ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSASHA512v01}
	default:
		return []string{keyType}
	}
}
