package pypi

import (
	"fmt"
	"strings"
)

// Publisher represents a PEP 740 publish attestation identity.
type Publisher struct {
	Issuer  string `json:"issuer"`  // OIDC issuer URL from the publish attestation
	Subject string `json:"subject"` // SAN of the signing certificate
}

// Entry represents a PyPI transparency log entry.
type Entry struct {
	Checksum  string     `json:"checksum"`            // e.g. sha256:abcdef...
	Filename  string     `json:"filename"`            // e.g. urllib3-2.6.3-py3-none-any.whl
	Publisher *Publisher `json:"publisher,omitempty"` // optional
}

const versionHeader = "pypi-transparency/v1"

// Marshal serializes the entry to the log wire format.
func (e Entry) Marshal() ([]byte, error) {
	if e.Checksum == "" {
		return nil, fmt.Errorf("checksum empty")
	}
	if strings.Contains(e.Checksum, "\n") {
		return nil, fmt.Errorf("checksum contains newline")
	}
	if e.Filename == "" {
		return nil, fmt.Errorf("filename empty")
	}
	if strings.Contains(e.Filename, "\n") {
		return nil, fmt.Errorf("filename contains newline")
	}
	s := fmt.Sprintf("%s\n%s\n%s", versionHeader, e.Checksum, e.Filename)
	if e.Publisher != nil {
		if e.Publisher.Issuer == "" {
			return nil, fmt.Errorf("publisher issuer empty")
		}
		if strings.Contains(e.Publisher.Issuer, "\n") {
			return nil, fmt.Errorf("publisher issuer contains newline")
		}
		if e.Publisher.Subject == "" {
			return nil, fmt.Errorf("publisher subject empty")
		}
		if strings.Contains(e.Publisher.Subject, "\n") {
			return nil, fmt.Errorf("publisher subject contains newline")
		}
		s += fmt.Sprintf(
			"\npublisher %s %s", e.Publisher.Issuer, e.Publisher.Subject)
	}
	return []byte(s), nil
}

// Unmarshal parses an entry from the log wire format.
func (e *Entry) Unmarshal(u []byte) error {
	lines := strings.Split(string(u), "\n")
	if len(lines) < 3 || len(lines) > 4 {
		return fmt.Errorf(
			"invalid entry: expected 3 or 4 lines, got %d", len(lines))
	}
	if lines[0] != versionHeader {
		return fmt.Errorf(
			"invalid entry: unrecognized version %q", lines[0])
	}
	e.Checksum = lines[1]
	e.Filename = lines[2]
	if len(lines) == 4 {
		rest, found := strings.CutPrefix(lines[3], "publisher ")
		if !found {
			return fmt.Errorf(
				"invalid entry: fourth line must start with \"publisher \"")
		}
		issuer, subject, found := strings.Cut(rest, " ")
		if !found {
			return fmt.Errorf(
				"invalid entry: publisher line must contain issuer and subject")
		}
		e.Publisher = &Publisher{Issuer: issuer, Subject: subject}
	}
	return nil
}
