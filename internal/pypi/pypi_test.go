package pypi

import (
	"testing"
)

func TestMarshalRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		entry Entry
	}{
		{
			name: "without publisher",
			entry: Entry{
				Checksum: "sha256:abcdef1234567890",
				Filename: "urllib3-2.6.3-py3-none-any.whl",
			},
		},
		{
			name: "with publisher",
			entry: Entry{
				Checksum: "sha256:abcdef1234567890",
				Filename: "urllib3-2.6.3-py3-none-any.whl",
				Publisher: &Publisher{
					Issuer:  "https://token.actions.githubusercontent.com",
					Subject: "repo:org/repo",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.entry.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			var got Entry
			if err := got.Unmarshal(b); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if got.Checksum != tt.entry.Checksum {
				t.Errorf("Checksum = %q, want %q",
					got.Checksum, tt.entry.Checksum)
			}
			if got.Filename != tt.entry.Filename {
				t.Errorf("Filename = %q, want %q",
					got.Filename, tt.entry.Filename)
			}
			if tt.entry.Publisher == nil {
				if got.Publisher != nil {
					t.Errorf("Publisher = %v, want nil",
						got.Publisher)
				}
			} else {
				if got.Publisher == nil {
					t.Fatal("Publisher = nil, want non-nil")
				}
				if got.Publisher.Issuer != tt.entry.Publisher.Issuer {
					t.Errorf("Publisher.Issuer = %q, want %q",
						got.Publisher.Issuer,
						tt.entry.Publisher.Issuer)
				}
				if got.Publisher.Subject != tt.entry.Publisher.Subject {
					t.Errorf("Publisher.Subject = %q, want %q",
						got.Publisher.Subject,
						tt.entry.Publisher.Subject)
				}
			}
		})
	}
}

func TestMarshalErrors(t *testing.T) {
	tests := []struct {
		name    string
		entry   Entry
		wantErr string
	}{
		{
			name:    "empty checksum",
			entry:   Entry{Filename: "foo.whl"},
			wantErr: "checksum empty",
		},
		{
			name:    "empty filename",
			entry:   Entry{Checksum: "sha256:abc"},
			wantErr: "filename empty",
		},
		{
			name: "checksum with newline",
			entry: Entry{
				Checksum: "sha256:abc\ndef",
				Filename: "foo.whl",
			},
			wantErr: "checksum contains newline",
		},
		{
			name: "filename with newline",
			entry: Entry{
				Checksum: "sha256:abc",
				Filename: "foo\n.whl",
			},
			wantErr: "filename contains newline",
		},
		{
			name: "empty publisher issuer",
			entry: Entry{
				Checksum:  "sha256:abc",
				Filename:  "foo.whl",
				Publisher: &Publisher{Subject: "repo:org/repo"},
			},
			wantErr: "publisher issuer empty",
		},
		{
			name: "empty publisher subject",
			entry: Entry{
				Checksum:  "sha256:abc",
				Filename:  "foo.whl",
				Publisher: &Publisher{Issuer: "https://token.actions.githubusercontent.com"},
			},
			wantErr: "publisher subject empty",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.entry.Marshal()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tt.wantErr {
				t.Errorf("error = %q, want %q",
					err.Error(), tt.wantErr)
			}
		})
	}
}

func TestUnmarshalErrors(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "too few lines",
			input:   "pypi-transparency/v1\nsha256:abc",
			wantErr: "invalid entry: expected 3 or 4 lines, got 2",
		},
		{
			name: "too many lines",
			input: "pypi-transparency/v1\nsha256:abc\n" +
				"foo.whl\npublisher github repo\nextra",
			wantErr: "invalid entry: expected 3 or 4 lines, got 5",
		},
		{
			name:    "wrong version",
			input:   "pypi-transparency/v2\nsha256:abc\nfoo.whl",
			wantErr: `invalid entry: unrecognized version "pypi-transparency/v2"`,
		},
		{
			name: "bad publisher prefix",
			input: "pypi-transparency/v1\nsha256:abc\n" +
				"foo.whl\nnotpublisher github repo",
			wantErr: `invalid entry: fourth line must start with "publisher "`,
		},
		{
			name: "publisher missing subject",
			input: "pypi-transparency/v1\nsha256:abc\n" +
				"foo.whl\npublisher github",
			wantErr: "invalid entry: publisher line must contain issuer and subject",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e Entry
			err := e.Unmarshal([]byte(tt.input))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tt.wantErr {
				t.Errorf("error = %q, want %q",
					err.Error(), tt.wantErr)
			}
		})
	}
}
