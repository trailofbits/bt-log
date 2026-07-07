package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trailofbits/bt-log/internal/pypi"
	f_log "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/tessera"
	"golang.org/x/mod/sumdb/note"
)

func bulkTestEntry(filename string) pypi.Entry {
	sum := sha256.Sum256([]byte(filename))
	return pypi.Entry{Checksum: "sha256:" + hex.EncodeToString(sum[:]), Filename: filename}
}

func bulkTestEntryJSON(t *testing.T, filename string) string {
	t.Helper()
	b, err := json.Marshal(bulkTestEntry(filename))
	if err != nil {
		t.Fatalf("Marshal(%q): %v", filename, err)
	}
	return string(b)
}

func bulkTestItem(t *testing.T, filename string, valid bool) bulkAppendItem {
	t.Helper()
	e := bulkTestEntry(filename)
	raw, err := e.Marshal()
	if err != nil {
		t.Fatalf("Marshal(%q): %v", filename, err)
	}
	item := bulkAppendItem{entry: e, raw: raw, result: bulkAppendResult{Filename: filename}, valid: valid}
	if !valid {
		item.result = bulkAppendResult{Filename: filename, Status: "error", Error: "pre-existing validation error"}
	}
	return item
}

type fakeBulkAdd struct {
	mu      sync.Mutex
	indexes map[string]uint64
	errors  map[string]error
	calls   []string
}

func (f *fakeBulkAdd) add(ctx context.Context, entry *tessera.Entry) tessera.IndexFuture {
	var e pypi.Entry
	if err := e.Unmarshal(entry.Data()); err != nil {
		return func() (tessera.Index, error) { return tessera.Index{}, err }
	}
	f.mu.Lock()
	f.calls = append(f.calls, e.Filename)
	f.mu.Unlock()
	return func() (tessera.Index, error) {
		if err := f.errors[e.Filename]; err != nil {
			return tessera.Index{}, err
		}
		return tessera.Index{Index: f.indexes[e.Filename]}, nil
	}
}

func (f *fakeBulkAdd) calledFilenames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

type fakeBulkLogReader struct {
	mu          sync.Mutex
	checkpoints [][]byte
	errors      []error
	calls       int
}

func (f *fakeBulkLogReader) ReadCheckpoint(ctx context.Context) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if len(f.errors) > 0 {
		err := f.errors[0]
		f.errors = f.errors[1:]
		if err != nil {
			return nil, err
		}
	}
	if len(f.checkpoints) == 0 {
		return nil, errors.New("no checkpoint")
	}
	raw := f.checkpoints[0]
	if len(f.checkpoints) > 1 {
		f.checkpoints = f.checkpoints[1:]
	}
	return raw, nil
}

func (f *fakeBulkLogReader) ReadTile(ctx context.Context, level, index uint64, p uint8) ([]byte, error) {
	return nil, errors.New("ReadTile not implemented in test fake")
}

func (f *fakeBulkLogReader) ReadEntryBundle(ctx context.Context, index uint64, p uint8) ([]byte, error) {
	return nil, errors.New("ReadEntryBundle not implemented in test fake")
}

func (f *fakeBulkLogReader) NextIndex(ctx context.Context) (uint64, error)      { return 0, nil }
func (f *fakeBulkLogReader) IntegratedSize(ctx context.Context) (uint64, error) { return 0, nil }

func bulkCheckpointSigner(t *testing.T) (string, note.Signer, note.Verifier) {
	t.Helper()
	origin := "bulk-test-log"
	skey, vkey, err := note.GenerateKey(nil, origin)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return origin, signer, verifier
}

func signBulkCheckpoint(t *testing.T, origin string, signer note.Signer, size uint64) ([]byte, *f_log.Checkpoint) {
	t.Helper()
	cp := &f_log.Checkpoint{Origin: origin, Size: size, Hash: bytes.Repeat([]byte{byte(size)}, 32)}
	raw, err := note.Sign(&note.Note{Text: string(cp.Marshal())}, signer)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return raw, cp
}

func signedBulkCheckpoint(t *testing.T, size uint64) ([]byte, *f_log.Checkpoint, string, note.Verifier) {
	t.Helper()
	origin, signer, verifier := bulkCheckpointSigner(t)
	raw, cp := signBulkCheckpoint(t, origin, signer, size)
	return raw, cp, origin, verifier
}

func decodeBulkStream(t *testing.T, body string) []bulkAppendStreamRecord {
	t.Helper()
	var records []bulkAppendStreamRecord
	s := bufio.NewScanner(strings.NewReader(body))
	for s.Scan() {
		var rec bulkAppendStreamRecord
		if err := json.Unmarshal(s.Bytes(), &rec); err != nil {
			t.Fatalf("Unmarshal stream record %q: %v", s.Text(), err)
		}
		records = append(records, rec)
	}
	if err := s.Err(); err != nil {
		t.Fatalf("Scanner: %v", err)
	}
	return records
}

func TestStreamBulkAppendResponse(t *testing.T) {
	t.Run("all invalid entries with existing checkpoint streams checkpoint results and complete", func(t *testing.T) {
		rawCp := []byte("signed checkpoint bytes")
		cp := &f_log.Checkpoint{Size: 12}
		items := []bulkAppendItem{
			{result: bulkAppendResult{Filename: "bad-a.whl", Status: "error", Error: "checksum empty"}},
			{result: bulkAppendResult{Filename: "bad-b.whl", Status: "error", Error: "duplicate filename in request"}},
		}
		tileFetcherCalled := false
		w := httptest.NewRecorder()

		_, ok := streamBulkAppendResponse(context.Background(), w, items, 0, rawCp, cp, func(ctx context.Context, level, index uint64, p uint8) ([]byte, error) {
			tileFetcherCalled = true
			return nil, errors.New("tile fetcher should not be called")
		}, nil)
		if !ok {
			t.Fatal("ok = false, want true")
		}
		if got := w.Header().Get("Content-Type"); got != "application/x-ndjson" {
			t.Errorf("Content-Type = %q, want %q", got, "application/x-ndjson")
		}
		if tileFetcherCalled {
			t.Error("tile fetcher was called for loggedCount == 0")
		}

		records := decodeBulkStream(t, w.Body.String())
		if len(records) != 4 {
			t.Fatalf("len(records) = %d, want 4; body:\n%s", len(records), w.Body.String())
		}
		if records[0].Type != "checkpoint" {
			t.Errorf("records[0].Type = %q, want checkpoint", records[0].Type)
		}
		if !bytes.Equal(records[0].Checkpoint, rawCp) {
			t.Errorf("records[0].Checkpoint = %q, want %q", records[0].Checkpoint, rawCp)
		}
		if records[0].TreeSize != 12 {
			t.Errorf("records[0].TreeSize = %d, want 12", records[0].TreeSize)
		}
		for i, want := range []bulkAppendResult{items[0].result, items[1].result} {
			rec := records[i+1]
			if rec.Type != "result" {
				t.Errorf("records[%d].Type = %q, want result", i+1, rec.Type)
			}
			if rec.Result == nil {
				t.Fatalf("records[%d].Result = nil, want non-nil", i+1)
			}
			if rec.Result.Filename != want.Filename {
				t.Errorf("records[%d].Result.Filename = %q, want %q", i+1, rec.Result.Filename, want.Filename)
			}
			if rec.Result.Status != want.Status {
				t.Errorf("records[%d].Result.Status = %q, want %q", i+1, rec.Result.Status, want.Status)
			}
			if rec.Result.Error != want.Error {
				t.Errorf("records[%d].Result.Error = %q, want %q", i+1, rec.Result.Error, want.Error)
			}
		}
		if records[3].Type != "complete" {
			t.Errorf("records[3].Type = %q, want complete", records[3].Type)
		}
		if records[3].Count != 2 {
			t.Errorf("records[3].Count = %d, want 2", records[3].Count)
		}
	})

	t.Run("all invalid entries without existing checkpoint streams results and complete", func(t *testing.T) {
		items := []bulkAppendItem{{result: bulkAppendResult{Filename: "bad.whl", Status: "error", Error: "filename empty"}}}
		w := httptest.NewRecorder()
		_, ok := streamBulkAppendResponse(context.Background(), w, items, 0, nil, nil, nil, nil)
		if !ok {
			t.Fatal("ok = false, want true")
		}
		if got := w.Header().Get("Content-Type"); got != "application/x-ndjson" {
			t.Errorf("Content-Type = %q, want %q", got, "application/x-ndjson")
		}
		records := decodeBulkStream(t, w.Body.String())
		if len(records) != 2 {
			t.Fatalf("len(records) = %d, want 2; body:\n%s", len(records), w.Body.String())
		}
		if records[0].Type != "result" {
			t.Errorf("records[0].Type = %q, want result", records[0].Type)
		}
		if records[0].Result == nil {
			t.Fatal("records[0].Result = nil, want non-nil")
		}
		if records[0].Result.Filename != "bad.whl" {
			t.Errorf("records[0].Result.Filename = %q, want bad.whl", records[0].Result.Filename)
		}
		if records[0].Result.Status != "error" {
			t.Errorf("records[0].Result.Status = %q, want error", records[0].Result.Status)
		}
		if records[0].Result.Error != "filename empty" {
			t.Errorf("records[0].Result.Error = %q, want filename empty", records[0].Result.Error)
		}
		if records[1].Type != "complete" {
			t.Errorf("records[1].Type = %q, want complete", records[1].Type)
		}
		if records[1].Count != 1 {
			t.Errorf("records[1].Count = %d, want 1", records[1].Count)
		}
	})
}

func TestBulkAppendCheckpoint(t *testing.T) {
	origin, signer, verifier := bulkCheckpointSigner(t)
	rawSize2, _ := signBulkCheckpoint(t, origin, signer, 2)
	rawSize5, _ := signBulkCheckpoint(t, origin, signer, 5)

	t.Run("logged entries wait for checkpoint through max index", func(t *testing.T) {
		reader := &fakeBulkLogReader{checkpoints: [][]byte{rawSize2, rawSize5}}
		rawCp, cp, httpErr := bulkAppendCheckpoint(context.Background(), reader, origin, verifier, true, 4, time.Second)
		if httpErr != nil {
			t.Fatalf("httpErr = %+v, want nil", httpErr)
		}
		if !bytes.Equal(rawCp, rawSize5) {
			t.Errorf("raw checkpoint = %q, want size-5 checkpoint %q", rawCp, rawSize5)
		}
		if cp == nil {
			t.Fatal("cp = nil, want non-nil")
		}
		if cp.Size != 5 {
			t.Errorf("cp.Size = %d, want 5", cp.Size)
		}
		if reader.calls != 2 {
			t.Errorf("reader.calls = %d, want 2", reader.calls)
		}
	})

	t.Run("logged entries timeout maps to gateway timeout", func(t *testing.T) {
		reader := &fakeBulkLogReader{checkpoints: [][]byte{rawSize2}}
		rawCp, cp, httpErr := bulkAppendCheckpoint(context.Background(), reader, origin, verifier, true, 4, time.Millisecond)
		if rawCp != nil {
			t.Errorf("rawCp = %q, want nil", rawCp)
		}
		if cp != nil {
			t.Errorf("cp = %+v, want nil", cp)
		}
		if httpErr == nil {
			t.Fatal("httpErr = nil, want non-nil")
		}
		if httpErr.status != http.StatusGatewayTimeout {
			t.Errorf("httpErr.status = %d, want %d", httpErr.status, http.StatusGatewayTimeout)
		}
		if httpErr.msg != context.DeadlineExceeded.Error() {
			t.Errorf("httpErr.msg = %q, want %q", httpErr.msg, context.DeadlineExceeded.Error())
		}
	})

	t.Run("no logged entries returns current valid checkpoint", func(t *testing.T) {
		reader := &fakeBulkLogReader{checkpoints: [][]byte{rawSize2}}
		rawCp, cp, httpErr := bulkAppendCheckpoint(context.Background(), reader, origin, verifier, false, 0, time.Second)
		if httpErr != nil {
			t.Fatalf("httpErr = %+v, want nil", httpErr)
		}
		if !bytes.Equal(rawCp, rawSize2) {
			t.Errorf("raw checkpoint = %q, want %q", rawCp, rawSize2)
		}
		if cp == nil {
			t.Fatal("cp = nil, want non-nil")
		}
		if cp.Size != 2 {
			t.Errorf("cp.Size = %d, want 2", cp.Size)
		}
	})

	t.Run("no logged entries tolerates unavailable checkpoint", func(t *testing.T) {
		reader := &fakeBulkLogReader{errors: []error{errors.New("not found")}}
		rawCp, cp, httpErr := bulkAppendCheckpoint(context.Background(), reader, origin, verifier, false, 0, time.Second)
		if httpErr != nil {
			t.Fatalf("httpErr = %+v, want nil", httpErr)
		}
		if rawCp != nil {
			t.Errorf("rawCp = %q, want nil", rawCp)
		}
		if cp != nil {
			t.Errorf("cp = %+v, want nil", cp)
		}
	})

	t.Run("no logged entries tolerates invalid checkpoint", func(t *testing.T) {
		reader := &fakeBulkLogReader{checkpoints: [][]byte{[]byte("not a signed checkpoint")}}
		rawCp, cp, httpErr := bulkAppendCheckpoint(context.Background(), reader, origin, verifier, false, 0, time.Second)
		if httpErr != nil {
			t.Fatalf("httpErr = %+v, want nil", httpErr)
		}
		if rawCp != nil {
			t.Errorf("rawCp = %q, want nil", rawCp)
		}
		if cp != nil {
			t.Errorf("cp = %+v, want nil", cp)
		}
	})
}

func TestSummarizeBulkAppendResults(t *testing.T) {
	tests := []struct {
		name            string
		items           []bulkAppendItem
		wantLoggedCount int
		wantMaxIndex    uint64
		wantHaveIndex   bool
	}{
		{
			name: "no logged entries",
			items: []bulkAppendItem{
				{result: bulkAppendResult{Filename: "a.whl", Status: "error", Error: "bad"}},
				{result: bulkAppendResult{Filename: "b.whl"}},
			},
			wantLoggedCount: 0,
			wantMaxIndex:    0,
			wantHaveIndex:   false,
		},
		{
			name: "mixed statuses",
			items: []bulkAppendItem{
				{result: bulkAppendResult{Filename: "a.whl", Index: 2, Status: "logged"}},
				{result: bulkAppendResult{Filename: "b.whl", Status: "error", Error: "bad"}},
				{result: bulkAppendResult{Filename: "c.whl", Index: 1, Status: "logged"}},
			},
			wantLoggedCount: 2,
			wantMaxIndex:    2,
			wantHaveIndex:   true,
		},
		{
			name: "highest index selection",
			items: []bulkAppendItem{
				{result: bulkAppendResult{Filename: "low.whl", Index: 4, Status: "logged"}},
				{result: bulkAppendResult{Filename: "high.whl", Index: 99, Status: "logged"}},
				{result: bulkAppendResult{Filename: "middle.whl", Index: 50, Status: "logged"}},
			},
			wantLoggedCount: 3,
			wantMaxIndex:    99,
			wantHaveIndex:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLoggedCount, gotMaxIndex, gotHaveIndex := summarizeBulkAppendResults(tt.items)
			if gotLoggedCount != tt.wantLoggedCount {
				t.Errorf("loggedCount = %d, want %d", gotLoggedCount, tt.wantLoggedCount)
			}
			if gotMaxIndex != tt.wantMaxIndex {
				t.Errorf("maxIndex = %d, want %d", gotMaxIndex, tt.wantMaxIndex)
			}
			if gotHaveIndex != tt.wantHaveIndex {
				t.Errorf("haveIndex = %v, want %v", gotHaveIndex, tt.wantHaveIndex)
			}
		})
	}
}

func TestAppendBulkEntries(t *testing.T) {
	tests := []struct {
		name        string
		workerCount uint
		items       []bulkAppendItem
		indexes     map[string]uint64
		errors      map[string]error
		wantCalls   []string
		wantResults []bulkAppendResult
	}{
		{
			name:        "only valid items are appended",
			workerCount: 2,
			items: []bulkAppendItem{
				bulkTestItem(t, "valid-a.whl", true),
				bulkTestItem(t, "invalid.whl", false),
				bulkTestItem(t, "valid-b.whl", true),
			},
			indexes:   map[string]uint64{"valid-a.whl": 7, "valid-b.whl": 8},
			wantCalls: []string{"valid-a.whl", "valid-b.whl"},
			wantResults: []bulkAppendResult{
				{Filename: "valid-a.whl", Index: 7, Status: "logged"},
				{Filename: "invalid.whl", Status: "error", Error: "pre-existing validation error"},
				{Filename: "valid-b.whl", Index: 8, Status: "logged"},
			},
		},
		{
			name:        "append future error is per-item error",
			workerCount: 1,
			items:       []bulkAppendItem{bulkTestItem(t, "fails.whl", true)},
			errors:      map[string]error{"fails.whl": errors.New("append failed")},
			wantCalls:   []string{"fails.whl"},
			wantResults: []bulkAppendResult{{Filename: "fails.whl", Status: "error", Error: "append failed"}},
		},
		{
			name:        "zero workers falls back to one worker",
			workerCount: 0,
			items:       []bulkAppendItem{bulkTestItem(t, "zero-workers.whl", true)},
			indexes:     map[string]uint64{"zero-workers.whl": 42},
			wantCalls:   []string{"zero-workers.whl"},
			wantResults: []bulkAppendResult{{Filename: "zero-workers.whl", Index: 42, Status: "logged"}},
		},
		{
			name:        "more workers than items is safe",
			workerCount: 10,
			items:       []bulkAppendItem{bulkTestItem(t, "one.whl", true)},
			indexes:     map[string]uint64{"one.whl": 3},
			wantCalls:   []string{"one.whl"},
			wantResults: []bulkAppendResult{{Filename: "one.whl", Index: 3, Status: "logged"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeBulkAdd{indexes: tt.indexes, errors: tt.errors}
			appendBulkEntries(context.Background(), fake.add, tt.items, tt.workerCount)

			calls := fake.calledFilenames()
			if len(calls) != len(tt.wantCalls) {
				t.Fatalf("len(calls) = %d (%v), want %d (%v)", len(calls), calls, len(tt.wantCalls), tt.wantCalls)
			}
			callSet := map[string]int{}
			for _, got := range calls {
				callSet[got]++
			}
			for _, want := range tt.wantCalls {
				if callSet[want] != 1 {
					t.Errorf("calls for %q = %d, want 1; all calls %v", want, callSet[want], calls)
				}
			}

			if len(tt.items) != len(tt.wantResults) {
				t.Fatalf("len(items) = %d, want %d", len(tt.items), len(tt.wantResults))
			}
			for i, want := range tt.wantResults {
				got := tt.items[i].result
				if got.Filename != want.Filename {
					t.Errorf("items[%d].result.Filename = %q, want %q", i, got.Filename, want.Filename)
				}
				if got.Index != want.Index {
					t.Errorf("items[%d].result.Index = %d, want %d", i, got.Index, want.Index)
				}
				if got.Status != want.Status {
					t.Errorf("items[%d].result.Status = %q, want %q", i, got.Status, want.Status)
				}
				if got.Error != want.Error {
					t.Errorf("items[%d].result.Error = %q, want %q", i, got.Error, want.Error)
				}
			}
		})
	}
}

func TestParseBulkAppendRequest(t *testing.T) {
	validA := bulkTestEntryJSON(t, "a.whl")
	validB := bulkTestEntryJSON(t, "b.whl")
	tests := []struct {
		name           string
		body           string
		maxEntries     uint
		wantHTTPStatus int
		wantHTTPMsg    string
		want           []bulkAppendResult
		wantValid      []bool
	}{
		{
			name:       "valid records and blank lines",
			body:       "\n" + validA + "\n\n" + validB + "\n",
			maxEntries: 5,
			want: []bulkAppendResult{
				{Filename: "a.whl"},
				{Filename: "b.whl"},
			},
			wantValid: []bool{true, true},
		},
		{
			name:       "malformed json is per-record error",
			body:       validA + "\n{bad json\n" + validB + "\n",
			maxEntries: 5,
			want: []bulkAppendResult{
				{Filename: "a.whl"},
				{Status: "error", Error: "invalid character 'b' looking for beginning of object key string"},
				{Filename: "b.whl"},
			},
			wantValid: []bool{true, false, true},
		},
		{
			name:       "invalid pypi entry is per-record error",
			body:       `{"checksum":"","filename":"empty-checksum.whl"}` + "\n",
			maxEntries: 5,
			want: []bulkAppendResult{
				{Filename: "empty-checksum.whl", Status: "error", Error: "checksum empty"},
			},
			wantValid: []bool{false},
		},
		{
			name:       "duplicate filename is per-record error",
			body:       validA + "\n" + validA + "\n",
			maxEntries: 5,
			want: []bulkAppendResult{
				{Filename: "a.whl"},
				{Filename: "a.whl", Status: "error", Error: "duplicate filename in request"},
			},
			wantValid: []bool{true, false},
		},
		{
			name:           "max entries exceeded aborts request",
			body:           validA + "\n" + validB + "\n",
			maxEntries:     1,
			wantHTTPStatus: http.StatusRequestEntityTooLarge,
			wantHTTPMsg:    "bulk append is limited to 1 entries",
		},
		{
			name:           "oversized scanner token aborts request",
			body:           strings.Repeat("a", 1024*1024+1),
			maxEntries:     5,
			wantHTTPStatus: http.StatusBadRequest,
			wantHTTPMsg:    "bufio.Scanner: token too long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items, httpErr := parseBulkAppendRequest(strings.NewReader(tt.body), tt.maxEntries)
			if tt.wantHTTPStatus != 0 {
				if httpErr == nil {
					t.Fatal("httpErr = nil, want non-nil")
				}
				if httpErr.status != tt.wantHTTPStatus {
					t.Errorf("httpErr.status = %d, want %d", httpErr.status, tt.wantHTTPStatus)
				}
				if httpErr.msg != tt.wantHTTPMsg {
					t.Errorf("httpErr.msg = %q, want %q", httpErr.msg, tt.wantHTTPMsg)
				}
				if items != nil {
					t.Errorf("items = %v, want nil", items)
				}
				return
			}
			if httpErr != nil {
				t.Fatalf("httpErr = %+v, want nil", httpErr)
			}
			if len(items) != len(tt.want) {
				t.Fatalf("len(items) = %d, want %d", len(items), len(tt.want))
			}
			for i, item := range items {
				if item.result.Filename != tt.want[i].Filename {
					t.Errorf("items[%d].result.Filename = %q, want %q", i, item.result.Filename, tt.want[i].Filename)
				}
				if item.result.Status != tt.want[i].Status {
					t.Errorf("items[%d].result.Status = %q, want %q", i, item.result.Status, tt.want[i].Status)
				}
				if item.result.Error != tt.want[i].Error {
					t.Errorf("items[%d].result.Error = %q, want %q", i, item.result.Error, tt.want[i].Error)
				}
				if item.valid != tt.wantValid[i] {
					t.Errorf("items[%d].valid = %v, want %v", i, item.valid, tt.wantValid[i])
				}
				if item.valid && item.entry.Filename != tt.want[i].Filename {
					t.Errorf("items[%d].entry.Filename = %q, want %q", i, item.entry.Filename, tt.want[i].Filename)
				}
				if item.valid && len(item.raw) == 0 {
					t.Errorf("items[%d].raw is empty for valid item", i)
				}
			}
		})
	}
}
