package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/trailofbits/bt-log/internal/pypi"
	f_log "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
)

type bulkAppendResult struct {
	Filename       string   `json:"filename"`
	Index          uint64   `json:"index"`
	Status         string   `json:"status"`
	InclusionProof [][]byte `json:"inclusionProof,omitempty"`
	Error          string   `json:"error,omitempty"`
}

type bulkAppendStreamRecord struct {
	Type       string            `json:"type"`
	Checkpoint []byte            `json:"checkpoint,omitempty"`
	TreeSize   uint64            `json:"tree_size,omitempty"`
	Result     *bulkAppendResult `json:"result,omitempty"`
	Count      uint64            `json:"count,omitempty"`
}

type bulkAppendTask struct {
	pos   int
	entry pypi.Entry
	raw   []byte
}

type httpError struct {
	status int
	msg    string
}

// waitForTreeSize polls the log checkpoint until the tree size is at least
// `size`.
func waitForTreeSize(ctx context.Context, reader tessera.LogReader, origin string, verifier note.Verifier, size uint64) ([]byte, *f_log.Checkpoint, error) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		rawCp, err := reader.ReadCheckpoint(ctx)
		if err == nil {
			cp, _, _, err := f_log.ParseCheckpoint(rawCp, origin, verifier)
			if err == nil && cp.Size >= size {
				return rawCp, cp, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

// parseBulkAppendRequest reads newline-delimited PyPI entry JSON records from
// body, validates and marshals each entry, and returns append tasks plus
// placeholder/error results in request order.
func parseBulkAppendRequest(body io.Reader, maxEntries uint) ([]bulkAppendTask, []bulkAppendResult, *httpError) {
	var tasks []bulkAppendTask
	var results []bulkAppendResult
	seen := map[string]struct{}{}
	entryCount := 0
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		entryCount++
		if entryCount > int(maxEntries) {
			return nil, nil, &httpError{status: http.StatusRequestEntityTooLarge, msg: fmt.Sprintf("bulk append is limited to %d entries", maxEntries)}
		}
		var e pypi.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			results = append(results, bulkAppendResult{Status: "error", Error: err.Error()})
			continue
		}
		raw, err := e.Marshal()
		if err != nil {
			results = append(results, bulkAppendResult{Filename: e.Filename, Status: "error", Error: err.Error()})
			continue
		}
		if _, ok := seen[e.Filename]; ok {
			results = append(results, bulkAppendResult{Filename: e.Filename, Status: "error", Error: "duplicate filename in request"})
			continue
		}
		seen[e.Filename] = struct{}{}
		tasks = append(tasks, bulkAppendTask{pos: len(results), entry: e, raw: raw})
		results = append(results, bulkAppendResult{Filename: e.Filename})
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, &httpError{status: http.StatusBadRequest, msg: err.Error()}
	}
	return tasks, results, nil
}

// appendBulkEntries appends to the log all valid bulk tasks using up to
// `workerCount` concurrent workers and writes each task's logged/error result
// into `results`.
func appendBulkEntries(ctx context.Context, addFn tessera.AddFn, tasks []bulkAppendTask, results []bulkAppendResult, workerCount uint) {
	var wg sync.WaitGroup
	workers := int(workerCount)
	if workers < 1 {
		workers = 1
	}
	if workers > len(tasks) {
		workers = len(tasks)
	}
	taskCh := make(chan bulkAppendTask)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskCh {
				f := addFn(ctx, tessera.NewEntry(task.raw))
				idx, err := f()
				if err != nil {
					results[task.pos] = bulkAppendResult{Filename: task.entry.Filename, Status: "error", Error: err.Error()}
					continue
				}
				results[task.pos] = bulkAppendResult{Filename: task.entry.Filename, Index: idx.Index, Status: "logged"}
			}
		}()
	}
	for _, task := range tasks {
		taskCh <- task
	}
	close(taskCh)
	wg.Wait()
}

// summarizeBulkAppendResults counts logged entries and returns the highest log
// index observed, if any entries were successfully logged.
func summarizeBulkAppendResults(results []bulkAppendResult) (loggedCount int, maxIndex uint64, haveIndex bool) {
	for _, result := range results {
		if result.Status != "logged" {
			continue
		}
		loggedCount++
		if !haveIndex || result.Index > maxIndex {
			maxIndex = result.Index
			haveIndex = true
		}
	}
	return loggedCount, maxIndex, haveIndex
}

// bulkAppendCheckpoint returns a verified checkpoint suitable for the bulk
// response. If entries were logged, it waits for publication through `maxIndex`;
// otherwise it returns the current checkpoint when one is available.
func bulkAppendCheckpoint(ctx context.Context, reader tessera.LogReader, origin string, verifier note.Verifier, haveIndex bool, maxIndex uint64, publishTimeout time.Duration) ([]byte, *f_log.Checkpoint, *httpError) {
	if haveIndex {
		publishCtx, cancel := context.WithTimeout(ctx, publishTimeout)
		defer cancel()
		rawCp, cp, err := waitForTreeSize(publishCtx, reader, origin, verifier, maxIndex+1)
		if err != nil {
			return nil, nil, &httpError{status: http.StatusGatewayTimeout, msg: err.Error()}
		}
		return rawCp, cp, nil
	}

	// No entries were appended. Return per-record validation results even if this is
	// a fresh log with no checkpoint yet.
	if rawCp, err := reader.ReadCheckpoint(ctx); err == nil {
		if cp, _, _, err := f_log.ParseCheckpoint(rawCp, origin, verifier); err == nil {
			return rawCp, cp, nil
		}
	}
	return nil, nil, nil
}

// streamBulkAppendResponse writes the bulk append NDJSON response. It emits the
// checkpoint first, then builds inclusion proofs one result at a time and streams
// each result as soon as it is ready.
func streamBulkAppendResponse(ctx context.Context, w http.ResponseWriter, results []bulkAppendResult, loggedCount int, rawCp []byte, cp *f_log.Checkpoint, tileFetcher client.TileFetcherFunc) (time.Duration, bool) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	enc := json.NewEncoder(w)
	flusher, _ := w.(http.Flusher)
	if cp != nil {
		_ = enc.Encode(bulkAppendStreamRecord{Type: "checkpoint", Checkpoint: rawCp, TreeSize: cp.Size})
		if flusher != nil {
			flusher.Flush()
		}
	}

	proofStart := time.Now()
	if loggedCount > 0 {
		pb, err := client.NewProofBuilder(ctx, cp.Size, tileFetcher)
		if err != nil {
			_ = enc.Encode(bulkAppendStreamRecord{Type: "error", Result: &bulkAppendResult{Status: "error", Error: err.Error()}})
			return time.Since(proofStart), false
		}
		for i := range results {
			if results[i].Status == "logged" {
				inclusionProof, err := pb.InclusionProof(ctx, results[i].Index)
				if err != nil {
					results[i].Status = "error"
					results[i].Error = err.Error()
				} else {
					results[i].InclusionProof = inclusionProof
				}
			}
			_ = enc.Encode(bulkAppendStreamRecord{Type: "result", Result: &results[i]})
			if flusher != nil && i%100 == 0 {
				flusher.Flush()
			}
		}
	} else {
		for i := range results {
			_ = enc.Encode(bulkAppendStreamRecord{Type: "result", Result: &results[i]})
			if flusher != nil && i%100 == 0 {
				flusher.Flush()
			}
		}
	}
	proofElapsed := time.Since(proofStart)
	_ = enc.Encode(bulkAppendStreamRecord{Type: "complete", Count: uint64(len(results))})
	return proofElapsed, true
}
