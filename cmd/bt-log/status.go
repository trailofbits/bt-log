package main

import (
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	f_log "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/tessera"
	"golang.org/x/mod/sumdb/note"
)

type LogLatencyStats struct {
	Count               uint64  `json:"count"`
	Failures            uint64  `json:"failures"`
	LastMillis          float64 `json:"last_ms"`
	AverageMillis       float64 `json:"average_ms"`
	MinMillis           float64 `json:"min_ms"`
	MaxMillis           float64 `json:"max_ms"`
	ThroughputPerSecond float64 `json:"throughput_per_second"`
}

type latencyTracker struct {
	mu                  sync.Mutex
	count               uint64
	failures            uint64
	total               time.Duration
	last                time.Duration
	min                 time.Duration
	max                 time.Duration
	throughputPerSecond float64
}

type latencyBatch struct {
	count              uint64
	failures           uint64
	total              time.Duration
	last               time.Duration
	min                time.Duration
	max                time.Duration
	throughputEntries  uint64
	throughputDuration time.Duration
}

type diskUsageCache struct {
	mu         sync.Mutex
	ttl        time.Duration
	updated    time.Time
	usage      DiskUsage
	refreshing bool
}

func newLatencyTracker() *latencyTracker {
	return &latencyTracker{}
}

func (t *latencyTracker) finish(start time.Time, success bool) {
	d := time.Since(start)
	t.mu.Lock()
	defer t.mu.Unlock()
	if !success {
		t.failures++
		return
	}
	t.recordLocked(d)
}

func (b *latencyBatch) observe(d time.Duration) {
	b.count++
	b.total += d
	b.last = d
	if b.min == 0 || d < b.min {
		b.min = d
	}
	if d > b.max {
		b.max = d
	}
}

func (b *latencyBatch) addFailure() {
	b.failures++
}

func (t *latencyTracker) observeBatch(b latencyBatch) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if b.count > 0 {
		t.count += b.count
		t.total += b.total
		t.last = b.last
		if t.min == 0 || b.min < t.min {
			t.min = b.min
		}
		if b.max > t.max {
			t.max = b.max
		}
	}
	t.failures += b.failures
	t.recordThroughputLocked(b.throughputEntries, b.throughputDuration)
}

func (t *latencyTracker) addFailures(n uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failures += n
}

func (t *latencyTracker) recordLocked(d time.Duration) {
	t.count++
	t.total += d
	t.last = d
	if t.min == 0 || d < t.min {
		t.min = d
	}
	if d > t.max {
		t.max = d
	}
}

func (t *latencyTracker) recordThroughputLocked(entries uint64, d time.Duration) {
	if entries == 0 || d <= 0 {
		return
	}
	t.throughputPerSecond = float64(entries) / d.Seconds()
}

func (t *latencyTracker) snapshot() LogLatencyStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	var avg float64
	if t.count > 0 {
		avg = durationMillis(t.total) / float64(t.count)
	}
	return LogLatencyStats{
		Count:               t.count,
		Failures:            t.failures,
		LastMillis:          durationMillis(t.last),
		AverageMillis:       avg,
		MinMillis:           durationMillis(t.min),
		MaxMillis:           durationMillis(t.max),
		ThroughputPerSecond: t.throughputPerSecond,
	}
}

type DiskUsage struct {
	Bytes uint64 `json:"bytes"`
	Files uint64 `json:"files"`
	Error string `json:"error,omitempty"`
}

type CheckpointStatus struct {
	Available     bool   `json:"available"`
	TreeSize      uint64 `json:"tree_size,omitempty"`
	RootHash      string `json:"root_hash,omitempty"`
	RawCheckpoint string `json:"raw_checkpoint,omitempty"`
	Error         string `json:"error,omitempty"`
}

type StatusJSON struct {
	Origin            string           `json:"origin"`
	EntryType         string           `json:"entry_type"`
	StorageDir        string           `json:"storage_dir"`
	WitnessConfigured bool             `json:"witness_configured"`
	GeneratedAt       string           `json:"generated_at"`
	Checkpoint        CheckpointStatus `json:"checkpoint"`
	Latency           LogLatencyStats  `json:"latency"`
	BulkLatency       LogLatencyStats  `json:"bulk_latency"`
	Disk              DiskUsage        `json:"disk"`
}

type statusConfig struct {
	Origin            string
	EntryType         string
	StorageDir        string
	WitnessConfigured bool
	LogReader         tessera.LogReader
	Verifier          note.Verifier
	Latency           *latencyTracker
	BulkLatency       *latencyTracker
	DiskCache         diskUsageCache
}

func (c *statusConfig) buildStatus(ctx context.Context) StatusJSON {
	disk := c.DiskCache.get(c.StorageDir)
	status := StatusJSON{
		Origin:            c.Origin,
		EntryType:         c.EntryType,
		StorageDir:        c.StorageDir,
		WitnessConfigured: c.WitnessConfigured,
		GeneratedAt:       time.Now().UTC().Format(time.RFC3339),
		Latency:           c.Latency.snapshot(),
		BulkLatency:       c.BulkLatency.snapshot(),
		Disk:              disk,
	}
	rawCp, err := c.LogReader.ReadCheckpoint(ctx)
	if err != nil {
		status.Checkpoint.Error = err.Error()
		return status
	}
	cp, _, _, err := f_log.ParseCheckpoint(rawCp, c.Origin, c.Verifier)
	if err != nil {
		status.Checkpoint.Error = err.Error()
		return status
	}
	status.Checkpoint = CheckpointStatus{
		Available:     true,
		TreeSize:      cp.Size,
		RootHash:      hex.EncodeToString(cp.Hash),
		RawCheckpoint: string(rawCp),
	}
	return status
}

func registerStatusHandlers(cfg *statusConfig) {
	http.HandleFunc("GET /", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}

		status := cfg.buildStatus(req.Context())

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := statusPageTmpl.Execute(w, status); err != nil {
			log.Printf("status page: %v", err)
		}
	})

	http.HandleFunc("GET /status.json", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg.buildStatus(req.Context()))
	})
}

func durationMillis(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}

func formatMillis(v float64) string {
	if v == 0 {
		return "—"
	}
	if v < 1000 {
		return fmt.Sprintf("%.1f ms", v)
	}
	return fmt.Sprintf("%.2f s", v/1000)
}

func formatBytes(bytes uint64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	n := float64(bytes)
	i := 0
	for n >= 1024 && i < len(units)-1 {
		n /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s", n, units[i])
	}
	return fmt.Sprintf("%.1f %s", n, units[i])
}

func formatThroughput(v float64) string {
	if v == 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f entries/s", v)
}

func newDiskUsageCache(ttl time.Duration) diskUsageCache {
	return diskUsageCache{ttl: ttl}
}

func (c *diskUsageCache) get(root string) DiskUsage {
	c.mu.Lock()
	fresh := !c.updated.IsZero() && time.Since(c.updated) < c.ttl
	if fresh || c.refreshing {
		usage := c.usage
		c.mu.Unlock()
		return usage
	}
	c.refreshing = true
	c.mu.Unlock()

	usage := directoryUsage(root)

	c.mu.Lock()
	c.usage = usage
	c.updated = time.Now()
	c.refreshing = false
	c.mu.Unlock()
	return usage
}

func directoryUsage(root string) DiskUsage {
	var usage DiskUsage
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			usage.Bytes += uint64(info.Size())
			usage.Files++
		}
		return nil
	})
	if err != nil {
		usage.Error = err.Error()
	}
	return usage
}

//go:embed status.html
var statusPageHTML string

var statusPageTmpl = template.Must(template.New("status").Funcs(template.FuncMap{
	"formatMillis":     formatMillis,
	"formatBytes":      formatBytes,
	"formatThroughput": formatThroughput,
}).Parse(statusPageHTML))
