package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/trailofbits/bt-log/internal/pypi"
	f_log "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/client"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

var (
	host                     = flag.String("host", "localhost", "host to listen on")
	port                     = flag.Uint("port", 8080, "port to listen on")
	storageDir               = flag.String("storage-dir", "", "Root directory to store log data")
	privKeyFile              = flag.String("private-key", "", "Location of private key file")
	pubKeyFile               = flag.String("public-key", "", "Location of public key file")
	witnessUrl               = flag.String("witness-url", "", "Optional witness to cosign checkpoint")
	witnessPubKeyFile        = flag.String("witness-public-key", "", "Optional witness public key location to verify cosignatures")
	bulkAppendWorkersFlag    = flag.Uint("bulk-append-workers", 8192, "Maximum concurrent workers for /admin/bulk/append")
	bulkAppendMaxEntriesFlag = flag.Uint("bulk-append-max-entries", 50000, "Maximum entries accepted per /admin/bulk/append request")
	bulkAppendPublishTimeout = flag.Duration("bulk-append-publish-timeout", 30*time.Second, "Maximum time to wait for bulk appended entries to be published")
)

func addCacheHeaders(value string, fs http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Cache-Control", value)
		fs.ServeHTTP(w, r)
	}
}

type PyPILogEntry = pypi.Entry

type LogEntryResponse struct {
	Index          uint64   `json:"index"`
	Checkpoint     []byte   `json:"checkpoint"`
	InclusionProof [][]byte `json:"inclusionProof"`
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func main() {
	flag.Parse()

	if *storageDir == "" {
		log.Fatalf("--storage-dir must be set")
	}
	if *privKeyFile == "" {
		log.Fatalf("--private-key must be set")
	}
	if *pubKeyFile == "" {
		log.Fatalf("--public-key must be set")
	}
	if (*witnessUrl != "" && *witnessPubKeyFile == "") ||
		(*witnessUrl == "" && *witnessPubKeyFile != "") {
		log.Fatalf("--witness-url and --witness-public-key must both be set")
	}

	ctx := context.Background()

	// Create NoteSigner/Verifier for signing/verifying checkpoints
	privKey, err := os.ReadFile(*privKeyFile)
	if err != nil {
		log.Fatalf("failed to read private key file for %s: %v", *privKeyFile, err)
	}
	s, err := note.NewSigner(string(privKey))
	if err != nil {
		log.Fatalf("failed to read signer %s: %v", *privKeyFile, err)
	}

	pubKey, err := os.ReadFile(*pubKeyFile)
	if err != nil {
		log.Fatalf("failed to read public key file for %s: %v", *pubKeyFile, err)
	}
	v, err := note.NewVerifier(string(pubKey))
	if err != nil {
		log.Fatalf("failed to read verifier %s: %v", *pubKeyFile, err)
	}

	// Create witness
	var witness *tessera.Witness
	if *witnessPubKeyFile != "" && *witnessUrl != "" {
		witnessPubKey, err := os.ReadFile(*witnessPubKeyFile)
		if err != nil {
			log.Fatal(err)
		}
		wUrl, err := url.Parse(*witnessUrl)
		if err != nil {
			log.Fatal(err)
		}
		wit, err := tessera.NewWitness(string(witnessPubKey), wUrl)
		if err != nil {
			log.Fatalf("error creating witness: %v", err)
		}
		witness = &wit
	}

	// Create the Tessera POSIX storage, using the directory from the --storage-dir flag
	driver, err := posix.New(ctx, posix.Config{
		Path: *storageDir,
	})
	if err != nil {
		log.Fatalf("failed to construct driver: %v", err)
	}

	opts := tessera.NewAppendOptions().
		WithCheckpointSigner(s).
		WithCheckpointInterval(time.Second).
		WithBatching(1024, 100*time.Millisecond).
		WithAntispam(256, nil)
	if witness != nil {
		opts = opts.WithWitnesses(tessera.NewWitnessGroup(1, witness), &tessera.WitnessOptions{FailOpen: false})
	}
	appender, shutdown, logReader, err := tessera.NewAppender(ctx, driver, opts)
	if err != nil {
		log.Fatalf("failed to create appender: %v", err)
	}
	addFn := appender.Add
	tileFetcher := logReader.ReadTile
	await := tessera.NewPublicationAwaiter(ctx, logReader.ReadCheckpoint, 200*time.Millisecond)
	addLatency := newLatencyTracker()
	bulkLatency := newLatencyTracker()
	registerStatusHandlers(&statusConfig{
		Origin:            v.Name(),
		EntryType:         pypi.EntryType,
		StorageDir:        *storageDir,
		WitnessConfigured: witness != nil,
		LogReader:         logReader,
		Verifier:          v,
		Latency:           addLatency,
		BulkLatency:       bulkLatency,
		DiskCache:         newDiskUsageCache(1 * time.Minute),
	})

	http.HandleFunc("GET /.well-known/public-key", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(pubKey)
	})

	// Define a handler for /add that accepts POST requests and adds the POST body to the log.
	http.HandleFunc("POST /add", func(w http.ResponseWriter, r *http.Request) {
		requestStart := time.Now()
		success := false
		defer func() { addLatency.finish(requestStart, success) }()

		b, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		e := &PyPILogEntry{}
		if err := json.Unmarshal(b, e); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		// TODO: Verify filename against regex, verify checksum.

		m, err := e.Marshal()
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		f := addFn(r.Context(), tessera.NewEntry(m))
		idx, rawCp, err := await.Await(ctx, f)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		cp, _, _, err := f_log.ParseCheckpoint(rawCp, v.Name(), v)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		pb, err := client.NewProofBuilder(r.Context(), cp.Size, tileFetcher)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		inclusionProof, err := pb.InclusionProof(r.Context(), idx.Index)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		leafHash := rfc6962.DefaultHasher.HashLeaf(m)
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher, idx.Index, cp.Size, leafHash, inclusionProof, cp.Hash); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(LogEntryResponse{Index: idx.Index, InclusionProof: inclusionProof, Checkpoint: rawCp}); err != nil {
			log.Printf("encode add response: %v", err)
			return
		}
		success = true
	})

	http.HandleFunc("POST /admin/bulk/append", func(w http.ResponseWriter, req *http.Request) {
		requestStart := time.Now()

		contentType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
		if err != nil || contentType != "application/x-ndjson" {
			writeJSONError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/x-ndjson")
			return
		}

		items, parseErr := parseBulkAppendRequest(req.Body, *bulkAppendMaxEntriesFlag)
		if parseErr != nil {
			writeJSONError(w, parseErr.status, parseErr.msg)
			return
		}
		parseElapsed := time.Since(requestStart)

		appendStart := time.Now()
		appendBulkEntries(req.Context(), addFn, items, *bulkAppendWorkersFlag)
		appendElapsed := time.Since(appendStart)

		loggedCount, maxIndex, haveIndex := summarizeBulkAppendResults(items)

		checkpointStart := time.Now()
		// Gets the checkpoint that contains all the entries in the bulk request
		rawCp, cp, checkpointErr := bulkAppendCheckpoint(req.Context(), logReader, v.Name(), v, haveIndex, maxIndex, *bulkAppendPublishTimeout)
		if checkpointErr != nil {
			bulkLatency.addFailures(uint64(loggedCount))
			writeJSONError(w, checkpointErr.status, checkpointErr.msg)
			return
		}
		checkpointElapsed := time.Since(checkpointStart)

		var bulkBatch latencyBatch
		proofElapsed, ok := streamBulkAppendResponse(req.Context(), w, items, loggedCount, rawCp, cp, tileFetcher, func(result bulkAppendResult) {
			if result.Status == "logged" {
				bulkBatch.observe(time.Since(requestStart))
			} else {
				bulkBatch.addFailure()
			}
		})
		if !ok {
			bulkLatency.addFailures(uint64(loggedCount))
			return
		}
		bulkBatch.throughputEntries = uint64(loggedCount)
		bulkBatch.throughputDuration = time.Since(requestStart)
		bulkLatency.observeBatch(bulkBatch)

		log.Printf(
			"bulk append: entries=%d logged=%d parse=%s append=%s checkpoint=%s proof=%s total=%s",
			len(items), loggedCount, parseElapsed, appendElapsed, checkpointElapsed, proofElapsed, time.Since(requestStart),
		)
	})

	// Proxy all GET requests to the filesystem as a lightweight file server.
	fs := http.FileServer(http.Dir(*storageDir))
	http.Handle("GET /checkpoint", addCacheHeaders("no-cache", fs))
	http.Handle("GET /tile/", addCacheHeaders("max-age=31536000, immutable", fs))

	address := fmt.Sprintf("%s:%d", *host, *port)
	fmt.Printf("Server running at %s\n", address)

	// Gracefully shutdown for SIGINT/SIGTERM
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	srv := &http.Server{
		Addr:    address,
		Handler: http.DefaultServeMux,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("error in ListenAndServe: %v", err)
		}
	}()

	// Wait until SIGINT/SIGTERM, then shutdown server and invoke Tessera cleanup
	sig := <-signalChan
	fmt.Printf("received %s, shutting down", sig)
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal(err)
	}
	if err := shutdown(ctx); err != nil {
		log.Fatal(err)
	}
}
