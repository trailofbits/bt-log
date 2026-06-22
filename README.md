# Binary Transparency for Package Registries

This repo contains an implementation of a transparency log for binary transparency
for package registries.

`cmd/bt-log` provides an HTTP server that accepts POST requests to an `/add` endpoint.
The JSON request must contain a PyPI package filename and SHA-256 checksum:

```json
{
    "filename": "my_package-1.2.3-py3-none-any.whl",
    "checksum": "sha256:3b9730808f265c6d174662668435c4cf1fc9ddcd369831a646fa84bff8594f0c"
}
```

An optional `publisher` object can be included for PEP 740 publish attestation identity metadata:

```json
{
    "filename": "my_package-1.2.3-py3-none-any.whl",
    "checksum": "sha256:3b9730808f265c6d174662668435c4cf1fc9ddcd369831a646fa84bff8594f0c",
    "publisher": {
        "issuer": "https://token.actions.githubusercontent.com",
        "subject": "https://github.com/example/project/.github/workflows/release.yml@refs/tags/v1.2.3"
    }
}
```

The JSON response will include the index of the entry, the inclusion proof, and the checkpoint
as per the [C2SP checkpoint spec](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md):

```json
{
    "index": 123,
    "checkpoint": "base64(checkpoint)",
    "inclusionProof": ["base64(hash)", "base64(hash)"]
}
```

The HTTP server also exposes endpoints per the [C2SP tlog-tiles spec](https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md):

* `/checkpoint`, which is updated every second
* `/tile`, which serves the raw tile data and entry bundles

## Log deployment

This will create a directory in the filesystem to store a log, and start the HTTP server
that can add entries to this log.

First, generate private and public keys:

```shell
go run ./cmd/gen-key --origin=binarytransparency.log/example
```

This will output private and public keys in Go's signed note format:

```shell
cat private.key
PRIVATE+KEY+binarytransparency.log/example+5de0f997+AXNNv9racVtMynH7oHIogZ4xS5sAIHBl47hlrcf6vsfu

cat public.key
binarytransparency.log/example+5de0f997+AcPfp2roeTxqSqmPdDkA9rIAd0pe3C5Je6Rze2SqBDUp
```

Then, start the log:

```shell
go run ./cmd/bt-log --storage-dir=/tmp/bt-log --private-key=private.key --public-key=public.key
```


### Witnessing

To prevent split-view attacks, where a log serves different views to different callers,
checkpoints must be witnessed, where an independent auditor verifies a consistency proof
that the log remains append-only and returns a cosignature over the checkpoint.

This repository contains a lightweight witness that implements the
[C2SP tlog-witness spec](https://github.com/C2SP/C2SP/blob/main/tlog-witness.md).

To initialize the witness, create a SQLite database and a signing key. The database will store
a log's verification key and origin, and the last size and tree hash the witness verified.

The commands below will initialize the log signing key, create the database, initialize the database, add a row with the
log's verification key, generate a witness signing key, and start the witness.

```shell
go run ./cmd/gen-key --origin=binarytransparency.log/example

sqlite3 -line witness.db '.database'
go run ./cmd/witness-add-key --database-path witness.db --public-key public.key

go run ./cmd/gen-key --origin=witness.log/example --private-key-path witness-private.key --public-key-path witness-public.key
go run ./cmd/witness-server --database-path witness.db --private-key witness-private.key --public-key witness-public.key
```

Then, start the log. The log will verify cosigned checkpoints using the provided witness verification key.

```shell
go run ./cmd/bt-log --storage-dir=/tmp/bt-log --private-key=private.key --public-key=public.key --witness-url="http://localhost:8081" --witness-public-key=witness-public.key
```

The checkpoint in the log's response will contain a co-signed checkpoint:

```shell
curl -XPOST http://localhost:8080/add -d "{\"filename\":\"pkgname-1.2.3-py3-none-any.whl\",\"checksum\":\"sha256:5141b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be92\"}" -o bundle

cat bundle | jq -r .checkpoint | base64 -d
```

The signed checkpoint will have two signatures, one from the log and one from the witness.

## Docker Deployment

Deployment-related files and docs live in [`deploy/`](deploy/). See [`deploy/README.md`](deploy/README.md) for Docker Compose instructions.

## Upcoming Work

* [ ] Lightweight monitor to demonstrate verifying ID-hash mapping is always 1-1 and alerting on publication
  * [x] ID-hash mapping verification
  * [x] Regex to match entries
  * [x] Use slog for output
  * [ ] Request PyPI file from registry and compare hash
  * [x] Add e2e to GHA script
* [ ] Add unit tests
* [x] Containerize for e2e tests
