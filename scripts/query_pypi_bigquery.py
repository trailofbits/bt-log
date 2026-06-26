# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "cryptography",
#     "google-auth",
#     "httpx",
#     "packaging",
#     "requests",
#     "rich",
# ]
# ///
"""Sync PyPI distribution metadata into SQLite, enrich it with PyPI
provenance, and optionally submit entries to bt-log.

The script is intentionally split into resumable subcommands:

    bigquery    ingest raw package/file rows from BigQuery
    provenance  enrich unchecked rows with provenance status
    submit      submit unlogged rows to bt-log and optionally store C2SP proofs

Each command commits incremental progress so an interrupted run can be safely
started again.
"""

import argparse
import base64
import hashlib
import json
import logging
import os
import sqlite3
import time
from collections import defaultdict
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from urllib.parse import urljoin

import google.auth
import google.auth.credentials
import google.auth.transport.requests
import httpx
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier
from packaging.utils import canonicalize_name
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

NUM_WORKERS = 10
WORKER_DELAY = 0.25
BQ_BASE = "https://bigquery.googleapis.com/bigquery/v2/projects"
CONSOLE = Console(stderr=True)
SIGSTORE_OIDC_ISSUER_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.1")

logging.basicConfig(
    level=logging.WARNING,
    format="%(message)s",
    handlers=[RichHandler(console=CONSOLE, show_time=False, show_path=False, markup=False)],
)
log = logging.getLogger(__name__)


@dataclass
class Publisher:
    issuer: str
    subject: str


@dataclass
class LogEntry:
    filename: str
    sha256_digest: str
    upload_time: str
    publisher: Publisher | None = None


@dataclass
class RawEntry:
    package_name: str
    filename: str
    sha256_digest: str
    upload_time: str


@dataclass
class ProvenanceTarget:
    package_name: str
    filename: str
    sha256_digest: str


@dataclass
class SubmitFuture:
    batch: list[LogEntry]
    start: float
    future: Future["SubmitBatchResult"]


@dataclass
class SubmitBatchResult:
    tree_size: int
    checkpoint: str
    proofs: dict[int, list[str]]
    results: list[tuple[LogEntry, int | None, str | None]]


@dataclass
class ProofEntry:
    filename: str
    sha256_digest: str
    log_index: int


def add_common_args(p: argparse.ArgumentParser):
    p.add_argument(
        "--db",
        default=os.environ.get("PYPI_INGEST_DB", "pypi_entries.db"),
        help="path to SQLite database (default: $PYPI_INGEST_DB or pypi_entries.db)",
    )
    p.add_argument(
        "--log-level",
        default=os.environ.get("PYPI_INGEST_LOG_LEVEL", "INFO"),
        help="Python logging level (default: INFO)",
    )


def parse_args():
    p = argparse.ArgumentParser(
        description="Sync PyPI metadata from BigQuery to SQLite, enrich provenance, and submit to bt-log",
    )
    sub = p.add_subparsers(dest="command", required=True)

    bq = sub.add_parser("bigquery", help="populate SQLite with raw BigQuery rows")
    add_common_args(bq)
    bq.add_argument("--since", help="initial lower bound when no cursor exists; Unix seconds or ISO/RFC3339")
    bq.add_argument("--batch-size", type=int, default=50_000, help="rows per committed BigQuery batch")
    bq.add_argument("--max-rows", type=int, help="maximum rows to ingest in this run")
    bq.add_argument("--no-count", action="store_true", help="skip initial COUNT(*) used for progress ETA")

    prov = sub.add_parser("provenance", help="populate provenance for unchecked SQLite entries")
    add_common_args(prov)
    prov.add_argument("--batch-size", type=int, default=5_000, help="unchecked DB rows to load per loop")
    prov.add_argument("--max-entries", type=int, help="maximum entries to process in this run")
    prov.add_argument("--retry-failed", action="store_true", help="also retry rows with provenance_status='failed'")
    prov.add_argument("--no-count", action="store_true", help="skip initial COUNT(*) used for progress ETA")

    submit = sub.add_parser("submit", help="submit unlogged SQLite entries to bt-log")
    add_common_args(submit)
    submit.add_argument(
        "--log-url",
        default=os.environ.get("BT_LOG_URL", "http://localhost:8080"),
        help="base URL of bt-log (default: $BT_LOG_URL or http://localhost:8080)",
    )
    submit.add_argument("--timeout", type=float, default=float(os.environ.get("PYPI_INGEST_TIMEOUT", "300")))
    submit.add_argument("--retries", type=int, default=int(os.environ.get("PYPI_INGEST_RETRIES", "3")))
    submit.add_argument(
        "--retry-backoff",
        type=float,
        default=float(os.environ.get("PYPI_INGEST_RETRY_BACKOFF", "1")),
    )
    submit.add_argument("--max-submit", type=int, help="maximum unlogged entries to submit in this run")
    submit.add_argument(
        "--submit-batch-size",
        type=int,
        default=int(os.environ.get("PYPI_INGEST_SUBMIT_BATCH_SIZE", "50000")),
        help="number of entries per bulk append request (default: $PYPI_INGEST_SUBMIT_BATCH_SIZE or 50000)",
    )
    submit.add_argument(
        "--submit-concurrency",
        type=int,
        default=int(os.environ.get("PYPI_INGEST_SUBMIT_CONCURRENCY", "1")),
        help="number of bulk append requests to keep in flight (default: $PYPI_INGEST_SUBMIT_CONCURRENCY or 1)",
    )
    submit.add_argument(
        "--proof-dir",
        help="store C2SP .tlog-proof inclusion proof files for successfully submitted entries under this directory",
    )
    submit.add_argument("--no-count", action="store_true", help="skip initial COUNT(*) used for progress ETA")

    reset_submit = sub.add_parser(
        "reset-submit",
        help="clear local submission status so entries can be submitted to bt-log again",
    )
    add_common_args(reset_submit)
    return p.parse_args()


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            package_name          TEXT NOT NULL,
            filename              TEXT NOT NULL,
            sha256_digest         TEXT NOT NULL,
            publisher_issuer      TEXT,
            publisher_subject     TEXT,
            upload_time           TEXT NOT NULL,
            provenance_status     TEXT NOT NULL DEFAULT 'unchecked',
            provenance_checked_at TEXT,
            provenance_error      TEXT,
            UNIQUE(filename)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS logged_entries (
            filename      TEXT NOT NULL,
            sha256_digest TEXT NOT NULL,
            logged_at     TEXT NOT NULL,
            log_index     TEXT,
            UNIQUE(filename)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cursor (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    _migrate_entries(conn)
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_entries_filename_unique ON entries (filename)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_logged_entries_filename_unique ON logged_entries (filename)")
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_entries_submit_order
        ON entries (upload_time, filename)
        WHERE provenance_status IN ('found', 'none')
    """)
    conn.commit()
    return conn


def _migrate_entries(conn: sqlite3.Connection):
    cols = {row[1] for row in conn.execute("PRAGMA table_info(entries)")}
    migrations = {
        "package_name": "ALTER TABLE entries ADD COLUMN package_name TEXT",
        "provenance_status": "ALTER TABLE entries ADD COLUMN provenance_status TEXT NOT NULL DEFAULT 'unchecked'",
        "provenance_checked_at": "ALTER TABLE entries ADD COLUMN provenance_checked_at TEXT",
        "provenance_error": "ALTER TABLE entries ADD COLUMN provenance_error TEXT",
        "publisher_issuer": "ALTER TABLE entries ADD COLUMN publisher_issuer TEXT",
    }
    for col, sql in migrations.items():
        if col not in cols:
            conn.execute(sql)
    if "publisher_kind" in cols:
        conn.execute(
            """UPDATE entries
               SET publisher_issuer = NULL,
                   publisher_subject = NULL,
                   provenance_status = 'unchecked',
                   provenance_checked_at = NULL,
                   provenance_error = NULL
               WHERE provenance_status = 'found'
                 AND publisher_issuer IS NULL"""
        )


def get_cursor_value(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM cursor WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def set_cursor_values(conn: sqlite3.Connection, values: dict[str, str]):
    for key, value in values.items():
        conn.execute(
            """INSERT INTO cursor (key, value) VALUES (?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (key, value),
        )


def get_bq_auth() -> tuple[google.auth.credentials.Credentials, str]:
    """Return (credentials, project_id) from ADC."""
    scopes = [
        "https://www.googleapis.com/auth/bigquery.readonly",
        "https://www.googleapis.com/auth/cloud-platform.read-only",
    ]
    creds, project = google.auth.default(scopes=scopes)
    if getattr(creds, "requires_scopes", False):
        creds = creds.with_scopes(scopes)
    creds.refresh(google.auth.transport.requests.Request())
    if not project:
        project = _discover_project(creds)
    return creds, project


def _discover_project(creds: google.auth.credentials.Credentials) -> str:
    resp = httpx.get(
        "https://cloudresourcemanager.googleapis.com/v1/projects",
        params={"pageSize": 1},
        headers=_bq_headers(creds),
        timeout=10,
    )
    resp.raise_for_status()
    projects = resp.json().get("projects", [])
    if not projects:
        raise RuntimeError("No GCP projects found. Set a default project with: gcloud config set project PROJECT_ID")
    return projects[0]["projectId"]


def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=CONSOLE,
    )


def _upload_time_to_micros(upload_time: str) -> int:
    return int(
        (Decimal(str(upload_time)) * Decimal(1_000_000)).to_integral_value(
            rounding=ROUND_HALF_UP
        )
    )


def _normalize_upload_time(upload_time: str) -> str:
    micros = _upload_time_to_micros(upload_time)
    return f"{micros // 1_000_000}.{micros % 1_000_000:06d}"


def _format_upload_time(upload_time: str | None) -> str:
    if not upload_time:
        return ""
    try:
        dt = datetime.fromtimestamp(float(upload_time), tz=timezone.utc)
        return f"{_normalize_upload_time(upload_time)} ({dt.isoformat()})"
    except Exception:
        return upload_time


def _sql_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _refresh_bq_creds(creds: google.auth.credentials.Credentials, *, force: bool = False):
    if force or not creds.valid:
        creds.refresh(google.auth.transport.requests.Request())


def _bq_headers(creds: google.auth.credentials.Credentials) -> dict:
    _refresh_bq_creds(creds)
    return {
        "Authorization": f"Bearer {creds.token}",
        "Content-Type": "application/json",
    }


def _bq_request(
    creds: google.auth.credentials.Credentials,
    method: str,
    url: str,
    json_body: dict | None = None,
    params: dict | None = None,
    max_retries: int = 3,
) -> dict:
    refreshed_after_401 = False
    for attempt in range(max_retries):
        try:
            with httpx.Client(timeout=120) as client:
                resp = client.request(
                    method,
                    url,
                    headers=_bq_headers(creds),
                    json=json_body,
                    params=params,
                )
                if resp.status_code == 401 and not refreshed_after_401:
                    CONSOLE.print("BigQuery returned 401; refreshing Google credentials and retrying...")
                    _refresh_bq_creds(creds, force=True)
                    refreshed_after_401 = True
                    resp = client.request(
                        method,
                        url,
                        headers=_bq_headers(creds),
                        json=json_body,
                        params=params,
                    )
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as e:
            if attempt == max_retries - 1:
                raise
            wait = 2 ** (attempt + 1)
            CONSOLE.print(f"BigQuery request failed: {e}. Retrying in {wait}s...")
            time.sleep(wait)
    raise RuntimeError("unreachable")


def _bigquery_where(
    last_upload_time: str | None,
    last_filename: str | None,
    last_sha256_digest: str | None,
) -> str:
    where = "WHERE sha256_digest IS NOT NULL"
    if last_upload_time:
        micros = _upload_time_to_micros(last_upload_time)
        ts = f"TIMESTAMP_MICROS({micros})"
        filename = _sql_string(last_filename or "")
        digest = _sql_string(last_sha256_digest or "")
        where += f"""
              AND (
                upload_time > {ts}
                OR (upload_time = {ts} AND filename > {filename})
                OR (upload_time = {ts} AND filename = {filename} AND sha256_digest > {digest})
              )"""
    return where


def query_bigquery_count(
    creds: google.auth.credentials.Credentials,
    project: str,
    last_upload_time: str | None,
    last_filename: str | None,
    last_sha256_digest: str | None,
) -> int:
    where = _bigquery_where(last_upload_time, last_filename, last_sha256_digest)
    query = f"""
            SELECT COUNT(1) AS row_count
            FROM `bigquery-public-data.pypi.distribution_metadata`
            {where}
        """
    data = _bq_request(
        creds,
        "POST",
        f"{BQ_BASE}/{project}/queries",
        json_body={"query": query, "useLegacySql": False, "maxResults": 1},
    )
    job_id = data["jobReference"]["jobId"]
    while not data.get("jobComplete"):
        time.sleep(2)
        data = _bq_request(
            creds,
            "GET",
            f"{BQ_BASE}/{project}/queries/{job_id}",
            params={"maxResults": 1},
        )
    rows = data.get("rows", [])
    return int(rows[0]["f"][0]["v"]) if rows else 0


def query_bigquery_batch(
    creds: google.auth.credentials.Credentials,
    project: str,
    last_upload_time: str | None,
    last_filename: str | None,
    last_sha256_digest: str | None,
    batch_size: int,
) -> list[RawEntry]:
    where = _bigquery_where(last_upload_time, last_filename, last_sha256_digest)
    query = f"""
            SELECT name, filename, sha256_digest, upload_time
            FROM `bigquery-public-data.pypi.distribution_metadata`
            {where}
            ORDER BY upload_time ASC, filename ASC, sha256_digest ASC
            LIMIT {batch_size}
        """
    data = _bq_request(
        creds,
        "POST",
        f"{BQ_BASE}/{project}/queries",
        json_body={"query": query, "useLegacySql": False, "maxResults": batch_size},
    )
    job_id = data["jobReference"]["jobId"]
    while not data.get("jobComplete"):
        time.sleep(2)
        data = _bq_request(
            creds,
            "GET",
            f"{BQ_BASE}/{project}/queries/{job_id}",
            params={"maxResults": batch_size},
        )

    fields = [f["name"] for f in data["schema"]["fields"]]
    rows: list[RawEntry] = []
    while True:
        for row in data.get("rows", []):
            values = [cell["v"] for cell in row["f"]]
            d = dict(zip(fields, values))
            rows.append(
                RawEntry(
                    d["name"],
                    d["filename"],
                    d["sha256_digest"],
                    _normalize_upload_time(d["upload_time"]),
                )
            )
        page_token = data.get("pageToken")
        if not page_token:
            break
        data = _bq_request(
            creds,
            "GET",
            f"{BQ_BASE}/{project}/queries/{job_id}",
            params={"maxResults": batch_size, "pageToken": page_token},
        )
    return rows


def insert_raw_entries_and_cursor(conn: sqlite3.Connection, rows: list[RawEntry]) -> int:
    inserted = 0
    with conn:
        for row in rows:
            conn.execute(
                """INSERT OR IGNORE INTO entries
                   (package_name, filename, sha256_digest, upload_time, provenance_status)
                   VALUES (?, ?, ?, ?, 'unchecked')""",
                (row.package_name, row.filename, row.sha256_digest, row.upload_time),
            )
            if conn.execute("SELECT changes()").fetchone()[0] > 0:
                inserted += 1
        last = rows[-1]
        set_cursor_values(
            conn,
            {
                "bigquery_last_upload_time": last.upload_time,
                "bigquery_last_filename": last.filename,
                "bigquery_last_sha256_digest": last.sha256_digest,
            },
        )
    return inserted


def run_bigquery(args) -> None:
    conn = init_db(args.db)
    last_upload_time = get_cursor_value(conn, "bigquery_last_upload_time")
    last_filename = get_cursor_value(conn, "bigquery_last_filename")
    last_digest = get_cursor_value(conn, "bigquery_last_sha256_digest")
    if not last_upload_time:
        last_upload_time = _since_to_upload_time(args.since)
        if last_upload_time:
            last_filename = ""
            last_digest = ""
    if last_upload_time:
        CONSOLE.print(
            f"Resuming BigQuery from {_format_upload_time(last_upload_time)} / "
            f"{last_filename or ''} / {last_digest or ''}"
        )
    else:
        CONSOLE.print("First BigQuery run: fetching all entries")

    creds, project = get_bq_auth()
    CONSOLE.print(f"Using project: {project}")
    progress_total = None
    if not args.no_count:
        CONSOLE.print("Counting remaining BigQuery rows for progress ETA...")
        progress_total = query_bigquery_count(creds, project, last_upload_time, last_filename, last_digest)
        if args.max_rows is not None:
            progress_total = min(progress_total, args.max_rows)
        CONSOLE.print(f"Rows to ingest this run: {progress_total}")

    total_fetched = total_inserted = 0
    start = time.monotonic()
    with make_progress() as progress:
        task = progress.add_task("Ingesting BigQuery rows", total=progress_total)
        while True:
            remaining = None if args.max_rows is None else args.max_rows - total_fetched
            if remaining is not None and remaining <= 0:
                break
            batch_size = min(args.batch_size, remaining) if remaining is not None else args.batch_size
            rows = query_bigquery_batch(creds, project, last_upload_time, last_filename, last_digest, batch_size)
            if not rows:
                break
            inserted = insert_raw_entries_and_cursor(conn, rows)
            total_fetched += len(rows)
            total_inserted += inserted
            last = rows[-1]
            last_upload_time, last_filename, last_digest = last.upload_time, last.filename, last.sha256_digest
            progress.update(task, advance=len(rows))
            log.debug(
                "Committed BigQuery batch: fetched=%d inserted=%d cursor=%s",
                len(rows),
                inserted,
                _format_upload_time(last_upload_time),
            )
            if len(rows) < batch_size:
                break
    conn.close()
    CONSOLE.print(f"Done: fetched={total_fetched}, inserted={total_inserted}, elapsed={time.monotonic() - start:.1f}s")


def publisher_from_cert(filename: str, cert_b64: str) -> Publisher | None:
    try:
        cert_bytes = base64.b64decode(cert_b64)
        cert = x509.load_der_x509_certificate(cert_bytes)
    except Exception:
        log.warning("Failed to parse certificate for %s", filename)
        return None
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
    except x509.ExtensionNotFound:
        return None
    if not uris:
        return None
    subject = uris[0]
    issuer = _cert_oidc_issuer(cert)
    if issuer is None:
        log.warning("Certificate for %s does not contain Sigstore OIDC issuer extension", filename)
        return None
    return Publisher(issuer=issuer, subject=subject)


def _cert_oidc_issuer(cert: x509.Certificate) -> str | None:
    try:
        ext = cert.extensions.get_extension_for_oid(SIGSTORE_OIDC_ISSUER_OID)
    except x509.ExtensionNotFound:
        return None
    value = ext.value
    if not isinstance(value, x509.UnrecognizedExtension):
        return None
    return _decode_asn1_string(value.value)


def _decode_asn1_string(raw: bytes) -> str | None:
    """Decode the simple DER-encoded string used by Sigstore cert extensions."""
    if len(raw) >= 2 and raw[0] in (0x0C, 0x16):  # UTF8String or IA5String
        length = raw[1]
        offset = 2
        if length & 0x80:
            n = length & 0x7F
            if len(raw) < 2 + n:
                return None
            length = int.from_bytes(raw[2 : 2 + n], "big")
            offset = 2 + n
        raw = raw[offset : offset + length]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _fetch_provenance_bundle(filename: str, prov_url: str, client: httpx.Client) -> Publisher | None:
    try:
        resp = client.get(prov_url)
        resp.raise_for_status()
        bundle = resp.json()
    except Exception:
        log.warning("Failed to fetch provenance for %s", filename)
        return None
    att_bundles = bundle.get("attestation_bundles", [])
    if not att_bundles:
        return None
    attestations = att_bundles[0].get("attestations", [])
    if not attestations:
        return None
    cert_b64 = attestations[0].get("verification_material", {}).get("certificate", "")
    if not cert_b64:
        return None
    return publisher_from_cert(filename, cert_b64)


def fetch_package_provenance(
    pkg_name: str,
    filenames: set[str],
    client: httpx.Client,
) -> tuple[bool, dict[str, Publisher | None], str | None]:
    """Return (ok, filename->publisher/None, error)."""
    url = f"https://pypi.org/simple/{canonicalize_name(pkg_name)}/"
    headers = {"Accept": "application/vnd.pypi.simple.v1+json"}
    try:
        resp = client.get(url, headers=headers)
    except httpx.HTTPError as e:
        return False, {}, str(e)
    if resp.status_code != 200:
        return False, {}, f"Simple API returned {resp.status_code}"
    try:
        data = resp.json()
    except Exception as e:
        return False, {}, f"failed to parse Simple API JSON: {e}"

    result: dict[str, Publisher | None] = {name: None for name in filenames}
    for f in data.get("files", []):
        fname = f.get("filename", "")
        if fname not in filenames:
            continue
        prov_url = f.get("provenance")
        result[fname] = _fetch_provenance_bundle(fname, prov_url, client) if prov_url else None
    return True, result, None


def _provenance_statuses(retry_failed: bool) -> str:
    return "'unchecked', 'failed'" if retry_failed else "'unchecked'"


def mark_pre_provenance_entries_without_provenance(conn: sqlite3.Connection) -> int:
    """Mark artifacts uploaded before PyPI provenance storage as no-provenance."""
    cutoff = _since_to_upload_time("2024-08-20T00:00:00Z")
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            """UPDATE entries
               SET publisher_issuer = NULL,
                   publisher_subject = NULL,
                   provenance_status = 'none',
                   provenance_checked_at = ?,
                   provenance_error = NULL
               WHERE provenance_status = 'unchecked'
                 AND CAST(upload_time AS REAL) < CAST(? AS REAL)""",
            (now, cutoff),
        )
        return conn.execute("SELECT changes()").fetchone()[0]


def count_provenance_targets(conn: sqlite3.Connection, retry_failed: bool) -> int:
    statuses = _provenance_statuses(retry_failed)
    row = conn.execute(
        f"""SELECT COUNT(1)
            FROM entries
            WHERE package_name IS NOT NULL
              AND provenance_status IN ({statuses})"""
    ).fetchone()
    return int(row[0]) if row else 0


def load_provenance_targets(conn: sqlite3.Connection, limit: int, retry_failed: bool) -> list[ProvenanceTarget]:
    statuses = _provenance_statuses(retry_failed)
    rows = conn.execute(
        f"""SELECT package_name, filename, sha256_digest
            FROM entries
            WHERE package_name IS NOT NULL
              AND provenance_status IN ({statuses})
            ORDER BY upload_time ASC, filename ASC, sha256_digest ASC
            LIMIT ?""",
        (limit,),
    ).fetchall()
    return [ProvenanceTarget(*row) for row in rows]


def update_package_provenance(
    conn: sqlite3.Connection,
    targets: list[ProvenanceTarget],
    ok: bool,
    prov_map: dict[str, Publisher | None],
    error: str | None,
):
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        for target in targets:
            pub = prov_map.get(target.filename)
            if ok:
                status = "found" if pub else "none"
                conn.execute(
                    """UPDATE entries
                       SET publisher_issuer = ?, publisher_subject = ?,
                           provenance_status = ?, provenance_checked_at = ?, provenance_error = NULL
                       WHERE filename = ?""",
                    (
                        pub.issuer if pub else None,
                        pub.subject if pub else None,
                        status,
                        now,
                        target.filename,
                    ),
                )
            else:
                conn.execute(
                    """UPDATE entries
                       SET provenance_status = 'failed', provenance_checked_at = ?, provenance_error = ?
                       WHERE filename = ?""",
                    (now, error, target.filename),
                )


def run_provenance(args) -> None:
    conn = init_db(args.db)
    pre_provenance_marked = mark_pre_provenance_entries_without_provenance(conn)
    if pre_provenance_marked:
        CONSOLE.print(
            f"Marked {pre_provenance_marked} entries uploaded before 2024-08-20 as having no provenance"
        )
    processed = found = none = failed = 0
    start = time.monotonic()
    progress_total = None
    if not args.no_count:
        CONSOLE.print("Counting provenance entries for progress ETA...")
        progress_total = count_provenance_targets(conn, args.retry_failed)
        if args.max_entries is not None:
            progress_total = min(progress_total, args.max_entries)
        CONSOLE.print(f"Entries to process this run: {progress_total}")

    def worker(pkg_name: str, pkg_targets: list[ProvenanceTarget]):
        client = httpx.Client(timeout=30, follow_redirects=True)
        try:
            names = {t.filename for t in pkg_targets}
            ok, prov_map, error = fetch_package_provenance(pkg_name, names, client)
            return pkg_name, ok, prov_map, error
        finally:
            client.close()
            time.sleep(WORKER_DELAY)

    with make_progress() as progress:
        task = progress.add_task("Fetching provenance", total=progress_total)
        while True:
            remaining = None if args.max_entries is None else args.max_entries - processed
            if remaining is not None and remaining <= 0:
                break
            limit = min(args.batch_size, remaining) if remaining is not None else args.batch_size
            targets = load_provenance_targets(conn, limit, args.retry_failed)
            if not targets:
                break
            grouped: dict[str, list[ProvenanceTarget]] = defaultdict(list)
            for target in targets:
                grouped[target.package_name].append(target)
            with ThreadPoolExecutor(max_workers=NUM_WORKERS) as pool:
                futures = {pool.submit(worker, pkg, pkg_targets): (pkg, pkg_targets) for pkg, pkg_targets in grouped.items()}
                for future in as_completed(futures):
                    pkg, pkg_targets = futures[future]
                    _, ok, prov_map, error = future.result()
                    update_package_provenance(conn, pkg_targets, ok, prov_map, error)
                    processed += len(pkg_targets)
                    if ok:
                        found += sum(1 for t in pkg_targets if prov_map.get(t.filename))
                        none += sum(1 for t in pkg_targets if not prov_map.get(t.filename))
                    else:
                        failed += len(pkg_targets)
                        log.warning("provenance failed for %s: %s", pkg, error)
                    progress.update(task, advance=len(pkg_targets))
    conn.close()
    CONSOLE.print(
        f"Done: processed={processed}, found={found}, none={none}, failed={failed}, elapsed={time.monotonic() - start:.1f}s"
    )


def _sqlite_table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return row is not None


def reset_submit_status(conn: sqlite3.Connection) -> tuple[bool, int]:
    """Clear only local state that tracks whether entries were submitted to bt-log."""
    with conn:
        dropped_logged_entries = False
        if _sqlite_table_exists(conn, "logged_entries"):
            # This can contain tens of millions of rows. DROP TABLE is much faster than
            # DELETE FROM and the normal init path will recreate the table on next use.
            conn.execute("DROP TABLE logged_entries")
            dropped_logged_entries = True

        cursor_deleted = 0
        if _sqlite_table_exists(conn, "cursor"):
            cursor_deleted = conn.execute(
                "DELETE FROM cursor WHERE key IN ('submit_last_upload_time', 'submit_last_filename')"
            ).rowcount
    return dropped_logged_entries, cursor_deleted


def run_reset_submit(args) -> None:
    CONSOLE.print(f"Opening SQLite database: {args.db}")
    # Avoid init_db() here: it may create indexes over huge tables before we get a
    # chance to reset them, which makes this command look like it is hanging.
    conn = sqlite3.connect(args.db, timeout=30)
    conn.execute("PRAGMA busy_timeout=30000")
    dropped_logged_entries, cursor_deleted = reset_submit_status(conn)
    conn.close()
    CONSOLE.print(
        "Reset submit status: "
        f"{'dropped logged_entries' if dropped_logged_entries else 'logged_entries did not exist'}, "
        f"deleted {cursor_deleted} submit cursor rows"
    )


def build_bulk_append_url(log_url: str) -> str:
    return urljoin(log_url.rstrip("/") + "/", "admin/bulk/append")


def entry_payload(entry: LogEntry) -> dict:
    payload = {"checksum": f"sha256:{entry.sha256_digest}", "filename": entry.filename}
    if entry.publisher:
        payload["publisher"] = {"issuer": entry.publisher.issuer, "subject": entry.publisher.subject}
    return payload


def record_logged_many(conn: sqlite3.Connection, results: list[tuple[LogEntry, int | None]]):
    logged_at = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.executemany(
            """INSERT INTO logged_entries (filename, sha256_digest, logged_at, log_index)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(filename) DO UPDATE SET
                 sha256_digest = excluded.sha256_digest,
                 logged_at = excluded.logged_at,
                 log_index = excluded.log_index""",
            [
                (entry.filename, entry.sha256_digest, logged_at, str(log_index) if log_index is not None else None)
                for entry, log_index in results
            ],
        )


def _unlogged_entries_query() -> str:
    return """SELECT e.filename, e.sha256_digest, e.upload_time,
                  e.publisher_issuer, e.publisher_subject
           FROM entries e
           LEFT JOIN logged_entries l
             ON l.filename = e.filename
           WHERE l.filename IS NULL
             AND e.provenance_status IN ('found', 'none')"""


def _submit_order_clause() -> str:
    return " ORDER BY e.upload_time ASC, e.filename ASC"


def count_unlogged_entries(conn: sqlite3.Connection, max_entries: int | None = None) -> int:
    cursor = get_submit_cursor(conn)
    if cursor is None:
        row = conn.execute(
            """SELECT COUNT(1)
               FROM entries e
               LEFT JOIN logged_entries l
                 ON l.filename = e.filename
               WHERE l.filename IS NULL
                 AND e.provenance_status IN ('found', 'none')"""
        ).fetchone()
    else:
        upload_time, filename = cursor
        row = conn.execute(
            """SELECT COUNT(1)
               FROM entries e
               WHERE e.provenance_status IN ('found', 'none')
                 AND (e.upload_time > ? OR (e.upload_time = ? AND e.filename > ?))""",
            (upload_time, upload_time, filename),
        ).fetchone()
    count = int(row[0]) if row else 0
    return min(count, max_entries) if max_entries is not None else count


def get_submit_cursor(conn: sqlite3.Connection) -> tuple[str, str] | None:
    upload_time = get_cursor_value(conn, "submit_last_upload_time")
    filename = get_cursor_value(conn, "submit_last_filename")
    if upload_time is None or filename is None:
        return None
    return upload_time, filename


def set_submit_cursor(conn: sqlite3.Connection, entry: LogEntry):
    with conn:
        set_cursor_values(
            conn,
            {
                "submit_last_upload_time": entry.upload_time,
                "submit_last_filename": entry.filename,
            },
        )


def load_unlogged_entries(
    conn: sqlite3.Connection,
    max_entries: int | None = None,
    after: tuple[str, str] | None = None,
) -> list[LogEntry]:
    limit = f" LIMIT {max_entries}" if max_entries is not None else ""
    if after is None:
        rows = conn.execute(_unlogged_entries_query() + _submit_order_clause() + limit).fetchall()
    else:
        upload_time, filename = after
        rows = conn.execute(
            _unlogged_entries_query()
            + """ AND (e.upload_time > ? OR (e.upload_time = ? AND e.filename > ?))"""
            + _submit_order_clause()
            + limit,
            (upload_time, upload_time, filename),
        ).fetchall()
    entries = []
    for filename, digest, upload_time, pub_issuer, pub_subject in rows:
        publisher = Publisher(pub_issuer, pub_subject) if pub_issuer and pub_subject else None
        entries.append(LogEntry(filename, digest, upload_time, publisher))
    return entries


def _chunks[T](items: list[T], size: int):
    for i in range(0, len(items), size):
        yield items[i : i + size]


def submit_entries_bulk(
    client: httpx.Client,
    bulk_append_url: str,
    entries: list[LogEntry],
    max_retries: int,
    retry_backoff: float,
) -> SubmitBatchResult:
    payload = "".join(json.dumps(entry_payload(entry), separators=(",", ":")) + "\n" for entry in entries)
    for attempt in range(max_retries):
        try:
            results_by_filename: dict[str, dict] = {}
            tree_size = 0
            checkpoint = ""
            proofs: dict[int, list[str]] = {}
            stream_errors: list[str] = []
            with client.stream(
                "POST",
                bulk_append_url,
                content=payload,
                headers={"Content-Type": "application/x-ndjson"},
            ) as resp:
                if resp.status_code != 200:
                    body = resp.read().decode("utf-8", errors="replace")
                    if 400 <= resp.status_code < 500:
                        raise RuntimeError(f"bt-log rejected bulk append: {resp.status_code} {body}")
                    raise httpx.HTTPStatusError(
                        f"bt-log returned {resp.status_code}: {body}",
                        request=resp.request,
                        response=resp,
                    )
                for line in resp.iter_lines():
                    if not line:
                        continue
                    record = json.loads(line)
                    record_type = record.get("type")
                    if record_type == "checkpoint":
                        tree_size = int(record.get("tree_size", 0))
                        checkpoint = record.get("checkpoint", "")
                    elif record_type == "result":
                        result = record.get("result") or {}
                        filename = result.get("filename")
                        if filename:
                            results_by_filename[filename] = result
                        inclusion_proof = result.get("inclusionProof")
                        if inclusion_proof is None:
                            inclusion_proof = result.get("inclusion_proof", [])
                        if result.get("index") is not None and inclusion_proof is not None:
                            proofs[int(result["index"])] = inclusion_proof
                    elif record_type == "error":
                        result = record.get("result") or {}
                        stream_errors.append(result.get("error") or "bt-log bulk append stream error")
                    elif record_type == "complete":
                        pass
                    else:
                        stream_errors.append(f"unexpected bt-log bulk append stream record type {record_type!r}")
            submitted: list[tuple[LogEntry, int | None, str | None]] = []
            for entry in entries:
                result = results_by_filename.get(entry.filename)
                if not result:
                    submitted.append((entry, None, "missing result from bt-log"))
                    continue
                status = result.get("status")
                if status in {"logged", "already_logged"}:
                    submitted.append((entry, result.get("index"), None))
                else:
                    submitted.append((entry, None, result.get("error") or f"unexpected status {status!r}"))
            if stream_errors:
                raise RuntimeError("; ".join(stream_errors))
            if not checkpoint:
                raise RuntimeError("bt-log bulk append stream did not include a checkpoint")
            return SubmitBatchResult(tree_size=tree_size, checkpoint=checkpoint, proofs=proofs, results=submitted)
        except (httpx.HTTPError, RuntimeError, json.JSONDecodeError) as e:
            if isinstance(e, RuntimeError) or attempt == max_retries - 1:
                raise
            wait = retry_backoff * (2 ** attempt)
            log.warning(
                "bulk submit failed for %d entries (attempt %d/%d): %s; retrying in %.1fs",
                len(entries),
                attempt + 1,
                max_retries,
                e,
                wait,
            )
            time.sleep(wait)
    raise RuntimeError("unreachable")


def load_next_submit_batch(
    conn: sqlite3.Connection,
    limit: int,
    scan_cursor: tuple[str, str] | None,
) -> tuple[list[LogEntry], tuple[str, str] | None, float]:
    load_start = time.monotonic()
    batch = load_unlogged_entries(conn, limit, after=scan_cursor)
    elapsed = time.monotonic() - load_start
    next_cursor = (batch[-1].upload_time, batch[-1].filename) if batch else scan_cursor
    return batch, next_cursor, elapsed


def collect_successful_submit_results(
    results: list[tuple[LogEntry, int | None, str | None]],
) -> tuple[list[tuple[LogEntry, int | None]], int]:
    successful: list[tuple[LogEntry, int | None]] = []
    failed = 0
    for entry, index, error in results:
        if error:
            failed += 1
            log.error("failed to submit %s: %s", entry.filename, error)
        else:
            successful.append((entry, index))
    return successful, failed


def record_submit_batch(
    conn: sqlite3.Connection,
    batch: list[LogEntry],
    successful: list[tuple[LogEntry, int | None]],
) -> tuple[tuple[str, str] | None, float]:
    record_start = time.monotonic()
    record_logged_many(conn, successful)
    if len(successful) == len(batch):
        set_submit_cursor(conn, batch[-1])
        cursor = (batch[-1].upload_time, batch[-1].filename)
    else:
        cursor = None
    return cursor, time.monotonic() - record_start


def submit_batches(
    conn: sqlite3.Connection,
    client: httpx.Client,
    bulk_append_url: str,
    args,
    progress,
    task,
) -> tuple[int, int]:
    succeeded = failed = 0
    loaded = processed = 0
    scan_cursor = get_submit_cursor(conn)
    if scan_cursor is not None:
        log.info("resuming submit scan after upload_time=%s filename=%s", scan_cursor[0], scan_cursor[1])

    with ThreadPoolExecutor(max_workers=args.submit_concurrency) as pool:
        in_flight: list[SubmitFuture] = []
        stop_loading = False

        while in_flight or not stop_loading:
            while (
                not stop_loading
                and len(in_flight) < args.submit_concurrency
                and (args.max_submit is None or loaded < args.max_submit)
            ):
                remaining = None if args.max_submit is None else args.max_submit - loaded
                limit = args.submit_batch_size if remaining is None else min(args.submit_batch_size, remaining)
                batch, next_scan_cursor, load_elapsed = load_next_submit_batch(conn, limit, scan_cursor)
                if not batch:
                    if processed == 0 and loaded == 0:
                        CONSOLE.print("No unlogged entries to submit")
                    stop_loading = True
                    break
                log.info("loaded submit batch of %d entries in %.1fs", len(batch), load_elapsed)
                scan_cursor = next_scan_cursor
                loaded += len(batch)
                progress.update(task, description=f"Submitting batch of {len(batch)} entries")
                in_flight.append(
                    SubmitFuture(
                        batch=batch,
                        start=time.monotonic(),
                        future=pool.submit(
                            submit_entries_bulk,
                            client,
                            bulk_append_url,
                            batch,
                            args.retries,
                            args.retry_backoff,
                        ),
                    )
                )

            if not in_flight:
                break

            item = in_flight.pop(0)
            batch = item.batch
            try:
                batch_result = item.future.result()
            except Exception as e:
                failed += len(batch)
                processed += len(batch)
                for entry in batch:
                    log.error("failed to submit %s: %s", entry.filename, e)
                progress.update(task, advance=len(batch), description="Submitting entries")
                log.error("stopping submit after bulk API failure; cursor was not advanced")
                break
            log.info("bulk API returned %d results in %.1fs", len(batch_result.results), time.monotonic() - item.start)

            successful, batch_failed = collect_successful_submit_results(batch_result.results)
            failed += batch_failed
            if args.proof_dir and successful:
                proof_start = time.monotonic()
                try:
                    stored, skipped = store_submitted_proofs(
                        args.proof_dir,
                        successful,
                        batch_result.checkpoint,
                        batch_result.proofs,
                    )
                except Exception as e:
                    failed += len(batch)
                    processed += len(batch)
                    log.error("stopping submit after proof storage failure; successful appends were not recorded locally: %s", e)
                    progress.update(task, advance=len(batch), description="Submitting entries")
                    break
                log.info("stored %d proofs and skipped %d existing proofs in %.1fs", stored, skipped, time.monotonic() - proof_start)
            _, record_elapsed = record_submit_batch(conn, batch, successful)
            log.info("recorded %d successful submissions in %.1fs", len(successful), record_elapsed)
            succeeded += len(successful)
            processed += len(batch)
            progress.update(task, advance=len(batch), description="Submitting entries")
            log.info("submitted %d entries; failed=%d", succeeded, failed)
            if len(successful) != len(batch):
                log.error(
                    "stopping submit because %d entries in the last batch failed; cursor was not advanced",
                    len(batch) - len(successful),
                )
                break

    return succeeded, failed


def proof_path(proof_dir: str, log_index: int) -> str:
    index_text = str(log_index)
    shard = hashlib.sha256(index_text.encode("ascii")).hexdigest()
    return os.path.join(proof_dir, shard[:2], shard[2:4], shard[4:6], f"{index_text}.tlog-proof")


def decode_checkpoint(checkpoint_b64: str) -> str:
    checkpoint = base64.b64decode(checkpoint_b64).decode("utf-8")
    return checkpoint if checkpoint.endswith("\n") else checkpoint + "\n"


def format_c2sp_tlog_proof(entry: ProofEntry, inclusion_proof: list[str], checkpoint_b64: str) -> str:
    extra = base64.b64encode(
        json.dumps(
            {"filename": entry.filename, "sha256_digest": entry.sha256_digest},
            separators=(",", ":"),
        ).encode("utf-8")
    ).decode("ascii")
    return (
        "c2sp.org/tlog-proof@v1\n"
        f"extra {extra}\n"
        f"index {entry.log_index}\n"
        + "".join(f"{hash_b64}\n" for hash_b64 in inclusion_proof)
        + "\n"
        + decode_checkpoint(checkpoint_b64)
    )


def write_proof_file(path: str, content: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, path)


def proof_entry_ranges(
    successful: list[tuple[LogEntry, int | None]],
    max_range_size: int,
) -> list[list[ProofEntry]]:
    entries: list[ProofEntry] = []
    for entry, index in successful:
        if index is None:
            raise RuntimeError(f"bt-log did not return a log index for {entry.filename}")
        entries.append(ProofEntry(entry.filename, entry.sha256_digest, int(index)))
    entries.sort(key=lambda e: e.log_index)

    ranges: list[list[ProofEntry]] = []
    current: list[ProofEntry] = []
    start = prev = -1
    for entry in entries:
        if not current:
            current = [entry]
            start = prev = entry.log_index
            continue
        if entry.log_index != prev + 1 or entry.log_index - start + 1 > max_range_size:
            ranges.append(current)
            current = [entry]
            start = entry.log_index
        else:
            current.append(entry)
        prev = entry.log_index
    if current:
        ranges.append(current)
    return ranges


def store_submitted_proofs(
    proof_dir: str,
    successful: list[tuple[LogEntry, int | None]],
    checkpoint_b64: str,
    proofs: dict[int, list[str]],
) -> tuple[int, int]:
    stored = skipped = 0
    for entries in proof_entry_ranges(successful, len(successful)):
        for entry in entries:
            path = proof_path(proof_dir, entry.log_index)
            if os.path.exists(path):
                skipped += 1
                continue
            proof = proofs.get(entry.log_index)
            if proof is None:
                raise RuntimeError(f"append response missing proof for index {entry.log_index} ({entry.filename})")
            write_proof_file(path, format_c2sp_tlog_proof(entry, proof, checkpoint_b64))
            stored += 1
    return stored, skipped


def run_submit(args) -> None:
    CONSOLE.print(f"Opening SQLite database: {args.db}")
    conn = init_db(args.db)
    progress_total = None
    if args.submit_concurrency < 1:
        raise SystemExit("--submit-concurrency must be at least 1")
    if not args.no_count:
        CONSOLE.print("Counting unlogged entries for progress ETA...")
        progress_total = count_unlogged_entries(conn, args.max_submit)
        CONSOLE.print(f"Entries to submit this run: {progress_total}")
        if progress_total == 0:
            CONSOLE.print("No unlogged entries to submit")
            conn.close()
            return

    bulk_append_url = build_bulk_append_url(args.log_url)
    proof_msg = f" and storing proofs under {args.proof_dir}" if args.proof_dir else ""
    CONSOLE.print(
        f"Submitting entries to {bulk_append_url} "
        f"in batches of {args.submit_batch_size} "
        f"with concurrency {args.submit_concurrency}"
        f"{proof_msg}"
    )
    with make_progress() as progress:
        task = progress.add_task("Submitting entries", total=progress_total or args.max_submit)
        with httpx.Client(timeout=args.timeout) as client:
            succeeded, failed = submit_batches(conn, client, bulk_append_url, args, progress, task)
    conn.close()
    CONSOLE.print(f"Done: submitted={succeeded}, submit_failed={failed}")


def _since_to_upload_time(since: str | None) -> str | None:
    if not since:
        return None
    try:
        return _normalize_upload_time(since)
    except Exception:
        pass
    dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return _normalize_upload_time(str(dt.timestamp()))


def main():
    args = parse_args()
    logging.getLogger().setLevel(args.log_level.upper())
    # httpx logs every request at INFO, which breaks Rich's live progress display.
    # Keep third-party HTTP logs quiet unless explicitly debugging them in code.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    if args.command == "bigquery":
        run_bigquery(args)
    elif args.command == "provenance":
        run_provenance(args)
    elif args.command == "submit":
        run_submit(args)
    elif args.command == "reset-submit":
        run_reset_submit(args)
    else:
        raise RuntimeError(f"unknown command: {args.command}")


if __name__ == "__main__":
    main()
