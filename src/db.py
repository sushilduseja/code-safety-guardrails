import sqlite3, hashlib, secrets
from contextlib import contextmanager

DB_PATH = "guardrails.db"

def init_db():
    with connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                key_hash    TEXT PRIMARY KEY,
                tenant_id   TEXT NOT NULL,
                rpm_limit   INTEGER DEFAULT 60,
                created_at  TEXT DEFAULT (datetime('now')),
                revoked_at  TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                request_id       TEXT PRIMARY KEY,
                tenant_id        TEXT,
                prompt_hash      TEXT,     -- SHA-256, never store the prompt
                language         TEXT,
                strict           INTEGER,
                validators_run   TEXT,     -- JSON array
                issues_found     TEXT,     -- JSON array
                passed           INTEGER,
                raw_code_hash    TEXT,
                protected_code_hash TEXT,
                latency_ms       INTEGER,
                created_at       TEXT DEFAULT (datetime('now'))
            )
        """)

@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def issue_key(tenant_id: str, rpm: int = 60) -> str:
    raw = secrets.token_urlsafe(32)
    h   = hashlib.sha256(raw.encode()).hexdigest()
    with connect() as conn:
        conn.execute("INSERT INTO api_keys VALUES (?,?,?,datetime('now'),NULL)", (h, tenant_id, rpm))
    return raw   # shown once, never stored

def resolve_key(raw: str) -> sqlite3.Row | None:
    h = hashlib.sha256(raw.encode()).hexdigest()
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM api_keys WHERE key_hash=? AND revoked_at IS NULL", (h,)
        ).fetchone()
