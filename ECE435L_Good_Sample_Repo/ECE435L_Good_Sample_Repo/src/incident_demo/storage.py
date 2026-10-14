"""SQLite data access and reproducible schema initialization."""
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from .security import hash_password


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def connect(db_path: str) -> sqlite3.Connection:
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys = ON')
    return db


def init_db(db_path: str) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with connect(db_path) as db:
        db.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('administrator','analyst','employee','auditor'))
            );
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL CHECK (severity IN ('Low','Medium','High','Critical')),
                affected_asset TEXT NOT NULL,
                reporter_id INTEGER NOT NULL REFERENCES users(id),
                assigned_analyst_id INTEGER REFERENCES users(id),
                status TEXT NOT NULL DEFAULT 'Open',
                created_at TEXT NOT NULL,
                resolved_at TEXT
            );
            CREATE TABLE IF NOT EXISTS investigation_notes (
                id INTEGER PRIMARY KEY,
                incident_id INTEGER NOT NULL REFERENCES incidents(id),
                analyst_id INTEGER NOT NULL REFERENCES users(id),
                content TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                action TEXT NOT NULL,
                outcome TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        ''')


def seed_users(db_path: str, password: str) -> None:
    """Populate fictional users for local learning; no passwords saved in the repo."""
    if len(password) < 12:
        raise ValueError('DEMO_PASSWORD must contain at least 12 characters')
    init_db(db_path)
    with connect(db_path) as db:
        for username, role in [
            ('demo_admin', 'administrator'),
            ('demo_analyst', 'analyst'),
            ('demo_employee', 'employee'),
            ('demo_auditor', 'auditor'),
        ]:
            salt, digest = hash_password(password)
            db.execute('INSERT OR IGNORE INTO users(username,salt,password_hash,role) VALUES(?,?,?,?)',
                       (username, salt, digest, role))


def write_audit(db: sqlite3.Connection, user_id: int | None, action: str, outcome: str) -> None:
    db.execute('INSERT INTO audit_logs(user_id, action, outcome, created_at) VALUES(?,?,?,?)',
               (user_id, action, outcome, utc_now()))
