"""Database module for web interface.

Uses SQLite to store audit history and results.
"""

import sqlite3
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# Database path
DATA_DIR = Path(__file__).parent.parent.parent / 'data'
AUDITS_DIR = DATA_DIR / 'audits'
DB_PATH = DATA_DIR / 'audit.db'


def init_database():
    """Initialize database and create tables."""
    # Create directories
    DATA_DIR.mkdir(exist_ok=True)
    AUDITS_DIR.mkdir(exist_ok=True)

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Create audits table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_ip TEXT NOT NULL,
                router_identity TEXT,
                router_version TEXT,
                audit_level TEXT,
                audit_profile TEXT,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                status TEXT DEFAULT 'pending',
                security_score INTEGER,
                issues_count INTEGER,
                report_path TEXT,
                error_message TEXT
            )
        ''')

        # Create issues table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS issues (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                audit_id INTEGER,
                severity TEXT,
                category TEXT,
                finding TEXT,
                description TEXT,
                recommendation TEXT,
                FOREIGN KEY (audit_id) REFERENCES audits(id)
            )
        ''')

        # Create index for faster lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_audits_status ON audits(status)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_audits_started ON audits(started_at DESC)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_issues_audit ON issues(audit_id)
        ''')

        conn.commit()
        logger.info(f"Database initialized at {DB_PATH}")


@contextmanager
def get_db_connection():
    """Get database connection context manager."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def create_audit(router_ip: str, audit_level: str = 'Standard',
                 audit_profile: Optional[str] = None) -> int:
    """
    Create new audit record.

    Args:
        router_ip: Router IP address
        audit_level: Basic/Standard/Comprehensive
        audit_profile: Optional profile name

    Returns:
        Audit ID
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audits (router_ip, audit_level, audit_profile, started_at, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (router_ip, audit_level, audit_profile, datetime.now().isoformat(), 'running'))
        conn.commit()
        return cursor.lastrowid


def update_audit_status(audit_id: int, status: str, error_message: Optional[str] = None):
    """Update audit status."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if status == 'completed':
            cursor.execute('''
                UPDATE audits
                SET status = ?, completed_at = ?, error_message = ?
                WHERE id = ?
            ''', (status, datetime.now().isoformat(), error_message, audit_id))
        else:
            cursor.execute('''
                UPDATE audits SET status = ?, error_message = ? WHERE id = ?
            ''', (status, error_message, audit_id))
        conn.commit()


def update_audit_result(audit_id: int, router_identity: str, router_version: str,
                        security_score: int, issues_count: int, report_path: str):
    """Update audit with results."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE audits
            SET router_identity = ?, router_version = ?,
                security_score = ?, issues_count = ?, report_path = ?,
                status = 'completed', completed_at = ?
            WHERE id = ?
        ''', (router_identity, router_version, security_score, issues_count,
              report_path, datetime.now().isoformat(), audit_id))
        conn.commit()


def save_issues(audit_id: int, issues: List[Dict]):
    """Save security issues to database."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        for issue in issues:
            cursor.execute('''
                INSERT INTO issues (audit_id, severity, category, finding,
                                   description, recommendation)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (audit_id, issue.get('severity', 'Medium'),
                  issue.get('category', ''), issue.get('finding', ''),
                  issue.get('description', ''), issue.get('recommendation', '')))
        conn.commit()


def get_audit(audit_id: int) -> Optional[Dict]:
    """Get audit by ID."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM audits WHERE id = ?', (audit_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_all_audits(limit: int = 50) -> List[Dict]:
    """Get all audits ordered by date."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM audits ORDER BY started_at DESC LIMIT ?
        ''', (limit,))
        return [dict(row) for row in cursor.fetchall()]


def get_audit_issues(audit_id: int) -> List[Dict]:
    """Get issues for specific audit."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM issues WHERE audit_id = ? ORDER BY
                CASE severity
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    ELSE 4
                END
        ''', (audit_id,))
        return [dict(row) for row in cursor.fetchall()]


def delete_audit(audit_id: int) -> bool:
    """Delete audit and its issues."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        # Delete issues first
        cursor.execute('DELETE FROM issues WHERE audit_id = ?', (audit_id,))
        # Delete audit
        cursor.execute('DELETE FROM audits WHERE id = ?', (audit_id,))
        conn.commit()
        return cursor.rowcount > 0


def get_audit_stats() -> Dict:
    """Get audit statistics."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Total audits
        cursor.execute('SELECT COUNT(*) as count FROM audits')
        total = cursor.fetchone()['count']

        # Completed audits
        cursor.execute("SELECT COUNT(*) as count FROM audits WHERE status = 'completed'")
        completed = cursor.fetchone()['count']

        # Average score
        cursor.execute("SELECT AVG(security_score) as avg_score FROM audits WHERE status = 'completed' AND security_score IS NOT NULL")
        avg_score = cursor.fetchone()['avg_score'] or 0

        # Recent audits (last 7 days)
        cursor.execute('''
            SELECT COUNT(*) as count FROM audits
            WHERE started_at >= datetime('now', '-7 days')
        ''')
        recent = cursor.fetchone()['count']

        return {
            'total': total,
            'completed': completed,
            'average_score': round(avg_score, 1),
            'recent': recent
        }


def get_score_history(limit: int = 20) -> List[Dict]:
    """Get security score history for charts."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT started_at, security_score, router_identity
            FROM audits
            WHERE status = 'completed' AND security_score IS NOT NULL
            ORDER BY started_at DESC
            LIMIT ?
        ''', (limit,))
        return [dict(row) for row in cursor.fetchall()]
