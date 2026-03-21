"""Tests for web database module."""

import tempfile
from pathlib import Path
from unittest.mock import patch

from src.web.database import (
    init_database,
    get_db_connection,
    create_audit,
    update_audit_status,
    update_audit_result,
    save_issues,
    get_audit,
    get_all_audits,
    get_audit_issues,
    delete_audit,
    get_audit_stats,
    get_score_history
)


class TestDatabaseInit:
    """Tests for database initialization."""

    def test_init_database_creates_tables(self):
        """Test that init_database creates tables."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('src.web.database.DATA_DIR', Path(tmpdir)):
                with patch('src.web.database.AUDITS_DIR', Path(tmpdir) / 'audits'):
                    with patch('src.web.database.DB_PATH', Path(tmpdir) / 'test.db'):
                        init_database()

                        # Check database file exists
                        db_path = Path(tmpdir) / 'test.db'
                        assert db_path.exists()

                        # Check tables exist
                        with get_db_connection() as conn:
                            cursor = conn.cursor()
                            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                            tables = [row[0] for row in cursor.fetchall()]
                            assert 'audits' in tables
                            assert 'issues' in tables


class TestCreateAudit:
    """Tests for create_audit function."""

    def test_create_audit_returns_id(self):
        """Test that create_audit returns audit ID."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('src.web.database.DATA_DIR', Path(tmpdir)):
                with patch('src.web.database.AUDITS_DIR', Path(tmpdir) / 'audits'):
                    with patch('src.web.database.DB_PATH', Path(tmpdir) / 'test.db'):
                        init_database()

                        audit_id = create_audit('192.168.88.1', 'Standard')

                        assert audit_id > 0

                        # Verify audit was created
                        audit = get_audit(audit_id)
                        assert audit is not None
                        assert audit['router_ip'] == '192.168.88.1'
                        assert audit['status'] == 'running'

    def test_create_audit_with_profile(self):
        """Test creating audit with profile."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('src.web.database.DATA_DIR', Path(tmpdir)):
                with patch('src.web.database.AUDITS_DIR', Path(tmpdir) / 'audits'):
                    with patch('src.web.database.DB_PATH', Path(tmpdir) / 'test.db'):
                        init_database()

                        audit_id = create_audit('192.168.88.1', 'Standard', 'wifi')

                        audit = get_audit(audit_id)
                        assert audit['audit_profile'] == 'wifi'


class TestUpdateAudit:
    """Tests for update functions."""

    def test_update_audit_status(self):
        """Test updating audit status."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('src.web.database.DATA_DIR', Path(tmpdir)):
                with patch('src.web.database.AUDITS_DIR', Path(tmpdir) / 'audits'):
                    with patch('src.web.database.DB_PATH', Path(tmpdir) / 'test.db'):
                        init_database()

                        audit_id = create_audit('192.168.88.1')

                        update_audit_status(audit_id, 'completed')

                        audit = get_audit(audit_id)
                        assert audit['status'] == 'completed'

    def test_update_audit_status_with_error(self):
        """Test updating audit status with error message."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('src.web.database.DATA_DIR', Path(tmpdir)):
                with patch('src.web.database.AUDITS_DIR', Path(tmpdir) / 'audits'):
                    with patch('src.web.database.DB_PATH', Path(tmpdir) / 'test.db'):
                        init_database()

                        audit_id = create_audit('192.168.88.1')

                        update_audit_status(audit_id, 'failed', 'Connection timeout')

                        audit = get_audit(audit_id)
                        assert audit['status'] == 'failed'
                        assert audit['error_message'] == 'Connection timeout'

    def test_update_audit_result(self):
        """Test updating audit with results."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('src.web.database.DATA_DIR', Path(tmpdir)):
                with patch('src.web.database.AUDITS_DIR', Path(tmpdir) / 'audits'):
                    with patch('src.web.database.DB_PATH', Path(tmpdir) / 'test.db'):
                        init_database()

                        audit_id = create_audit('192.168.88.1')

                        update_audit_result(
                            audit_id=audit_id,
                            router_identity='TestRouter',
                            router_version='7.12',
                            security_score=75,
                            issues_count=5,
                            report_path='/path/to/report.html'
                        )

                        audit = get_audit(audit_id)
                        assert audit['router_identity'] == 'TestRouter'
                        assert audit['router_version'] == '7.12'
                        assert audit['security_score'] == 75
                        assert audit['issues_count'] == 5
                        assert audit['report_path'] == '/path/to/report.html'


class TestSaveIssues:
    """Tests for save_issues function."""

    def test_save_issues(self):
        """Test saving issues to database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('src.web.database.DATA_DIR', Path(tmpdir)):
                with patch('src.web.database.AUDITS_DIR', Path(tmpdir) / 'audits'):
                    with patch('src.web.database.DB_PATH', Path(tmpdir) / 'test.db'):
                        init_database()

                        audit_id = create_audit('192.168.88.1')

                        issues = [
                            {
                                'severity': 'High',
                                'category': 'Firewall',
                                'finding': 'No firewall rules',
                                'description': 'Empty firewall',
                                'recommendation': 'Add rules'
                            },
                            {
                                'severity': 'Medium',
                                'category': 'SSH',
                                'finding': 'SSH on port 22',
                                'description': 'Default port',
                                'recommendation': 'Change port'
                            }
                        ]

                        save_issues(audit_id, issues)

                        saved_issues = get_audit_issues(audit_id)
                        assert len(saved_issues) == 2
                        assert saved_issues[0]['severity'] == 'High'
                        assert saved_issues[1]['severity'] == 'Medium'


class TestGetAudits:
    """Tests for get functions."""

    def test_get_all_audits(self):
        """Test getting all audits."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('src.web.database.DATA_DIR', Path(tmpdir)):
                with patch('src.web.database.AUDITS_DIR', Path(tmpdir) / 'audits'):
                    with patch('src.web.database.DB_PATH', Path(tmpdir) / 'test.db'):
                        init_database()

                        # Create multiple audits
                        create_audit('192.168.88.1')
                        create_audit('192.168.88.2')
                        create_audit('192.168.88.3')

                        audits = get_all_audits()

                        assert len(audits) == 3

    def test_get_all_audits_with_limit(self):
        """Test getting audits with limit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('src.web.database.DATA_DIR', Path(tmpdir)):
                with patch('src.web.database.AUDITS_DIR', Path(tmpdir) / 'audits'):
                    with patch('src.web.database.DB_PATH', Path(tmpdir) / 'test.db'):
                        init_database()

                        for i in range(10):
                            create_audit(f'192.168.88.{i}')

                        audits = get_all_audits(limit=5)

                        assert len(audits) == 5

    def test_get_nonexistent_audit(self):
        """Test getting nonexistent audit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('src.web.database.DATA_DIR', Path(tmpdir)):
                with patch('src.web.database.AUDITS_DIR', Path(tmpdir) / 'audits'):
                    with patch('src.web.database.DB_PATH', Path(tmpdir) / 'test.db'):
                        init_database()

                        audit = get_audit(9999)

                        assert audit is None


class TestDeleteAudit:
    """Tests for delete_audit function."""

    def test_delete_audit(self):
        """Test deleting audit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('src.web.database.DATA_DIR', Path(tmpdir)):
                with patch('src.web.database.AUDITS_DIR', Path(tmpdir) / 'audits'):
                    with patch('src.web.database.DB_PATH', Path(tmpdir) / 'test.db'):
                        init_database()

                        audit_id = create_audit('192.168.88.1')

                        # Delete audit
                        result = delete_audit(audit_id)

                        assert result is True

                        # Verify deleted
                        audit = get_audit(audit_id)
                        assert audit is None

    def test_delete_nonexistent_audit(self):
        """Test deleting nonexistent audit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('src.web.database.DATA_DIR', Path(tmpdir)):
                with patch('src.web.database.AUDITS_DIR', Path(tmpdir) / 'audits'):
                    with patch('src.web.database.DB_PATH', Path(tmpdir) / 'test.db'):
                        init_database()

                        result = delete_audit(9999)

                        assert result is False


class TestGetAuditStats:
    """Tests for get_audit_stats function."""

    def test_get_audit_stats_empty(self):
        """Test getting stats with no audits."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('src.web.database.DATA_DIR', Path(tmpdir)):
                with patch('src.web.database.AUDITS_DIR', Path(tmpdir) / 'audits'):
                    with patch('src.web.database.DB_PATH', Path(tmpdir) / 'test.db'):
                        init_database()

                        stats = get_audit_stats()

                        assert stats['total'] == 0
                        assert stats['completed'] == 0
                        assert stats['average_score'] == 0

    def test_get_audit_stats_with_audits(self):
        """Test getting stats with audits."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('src.web.database.DATA_DIR', Path(tmpdir)):
                with patch('src.web.database.AUDITS_DIR', Path(tmpdir) / 'audits'):
                    with patch('src.web.database.DB_PATH', Path(tmpdir) / 'test.db'):
                        init_database()

                        # Create completed audits
                        audit_id1 = create_audit('192.168.88.1')
                        update_audit_result(audit_id1, 'R1', '7.12', 80, 5, '/report1.html')

                        audit_id2 = create_audit('192.168.88.2')
                        update_audit_result(audit_id2, 'R2', '7.12', 60, 10, '/report2.html')

                        stats = get_audit_stats()

                        assert stats['total'] == 2
                        assert stats['completed'] == 2
                        assert stats['average_score'] == 70.0


class TestGetScoreHistory:
    """Tests for get_score_history function."""

    def test_get_score_history_empty(self):
        """Test getting score history with no data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('src.web.database.DATA_DIR', Path(tmpdir)):
                with patch('src.web.database.AUDITS_DIR', Path(tmpdir) / 'audits'):
                    with patch('src.web.database.DB_PATH', Path(tmpdir) / 'test.db'):
                        init_database()

                        history = get_score_history()

                        assert len(history) == 0

    def test_get_score_history_with_data(self):
        """Test getting score history with data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('src.web.database.DATA_DIR', Path(tmpdir)):
                with patch('src.web.database.AUDITS_DIR', Path(tmpdir) / 'audits'):
                    with patch('src.web.database.DB_PATH', Path(tmpdir) / 'test.db'):
                        init_database()

                        audit_id = create_audit('192.168.88.1')
                        update_audit_result(audit_id, 'R1', '7.12', 75, 5, '/report.html')

                        history = get_score_history()

                        assert len(history) == 1
                        assert history[0]['security_score'] == 75

    def test_get_score_history_with_limit(self):
        """Test getting score history with limit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('src.web.database.DATA_DIR', Path(tmpdir)):
                with patch('src.web.database.AUDITS_DIR', Path(tmpdir) / 'audits'):
                    with patch('src.web.database.DB_PATH', Path(tmpdir) / 'test.db'):
                        init_database()

                        for i in range(30):
                            audit_id = create_audit(f'192.168.88.{i}')
                            update_audit_result(audit_id, f'R{i}', '7.12', 70 + i, 5, f'/report{i}.html')

                        history = get_score_history(limit=10)

                        assert len(history) == 10
