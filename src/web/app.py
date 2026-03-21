"""Flask web application for MikroTik Audit Tool."""

import os
import json
import logging
import threading
import queue
from pathlib import Path
from datetime import datetime
from typing import Dict

from flask import Flask, render_template, request, jsonify, redirect, url_for, Response, send_file
from flask_cors import CORS

from src.web.database import (
    init_database,
    create_audit,
    update_audit_status,
    update_audit_result,
    save_issues,
    get_audit,
    get_all_audits,
    get_audit_issues,
    delete_audit,
    get_audit_stats,
    get_score_history,
    AUDITS_DIR
)
from src.config import AuditConfig, RouterConfig, AuditLevel
from src.auditor import MikroTikAuditor
from src.report_generator import ReportGenerator
from src.security_analyzer import SecurityAnalyzer

logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
CORS(app)

# Audit queue for processing multiple routers
audit_queue = queue.Queue()
audit_threads = []
MAX_AUDIT_THREADS = 3  # Concurrent audits


# ==================== Web Pages ====================

@app.route('/')
def index():
    """Home page - dashboard."""
    stats = get_audit_stats()
    recent_audits = get_all_audits(limit=10)
    return render_template('index.html', stats=stats, audits=recent_audits)


@app.route('/audit/new')
def new_audit():
    """New audit form."""
    return render_template('audit_new.html')


@app.route('/audit/<int:audit_id>')
def audit_detail(audit_id):
    """Audit detail page."""
    audit = get_audit(audit_id)
    if not audit:
        return redirect(url_for('index'))
    return render_template('audit_detail.html', audit=audit)


@app.route('/report/<int:audit_id>')
def report_view(audit_id):
    """View report page."""
    audit = get_audit(audit_id)
    if not audit:
        return redirect(url_for('index'))
    issues = get_audit_issues(audit_id)
    return render_template('report.html', audit=audit, issues=issues)


@app.route('/compare')
def compare_select():
    """Select audits to compare."""
    audits = get_all_audits(limit=50)
    return render_template('compare_select.html', audits=audits)


@app.route('/compare/<int:id1>/<int:id2>')
def compare_view(id1, id2):
    """Compare two audits."""
    audit1 = get_audit(id1)
    audit2 = get_audit(id2)
    if not audit1 or not audit2:
        return redirect(url_for('compare_select'))

    issues1 = get_audit_issues(id1)
    issues2 = get_audit_issues(id2)

    return render_template('compare.html',
                         audit1=audit1, audit2=audit2,
                         issues1=issues1, issues2=issues2)


@app.route('/history')
def history():
    """Audit history page."""
    audits = get_all_audits(limit=100)
    return render_template('history.html', audits=audits)


# ==================== API Endpoints ====================

@app.route('/api/stats')
def api_stats():
    """Get dashboard statistics."""
    return jsonify(get_audit_stats())


@app.route('/api/audits')
def api_audits():
    """Get all audits."""
    limit = request.args.get('limit', 50, type=int)
    audits = get_all_audits(limit=limit)
    return jsonify(audits)


@app.route('/api/audit/<int:audit_id>')
def api_audit(audit_id):
    """Get audit details."""
    audit = get_audit(audit_id)
    if not audit:
        return jsonify({'error': 'Audit not found'}), 404
    return jsonify(audit)


@app.route('/api/audit/<int:audit_id>/issues')
def api_audit_issues(audit_id):
    """Get audit issues."""
    issues = get_audit_issues(audit_id)
    return jsonify(issues)


@app.route('/api/audit/run', methods=['POST'])
def api_run_audit():
    """Start new audit."""
    data = request.get_json()

    router_ip = data.get('router_ip')
    if not router_ip:
        return jsonify({'error': 'router_ip is required'}), 400

    # Create audit record
    audit_id = create_audit(
        router_ip=router_ip,
        audit_level=data.get('audit_level', 'Standard'),
        audit_profile=data.get('audit_profile')
    )

    # Queue audit for processing
    audit_queue.put({
        'audit_id': audit_id,
        'config_data': data
    })

    # Start worker thread if needed
    start_audit_workers()

    return jsonify({
        'audit_id': audit_id,
        'status': 'queued',
        'message': 'Audit started'
    })


@app.route('/api/audit/<int:audit_id>/status')
def api_audit_status(audit_id):
    """Get audit status."""
    audit = get_audit(audit_id)
    if not audit:
        return jsonify({'error': 'Audit not found'}), 404

    return jsonify({
        'id': audit['id'],
        'status': audit['status'],
        'security_score': audit.get('security_score'),
        'issues_count': audit.get('issues_count'),
        'started_at': audit['started_at'],
        'completed_at': audit.get('completed_at'),
        'error_message': audit.get('error_message')
    })


@app.route('/api/audit/<int:audit_id>/delete', methods=['POST'])
def api_delete_audit(audit_id):
    """Delete audit."""
    audit = get_audit(audit_id)
    if not audit:
        return jsonify({'error': 'Audit not found'}), 404

    # Delete report file if exists
    if audit.get('report_path'):
        try:
            Path(audit['report_path']).unlink(missing_ok=True)
        except Exception as e:
            logger.warning(f"Could not delete report file: {e}")

    delete_audit(audit_id)
    return jsonify({'success': True})


@app.route('/api/audit/<int:audit_id>/export/<format>')
def api_export_audit(audit_id, format):
    """Export audit report."""
    audit = get_audit(audit_id)
    if not audit:
        return jsonify({'error': 'Audit not found'}), 404

    if not audit.get('report_path'):
        return jsonify({'error': 'Report not found'}), 404

    # Read existing report or regenerate
    report_path = Path(audit['report_path'])
    if not report_path.exists():
        return jsonify({'error': 'Report file not found'}), 404

    # For different formats, we'd regenerate - for now return the HTML
    return send_file(report_path, as_attachment=True,
                    download_name=f"audit_{audit_id}.{format}")


@app.route('/api/compare', methods=['POST'])
def api_compare():
    """Compare two audits."""
    data = request.get_json()
    id1 = data.get('audit_id_1')
    id2 = data.get('audit_id_2')

    if not id1 or not id2:
        return jsonify({'error': 'Both audit IDs required'}), 400

    audit1 = get_audit(id1)
    audit2 = get_audit(id2)
    issues1 = get_audit_issues(id1)
    issues2 = get_audit_issues(id2)

    # Calculate differences
    score_diff = (audit2.get('security_score') or 0) - (audit1.get('security_score') or 0)

    # Find new/removed issues
    findings1 = {i['finding'] for i in issues1}
    findings2 = {i['finding'] for i in issues2}

    new_issues = findings2 - findings1
    resolved_issues = findings1 - findings2

    return jsonify({
        'audit1': audit1,
        'audit2': audit2,
        'score_difference': score_diff,
        'new_issues_count': len(new_issues),
        'resolved_issues_count': len(resolved_issues),
        'new_issues': list(new_issues),
        'resolved_issues': list(resolved_issues)
    })


@app.route('/api/score-history')
def api_score_history():
    """Get security score history for charts."""
    limit = request.args.get('limit', 20, type=int)
    history = get_score_history(limit)
    return jsonify(history)


# ==================== Audit Worker ====================

def process_audit(audit_id: int, config_data: Dict):
    """Process audit in background thread."""
    try:
        logger.info(f"Starting audit {audit_id}")

        # Build configuration
        router_config = RouterConfig(
            router_ip=config_data.get('router_ip'),
            ssh_port=config_data.get('ssh_port', 22),
            ssh_user=config_data.get('ssh_user', 'admin'),
            ssh_pass=config_data.get('password', ''),
            ssh_key_file=config_data.get('ssh_key_file'),
            connect_timeout=config_data.get('connect_timeout', 30),
            command_timeout=config_data.get('command_timeout', 120)
        )

        audit_config = AuditConfig(
            router=router_config,
            audit_level=AuditLevel(config_data.get('audit_level', 'Standard')),
            audit_profile=config_data.get('audit_profile'),
            skip_security_check=False,
            redact_sensitive=config_data.get('redact', False),
            output_formats=['html', 'json'],
            enable_cve_check=config_data.get('cve_check', True),
            enable_live_cve_lookup=True
        )

        # Run audit
        auditor = MikroTikAuditor(audit_config)

        # Execute audit (this will block)
        auditor.run_audit()

        # Get results
        router_info = auditor.get_router_info()
        issues = auditor.get_security_issues()

        # Calculate score
        score = SecurityAnalyzer.calculate_security_score(issues)

        # Generate report
        report_gen = ReportGenerator(
            router_info=router_info,
            audit_results=auditor.get_results(),
            security_issues=issues,
            network_overview=auditor.get_network_overview()
        )

        # Save report
        report_filename = f"audit_{audit_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        report_path = AUDITS_DIR / report_filename
        report_gen.generate_html_report(str(report_path))

        # Update database
        update_audit_result(
            audit_id=audit_id,
            router_identity=router_info.identity if router_info else '',
            router_version=router_info.version if router_info else '',
            security_score=score,
            issues_count=len(issues),
            report_path=str(report_path)
        )

        # Save issues
        issues_data = [
            {
                'severity': i.severity,
                'category': i.category,
                'finding': i.finding,
                'description': i.description,
                'recommendation': i.recommendation
            }
            for i in issues
        ]
        save_issues(audit_id, issues_data)

        logger.info(f"Audit {audit_id} completed with score {score}")

    except Exception as e:
        logger.error(f"Audit {audit_id} failed: {e}")
        update_audit_status(audit_id, 'failed', str(e))


def audit_worker():
    """Worker thread for processing audits."""
    while True:
        try:
            task = audit_queue.get(timeout=1)
            if task is None:  # Shutdown signal
                break

            audit_id = task['audit_id']
            config_data = task['config_data']

            process_audit(audit_id, config_data)
            audit_queue.task_done()

        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Audit worker error: {e}")


def start_audit_workers():
    """Start worker threads if needed."""
    global audit_threads

    # Clean up finished threads
    audit_threads = [t for t in audit_threads if t.is_alive()]

    # Start new threads if needed
    while len(audit_threads) < MAX_AUDIT_THREADS:
        t = threading.Thread(target=audit_worker, daemon=True)
        t.start()
        audit_threads.append(t)


# ==================== Server-Sent Events ====================

@app.route('/api/audit/<int:audit_id>/progress')
def api_audit_progress(audit_id):
    """Server-Sent Events for audit progress."""
    def generate():
        while True:
            audit = get_audit(audit_id)
            if not audit:
                yield f"data: {json.dumps({'error': 'Not found'})}\n\n"
                break

            data = {
                'status': audit['status'],
                'started_at': audit['started_at']
            }

            if audit['status'] == 'completed':
                data['security_score'] = audit.get('security_score')
                data['issues_count'] = audit.get('issues_count')
                data['completed_at'] = audit.get('completed_at')
                yield f"data: {json.dumps(data)}\n\n"
                break
            elif audit['status'] == 'failed':
                data['error_message'] = audit.get('error_message')
                yield f"data: {json.dumps(data)}\n\n"
                break
            else:
                yield f"data: {json.dumps(data)}\n\n"

            # Wait before next update
            import time
            time.sleep(2)

    return Response(generate(), mimetype='text/event-stream')


# ==================== Main ====================

def create_app_instance():
    """Create and configure app instance."""
    init_database()
    start_audit_workers()
    return app


def run_server(host='127.0.0.1', port=5000, debug=False):
    """Run the web server."""
    init_database()
    start_audit_workers()

    print(f"""
╔═══════════════════════════════════════════════════════════╗
║     MikroTik Audit Tool - Web Interface                   ║
╠═══════════════════════════════════════════════════════════╣
║  Server starting...                                       ║
║  URL: http://{host}:{port}                                ║
║                                                           ║
║  Press Ctrl+C to stop                                     ║
╚═══════════════════════════════════════════════════════════╝
    """)

    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == '__main__':
    run_server()
