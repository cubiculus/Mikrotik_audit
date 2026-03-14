"""HTML report generator for MikroTik audit results."""

import logging
from pathlib import Path
from typing import List, Optional
from datetime import datetime

import plotly.graph_objects as go
from jinja2 import Environment, FileSystemLoader

from src.config import CommandResult, SecurityIssue, RouterInfo, BackupResult
from src.models import NetworkOverview
from src.reports.base_report import BaseReportGenerator

logger = logging.getLogger(__name__)


class HTMLReportGenerator(BaseReportGenerator):
    """Generates comprehensive HTML reports with interactive charts."""

    def __init__(self, output_dir: Path, template_path: Optional[Path] = None):
        """Initialize HTML report generator."""
        super().__init__(output_dir)
        self.template_path = template_path or Path(__file__).parent.parent / "templates" / "report.html"
        self._load_template()

    def _load_template(self) -> None:
        """Load HTML template from file."""
        try:
            # Создаем Environment с включенным autoescape для защиты от XSS
            self.env = Environment(
                loader=FileSystemLoader(self.template_path.parent),
                autoescape=True
            )
            self.template = self.env.get_template(self.template_path.name)
            logger.debug(f"Loaded HTML template from {self.template_path} with autoescape enabled")
        except Exception as e:
            logger.error(f"Failed to load template: {e}")
            raise

    def generate(
        self,
        results: List[CommandResult],
        security_issues: List[SecurityIssue],
        router_info: RouterInfo,
        backup_result: Optional[BackupResult] = None,
        network_overview: Optional[NetworkOverview] = None
    ) -> Path:
        """Generate HTML report."""
        logger.info("Generating HTML report...")

        try:
            # Prepare statistics
            stats = self._get_report_statistics(results)
            total_commands = stats["total_commands"]
            failed_commands = stats["failed_commands"]
            success_rate = stats["success_rate"]
            sorted_results = stats["sorted_results"]

            # Create plots
            charts_html = self._create_charts(results, sorted_results)

            # Create sections
            commands_table = self._create_commands_table(results)
            security_section = self._create_security_section(security_issues)
            containers_section = self._create_containers_section(network_overview)
            dns_section = self._create_dns_section(network_overview)
            traffic_flow_section = self._create_traffic_flow_section(network_overview)
            devices_section = self._create_devices_section(network_overview)
            failed_commands_section = self._create_failed_commands_section(results)
            nat_rules_section = self._create_nat_rules_section(network_overview)
            filter_rules_section = self._create_filter_rules_section(network_overview)
            backup_section = self._create_backup_section(backup_result)

            # Render template с autoescape
            report_datetime = datetime.now().strftime("%d.%m.%Y %H:%M:%S")

            html = self.template.render(
                router_identity=router_info.identity or "Unknown",
                router_model=router_info.model or "Unknown",
                router_version=router_info.version or "Unknown",
                router_ip=router_info.ip or "Unknown",
                # router_serial намеренно исключён (требования безопасности)
                router_uptime=router_info.uptime,
                report_datetime=report_datetime,
                total_commands=total_commands,
                failed_commands=failed_commands,
                success_rate=success_rate,
                security_issues_count=len(security_issues),
                charts_html=charts_html,
                backup_section=backup_section,
                security_section=security_section,
                commands_table=commands_table,
                containers_section=containers_section,
                dns_section=dns_section,
                traffic_flow_section=traffic_flow_section,
                devices_section=devices_section,
                failed_commands_section=failed_commands_section,
                nat_rules_section=nat_rules_section,
                filter_rules_section=filter_rules_section,
            )

            # Write report
            report_path = self.output_dir / self._get_report_filename(router_info, "html")
            self._write_file(report_path, html)
            logger.info(f"HTML report saved: {report_path}")

            return report_path

        except Exception as e:
            logger.error(f"Error generating HTML report: {e}", exc_info=True)
            raise IOError(f"Failed to generate HTML report: {e}")

    def _create_charts(self, results: List[CommandResult], sorted_results: List[CommandResult]) -> str:
        """Create interactive Plotly charts."""
        try:
            # Duration chart
            commands = [r.command[:40] + "..." if len(r.command) > 40 else r.command
                       for r in sorted_results]
            durations = [r.duration for r in sorted_results]

            fig1 = go.Figure(data=[go.Bar(x=commands, y=durations, marker_color='#667eea')])
            fig1.update_layout(
                title="Top 10 Slowest Commands",
                xaxis_title="Command",
                yaxis_title="Duration (seconds)",
                height=350,
                showlegend=False
            )

            # Error distribution
            error_types: dict[str, int] = {}
            for r in results:
                if r.has_error:
                    error_type = r.error_type or "Unknown"
                    error_types[error_type] = error_types.get(error_type, 0) + 1

            if error_types:
                fig2 = go.Figure(data=[
                    go.Pie(
                        labels=list(error_types.keys()),
                        values=list(error_types.values()),
                        marker_colors=['#ef4444', '#f59e0b', '#3b82f6', '#10b981']
                    )
                ])
                fig2.update_layout(title="Error Distribution", height=350)
            else:
                fig2 = go.Figure()
                fig2.add_annotation(text="No errors detected", showarrow=False)

            plot1_html = fig1.to_html(include_plotlyjs=False, div_id="plot1")
            plot2_html = fig2.to_html(include_plotlyjs=False, div_id="plot2")

            return f'<div class="chart">{plot1_html}</div><div class="chart">{plot2_html}</div>'

        except Exception as e:
            logger.error(f"Failed to create charts: {e}")
            return "<p>Failed to generate charts</p>"

    def _create_commands_table(self, results: List[CommandResult]) -> str:
        """Create HTML table of command results."""
        rows = []
        for r in results:
            if not r.has_error:
                status = '<span class="status-success">Success</span>'
                error_info = "-"
            else:
                status = '<span class="status-error">Failed</span>'
                error_parts = []
                if r.error_type:
                    error_parts.append(f"<strong>Type:</strong> {r.error_type}")
                if r.error_message:
                    error_msg = r.error_message.replace('<', '&lt;').replace('>', '&gt;')
                    if len(error_msg) > 200:
                        error_msg = error_msg[:200] + "..."
                    error_parts.append(f"<strong>Message:</strong> {error_msg}")
                if r.stderr:
                    stderr = '\n'.join(line for line in r.stderr.split('\n') if line.strip())
                    stderr = stderr.replace('<', '&lt;').replace('>', '&gt;')
                    if len(stderr) > 200:
                        stderr = stderr[:200] + "..."
                    error_parts.append(f"<strong>Stderr:</strong> {stderr}")
                error_info = "<br>".join(error_parts) if error_parts else "-"

            row_id = f"cmd_row_{r.index}"
            output_content = r.stdout if r.stdout else r.stderr if r.stderr else "No output"
            output_content = '\n'.join(line for line in output_content.split('\n') if line.strip())
            output_escaped = output_content.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

            rows.append(f'''
                <tr class="command-row {'error-row' if r.has_error else ''}" id="{row_id}" onclick="toggleCommand('{row_id}')">
                    <td>{r.index}</td>
                    <td><span class="command-toggle-icon">▶</span><code>{r.command}</code></td>
                    <td>{r.duration:.2f}</td>
                    <td>{status}</td>
                    <td class="error-details">{error_info}</td>
                </tr>
                <tr>
                    <td colspan="5" style="padding:0">
                        <div class="command-output" id="{row_id}_output">
                            <strong>Full Output:</strong><br>
                            <pre style="white-space: pre-wrap; font-family: monospace; font-size: 0.85em; background: #f8f9fa; padding: 10px; border-radius: 4px; max-height: 300px; overflow-y: auto;">{output_escaped}</pre>
                        </div>
                    </td>
                </tr>
            ''')

        return "\n".join(rows)

    def _create_security_section(self, issues: List[SecurityIssue]) -> str:
        """Create HTML security findings section."""
        if not issues:
            return '<p style="color: #10b981; font-weight: bold;">✓ No security issues detected</p>'

        html_issues = []
        for issue in issues:
            severity_class = issue.severity.lower()
            html_issues.append(f'''
                <div class="security-issue {severity_class}">
                    <div class="issue-title">[{issue.severity}] {issue.finding}</div>
                    <div class="issue-detail"><strong>Category:</strong> {issue.category}</div>
                    <div class="issue-detail"><strong>Recommendation:</strong> {issue.recommendation}</div>
                    <div class="issue-detail"><strong>Command:</strong> <code>{issue.command}</code></div>
                </div>
            ''')

        return "\n".join(html_issues)

    def _create_failed_commands_section(self, results: List[CommandResult]) -> str:
        """Create HTML section highlighting failed commands."""
        failed = [r for r in results if r.has_error]
        if not failed:
            return ''

        html_parts = [f'''
            <div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 6px; padding: 15px; margin-bottom: 20px;">
                <h3 style="color: #dc2626; margin-bottom: 15px;">Failed Commands ({len(failed)})</h3>
        ''']

        for r in failed:
            error_msg = r.error_message or "Unknown error"
            stderr_content = r.stderr or ""
            stderr_content = '\n'.join(line for line in stderr_content.split('\n') if line.strip())

            html_parts.append(f'''
                <div style="background: white; padding: 12px; margin: 8px 0; border-radius: 4px; border-left: 4px solid #dc2626;">
                    <div style="font-weight: bold; color: #333; margin-bottom: 8px;">
                        #{r.index}: <code style="background: #f0f0f0; padding: 2px 6px; border-radius: 3px;">{r.command}</code>
                    </div>
                    <div style="font-size: 0.9em; color: #666;">
                        <strong>Error Type:</strong> {r.error_type or "N/A"}<br>
                        <strong>Exit Status:</strong> {r.exit_status}<br>
                        <strong>Message:</strong> <span style="color: #dc2626;">{error_msg}</span>
                    </div>
                    {f'<div style="margin-top: 8px; padding: 8px; background: #1e1e1e; color: #f0f0f0; border-radius: 4px; font-family: monospace; font-size: 0.85em; white-space: pre-wrap; max-height: 150px; overflow-y: auto;">{stderr_content}</div>' if stderr_content else ''}
                </div>
            ''')

        html_parts.append('</div>')
        return ''.join(html_parts)

    def _create_backup_section(self, backup_result: Optional[BackupResult]) -> str:
        """Create HTML backup status section."""
        if not backup_result:
            return "<p>Backup was not performed.</p>"

        if backup_result.status == "success":
            size_kb = f"{backup_result.file_size / 1024:.2f} KB" if backup_result.file_size else "Unknown"
            file_link = f"<a href='{backup_result.local_path}' style='color:#065f46;text-decoration:underline' target='_blank'>💾 Download Backup File</a>" if backup_result.local_path else ""

            html = "<div style='background:#d1fae5;padding:20px;border-radius:8px;border-left:4px solid #10b981'>"
            html += "<h3 style='margin:0;color:#065f46'>✅ Backup Successful</h3>"
            html += "<p style='margin:5px 0;color:#065f46'>"
            html += f"<strong>Timestamp:</strong> {backup_result.timestamp}<br>"
            html += f"<strong>File:</strong> {backup_result.file_name or 'N/A'}<br>"
            html += f"<strong>Size:</strong> {size_kb}<br>"
            if file_link:
                html += f"<strong>Location:</strong> {file_link}"
            if backup_result.download_error:
                html += f"<br><strong style='color:#f59e0b'>⚠️ Download Warning:</strong> {backup_result.download_error}"
            html += "</p></div>"
            return html
        elif backup_result.status == "skipped":
            html = "<div style='background:#fef3c7;padding:20px;border-radius:8px;border-left:4px solid #f59e0b'>"
            html += "<h3 style='margin:0;color:#92400e'>⚠️ Backup Skipped</h3>"
            html += "<p style='margin:5px 0;color:#92400e'>"
            html += f"<strong>Timestamp:</strong> {backup_result.timestamp}<br>"
            html += f"<strong>Reason:</strong> {backup_result.error_message or 'Not required'}<br>"
            html += "<em>Note: This does not affect the audit results. Only the backup file was not created.</em>"
            html += "</p></div>"
            return html
        else:
            html = "<div style='background:#fee2e2;padding:20px;border-radius:8px;border-left:4px solid #ef4444'>"
            html += "<h3 style='margin:0;color:#991b1b'>❌ Backup Failed</h3>"
            html += "<p style='margin:5px 0;color:#991b1b'>"
            html += f"<strong>Timestamp:</strong> {backup_result.timestamp}<br>"
            html += f"<strong>Error:</strong> {backup_result.error_message or 'Unknown error'}<br>"
            html += "<em>Note: This does not affect the audit results. Only the backup file was not created.</em>"
            html += "</p></div>"
            return html

    def _create_containers_section(self, overview: Optional[NetworkOverview]) -> str:
        """Create HTML containers section."""
        if not overview or not overview.containers:
            return '<p style="color: #666;">No containers found on this router.</p>'

        try:
            cards = []
            for container in overview.containers:
                status_class = 'running' if container.status == 'running' else 'stopped'
                status_icon = '🟢' if container.status == 'running' else '🔴'
                cards.append(f'''
                    <div class="info-card container-card {status_class}">
                        <h4>{status_icon} {container.name or "Unnamed"}</h4>
                        <ul>
                            <li><strong>Status:</strong> {container.status}</li>
                            <li><strong>Image:</strong> {container.image or "N/A"}</li>
                            <li><strong>Root Dir:</strong> {container.root_directory or "N/A"}</li>
                        </ul>
                    </div>
                ''')

            return f'<div class="info-grid">{"".join(cards)}</div>'
        except Exception as e:
            logger.error(f"Error creating containers section: {e}")
            return f'<p style="color: #d11;">Error creating containers section: {e}</p>'

    def _create_dns_section(self, overview: Optional[NetworkOverview]) -> str:
        """Create HTML DNS configuration section."""
        if not overview or not overview.dns:
            return '<p style="color: #666;">No DNS configuration found.</p>'

        try:
            dns = overview.dns
            servers_html = ''.join(f'<span class="dns-server">{s}</span>' for s in dns.servers) if dns.servers else '<span style="color: #666;">No DNS servers configured</span>'
            doh_html = f'<p style="margin-top: 10px;"><strong>DoH Server:</strong> <code>{dns.doh_server}</code></p>' if dns.use_doh and dns.doh_server else ''

            static_html = ''
            if dns.static_entries:
                entries = []
                for entry in dns.static_entries[:20]:
                    disabled = ' (disabled)' if entry.get('disabled') else ''
                    comment = f' - {entry.get("comment")}' if entry.get('comment') else ''
                    entries.append(f'<li><code>{entry.get("name", "")}</code> → {entry.get("address", "")}{comment}{disabled}</li>')
                more = f'<li><em>...and {len(dns.static_entries) - 20} more</em></li>' if len(dns.static_entries) > 20 else ''
                static_html = f'<div class="info-card" style="margin-top: 15px;"><h4>Static DNS Entries ({len(dns.static_entries)})</h4><ul>{"".join(entries)}{more}</ul></div>'

            return f'''
                <div class="info-card">
                    <h4>DNS Servers</h4>
                    {servers_html}
                    {doh_html}
                    <p style="margin-top: 10px;">
                        <strong>Allow Remote:</strong> {"Yes" if dns.allow_remote else "No"} |
                        <strong>Cache Size:</strong> {dns.cache_size} KiB
                    </p>
                </div>
                {static_html}
            '''
        except Exception as e:
            logger.error(f"Error creating DNS section: {e}")
            return f'<p style="color: #d11;">Error creating DNS section: {e}</p>'

    def _create_traffic_flow_section(self, overview: Optional[NetworkOverview]) -> str:
        """Create HTML traffic flow section."""
        if not overview:
            return '<p style="color: #666;">No traffic marking or routing rules found.</p>'

        # Check for mangle rules and routing rules
        has_content = False
        content_parts = []

        # Mangle rules
        if hasattr(overview, 'mangle_rules') and overview.mangle_rules:
            has_content = True
            mangle_rows = []

            for idx, rule in enumerate(overview.mangle_rules[:50]):  # Limit to 50 rules
                disabled_badge = '<span style="color:#ef4444;font-size:0.85em;">(disabled)</span>' if rule.disabled else ''
                comment = rule.comment or ""

                mangle_rows.append(f'''
                    <tr class="{'disabled-rule' if rule.disabled else ''}">
                        <td>{idx + 1}</td>
                        <td><strong>{rule.chain or "prerouting"}</strong></td>
                        <td>{rule.action or "passthrough"}</td>
                        <td>{rule.new_connection_mark or rule.new_routing_mark or "-"}</td>
                        <td>{rule.protocol or "-"}</td>
                        <td>{rule.src_address or "-"}</td>
                        <td>{rule.dst_address or "-"}</td>
                        <td>{comment[:30] + "..." if len(comment) > 30 else comment}</td>
                        <td>{disabled_badge}</td>
                    </tr>
                ''')

            more_rules = len(overview.mangle_rules) - 50
            more_html = f'<tr><td colspan="9" style="text-align:center;color:#666;padding:10px;"><em>...and {more_rules} more mangle rules</em></td></tr>' if more_rules > 0 else ''

            content_parts.append(f'''
                <div class="info-card" style="margin-bottom: 20px;">
                    <h4>Mangle Rules (Traffic Marking)</h4>
                    <p style="margin-bottom:10px;color:#666;font-size:0.9em;">Total rules: {len(overview.mangle_rules)}</p>
                    <table class="rules-table">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Chain</th>
                                <th>Action</th>
                                <th>Connection/Route Mark</th>
                                <th>Protocol</th>
                                <th>Src Address</th>
                                <th>Dst Address</th>
                                <th>Comment</th>
                                <th>State</th>
                            </tr>
                        </thead>
                        <tbody>{''.join(mangle_rows)}{more_html}</tbody>
                    </table>
                </div>
            ''')

        # Routing rules
        if hasattr(overview, 'routing_rules') and overview.routing_rules:
            has_content = True
            routing_rows = []

            for idx, rule in enumerate(overview.routing_rules[:30]):  # Limit to 30 rules
                disabled_badge = '<span style="color:#ef4444;font-size:0.85em;">(disabled)</span>' if rule.disabled else ''
                comment = getattr(rule, 'comment', '') or ""

                routing_rows.append(f'''
                    <tr class="{'disabled-rule' if rule.disabled else ''}">
                        <td>{idx + 1}</td>
                        <td>{getattr(rule, 'action', 'accept')}</td>
                        <td>{getattr(rule, 'src_address', '-')}</td>
                        <td>{getattr(rule, 'dst_address', '-')}</td>
                        <td>{getattr(rule, 'in_interface', '-')}</td>
                        <td>{getattr(rule, 'out_interface', '-')}</td>
                        <td>{comment[:30] + "..." if len(comment) > 30 else comment}</td>
                        <td>{disabled_badge}</td>
                    </tr>
                ''')

            more_rules = len(overview.routing_rules) - 30
            more_html = f'<tr><td colspan="8" style="text-align:center;color:#666;padding:10px;"><em>...and {more_rules} more routing rules</em></td></tr>' if more_rules > 0 else ''

            content_parts.append(f'''
                <div class="info-card">
                    <h4>Routing Rules</h4>
                    <p style="margin-bottom:10px;color:#666;font-size:0.9em;">Total rules: {len(overview.routing_rules)}</p>
                    <table class="rules-table">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Action</th>
                                <th>Src Address</th>
                                <th>Dst Address</th>
                                <th>In Interface</th>
                                <th>Out Interface</th>
                                <th>Comment</th>
                                <th>State</th>
                            </tr>
                        </thead>
                        <tbody>{''.join(routing_rows)}{more_html}</tbody>
                    </table>
                </div>
            ''')

        # Routes
        if hasattr(overview, 'routes') and overview.routes:
            has_content = True
            route_rows = []

            for idx, route in enumerate(overview.routes[:30]):  # Limit to 30 routes
                disabled_badge = '<span style="color:#ef4444;font-size:0.85em;">(disabled)</span>' if route.disabled else ''
                comment = route.comment or ""

                route_rows.append(f'''
                    <tr class="{'disabled-rule' if route.disabled else ''}">
                        <td>{idx + 1}</td>
                        <td>{route.dst_address or "-"}</td>
                        <td>{route.gateway or "-"}</td>
                        <td>{route.routing_mark or "-"}</td>
                        <td>{route.distance or "-"}</td>
                        <td>{comment[:30] + "..." if len(comment) > 30 else comment}</td>
                        <td>{disabled_badge}</td>
                    </tr>
                ''')

            more_rules = len(overview.routes) - 30
            more_html = f'<tr><td colspan="7" style="text-align:center;color:#666;padding:10px;"><em>...and {more_rules} more routes</em></td></tr>' if more_rules > 0 else ''

            content_parts.append(f'''
                <div class="info-card" style="margin-bottom: 20px;">
                    <h4>IP Routes</h4>
                    <p style="margin-bottom:10px;color:#666;font-size:0.9em;">Total routes: {len(overview.routes)}</p>
                    <table class="rules-table">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Destination</th>
                                <th>Gateway</th>
                                <th>Routing Mark</th>
                                <th>Distance</th>
                                <th>Comment</th>
                                <th>State</th>
                            </tr>
                        </thead>
                        <tbody>{''.join(route_rows)}{more_html}</tbody>
                    </table>
                </div>
            ''')

        if not has_content:
            return '<p style="color: #666;">No traffic marking or routing rules found.</p>'

        return ''.join(content_parts)

    def _create_devices_section(self, overview: Optional[NetworkOverview]) -> str:
        """Create HTML devices and DHCP leases section."""
        if not overview or not overview.dhcp_leases:
            return '<p style="color: #666;">No DHCP leases found.</p>'

        try:
            leases = sorted(overview.dhcp_leases, key=lambda x: (getattr(x, 'dynamic', False), getattr(x, 'address', '')))
            rows = []

            for lease in leases:
                lease_status = getattr(lease, 'lease_status', '')
                is_dynamic = lease_status == 'Dynamic' or getattr(lease, 'dynamic', False)
                static_class = '' if is_dynamic else 'static'
                type_badge = '<span class="badge dynamic">Dynamic</span>' if is_dynamic else '<span class="badge static">Static</span>'

                host_name = (getattr(lease, 'host_name', '') or getattr(lease, 'hostname', '') or
                            getattr(lease, 'client_hostname', '') or getattr(lease, 'address', ''))
                comment = getattr(lease, 'comment', '') or ''

                rows.append(f'''
                    <tr class="{static_class}">
                        <td>{getattr(lease, 'address', '')}</td>
                        <td><code>{getattr(lease, 'mac_address', '')}</code></td>
                        <td>{host_name or "-"}</td>
                        <td>{type_badge}</td>
                        <td>{comment or "-"}</td>
                    </tr>
                ''')

            total = len(leases)
            static_count = sum(1 for l in leases if not getattr(l, 'dynamic', False))
            dynamic_count = total - static_count

            return f'''
                <div style="margin-bottom: 15px;">
                    <span class="badge static" style="font-size: 0.9em;">Static: {static_count}</span>
                    <span class="badge dynamic" style="font-size: 0.9em;">Dynamic: {dynamic_count}</span>
                    <span style="margin-left: 10px;">Total: {total} devices</span>
                </div>
                <table class="device-table">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>MAC Address</th>
                            <th>Hostname</th>
                            <th>Type</th>
                            <th>Comment</th>
                        </tr>
                    </thead>
                    <tbody>{"".join(rows)}</tbody>
                </table>
            '''
        except Exception as e:
            logger.error(f"Error creating devices section: {e}")
            return f'<p style="color: #d11;">Error creating devices section: {e}</p>'

    def _create_nat_rules_section(self, overview: Optional[NetworkOverview]) -> str:
        """Create HTML NAT rules section."""
        if not overview or not hasattr(overview, 'nat_rules') or not overview.nat_rules:
            return '<p style="color: #666;">No NAT firewall rules found.</p>'

        try:
            nat_rows = []

            for idx, rule in enumerate(overview.nat_rules[:50]):  # Limit to 50 rules
                disabled_badge = '<span style="color:#ef4444;font-size:0.85em;">(disabled)</span>' if rule.disabled else ''
                log_badge = '<span style="color:#3b82f6;font-size:0.85em;">📋 logged</span>' if rule.log == 'yes' else ''
                comment = rule.comment or ""

                nat_rows.append(f'''
                    <tr class="{'disabled-rule' if rule.disabled else ''}">
                        <td>{idx + 1}</td>
                        <td><strong>{rule.chain or "srcnat"}</strong></td>
                        <td><span style="color:#10b981;">{rule.action or "masquerade"}</span></td>
                        <td>{rule.to_addresses or "-"}</td>
                        <td>{rule.to_ports or "-"}</td>
                        <td>{rule.protocol or "-"}</td>
                        <td>{rule.src_address or "-"}</td>
                        <td>{rule.dst_address or "-"}</td>
                        <td>{rule.src_port or "-"}</td>
                        <td>{rule.dst_port or "-"}</td>
                        <td>{rule.in_interface or "-"}</td>
                        <td>{rule.out_interface or "-"}</td>
                        <td>{comment[:25] + "..." if len(comment) > 25 else comment}</td>
                        <td>{disabled_badge} {log_badge}</td>
                    </tr>
                ''')

            more_rules = len(overview.nat_rules) - 50
            more_html = f'<tr><td colspan="14" style="text-align:center;color:#666;padding:10px;"><em>...and {more_rules} more NAT rules</em></td></tr>' if more_rules > 0 else ''

            # Count rules by chain
            srcnat_count = sum(1 for r in overview.nat_rules if r.chain == 'srcnat')
            dstnat_count = sum(1 for r in overview.nat_rules if r.chain == 'dstnat')
            disabled_count = sum(1 for r in overview.nat_rules if r.disabled)

            return f'''
                <div style="margin-bottom: 15px;">
                    <span style="margin-right: 15px;"><strong>Total:</strong> {len(overview.nat_rules)} rules</span>
                    <span style="margin-right: 15px;"><strong>srcnat:</strong> {srcnat_count}</span>
                    <span style="margin-right: 15px;"><strong>dstnat:</strong> {dstnat_count}</span>
                    <span style="margin-right: 15px;"><strong>Disabled:</strong> {disabled_count}</span>
                </div>
                <div style="overflow-x: auto;">
                    <table class="rules-table">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Chain</th>
                                <th>Action</th>
                                <th>To Addr</th>
                                <th>To Port</th>
                                <th>Proto</th>
                                <th>Src Addr</th>
                                <th>Dst Addr</th>
                                <th>Src Port</th>
                                <th>Dst Port</th>
                                <th>In Iface</th>
                                <th>Out Iface</th>
                                <th>Comment</th>
                                <th>State</th>
                            </tr>
                        </thead>
                        <tbody>{''.join(nat_rows)}{more_html}</tbody>
                    </table>
                </div>
            '''
        except Exception as e:
            logger.error(f"Error creating NAT rules section: {e}")
            return f'<p style="color: #d11;">Error creating NAT rules section: {e}</p>'

    def _create_filter_rules_section(self, overview: Optional[NetworkOverview]) -> str:
        """Create HTML filter rules section."""
        if not overview or not hasattr(overview, 'filter_rules') or not overview.filter_rules:
            return '<p style="color: #666;">No Filter firewall rules found.</p>'

        try:
            filter_rows = []

            for idx, rule in enumerate(overview.filter_rules[:50]):  # Limit to 50 rules
                disabled_badge = '<span style="color:#ef4444;font-size:0.85em;">(disabled)</span>' if rule.disabled else ''
                log_badge = '<span style="color:#3b82f6;font-size:0.85em;">📋 logged</span>' if rule.log == 'yes' else ''

                # Color code based on action
                action_colors = {
                    'accept': 'color:#10b981;',
                    'drop': 'color:#ef4444;',
                    'reject': 'color:#f59e0b;',
                    'jump': 'color:#8b5cf6;',
                    'return': 'color:#6b7280;',
                }
                action_style = action_colors.get(rule.action, '')

                comment = rule.comment or ""

                filter_rows.append(f'''
                    <tr class="{'disabled-rule' if rule.disabled else ''}">
                        <td>{idx + 1}</td>
                        <td><strong style="{action_style}">{rule.chain or "forward"}</strong></td>
                        <td style="{action_style}">{rule.action or "accept"}</td>
                        <td>{rule.protocol or "-"}</td>
                        <td>{rule.src_address or "-"}</td>
                        <td>{rule.dst_address or "-"}</td>
                        <td>{rule.src_port or "-"}</td>
                        <td>{rule.dst_port or "-"}</td>
                        <td>{rule.in_interface or "-"}</td>
                        <td>{rule.out_interface or "-"}</td>
                        <td>{rule.connection_state or "-"}</td>
                        <td>{comment[:25] + "..." if len(comment) > 25 else comment}</td>
                        <td>{disabled_badge} {log_badge}</td>
                    </tr>
                ''')

            more_rules = len(overview.filter_rules) - 50
            more_html = f'<tr><td colspan="13" style="text-align:center;color:#666;padding:10px;"><em>...and {more_rules} more filter rules</em></td></tr>' if more_rules > 0 else ''

            # Count rules by action
            accept_count = sum(1 for r in overview.filter_rules if r.action == 'accept')
            drop_count = sum(1 for r in overview.filter_rules if r.action == 'drop')
            reject_count = sum(1 for r in overview.filter_rules if r.action == 'reject')
            disabled_count = sum(1 for r in overview.filter_rules if r.disabled)

            return f'''
                <div style="margin-bottom: 15px;">
                    <span style="margin-right: 15px;"><strong>Total:</strong> {len(overview.filter_rules)} rules</span>
                    <span style="margin-right: 15px;color:#10b981;"><strong>Accept:</strong> {accept_count}</span>
                    <span style="margin-right: 15px;color:#ef4444;"><strong>Drop:</strong> {drop_count}</span>
                    <span style="margin-right: 15px;color:#f59e0b;"><strong>Reject:</strong> {reject_count}</span>
                    <span style="margin-right: 15px;"><strong>Disabled:</strong> {disabled_count}</span>
                </div>
                <div style="overflow-x: auto;">
                    <table class="rules-table">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Chain</th>
                                <th>Action</th>
                                <th>Protocol</th>
                                <th>Src Addr</th>
                                <th>Dst Addr</th>
                                <th>Src Port</th>
                                <th>Dst Port</th>
                                <th>In Iface</th>
                                <th>Out Iface</th>
                                <th>Conn State</th>
                                <th>Comment</th>
                                <th>State</th>
                            </tr>
                        </thead>
                        <tbody>{''.join(filter_rows)}{more_html}</tbody>
                    </table>
                </div>
            '''
        except Exception as e:
            logger.error(f"Error creating filter rules section: {e}")
            return f'<p style="color: #d11;">Error creating filter rules section: {e}</p>'
