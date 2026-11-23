from __future__ import annotations

import html
from pathlib import Path

from core.models import ScanResult


class HTMLReporter:
    """Formats and exports ScanResult as a self-contained HTML report."""

    def render(self, result: ScanResult) -> str:
        summary = result.summary()
        fail_by_sev = summary["fail_by_severity"]
        regions_str = html.escape(", ".join(result.scanned_regions))
        services_str = html.escape(", ".join(s.upper() for s in result.scanned_services))
        account_id = html.escape(result.account_id)
        started_at = html.escape(result.started_at)
        finished_at = html.escape(result.finished_at)

        rows_html: list[str] = []
        for finding in result.findings:
            status_val = html.escape(finding.status.value)
            sev_val = html.escape(finding.severity.value)
            rows_html.append(
                "<tr>"
                f"<td><code>{html.escape(finding.rule_id)}</code></td>"
                f"<td>{html.escape(finding.service.upper())}</td>"
                f"<td><code>{html.escape(finding.resource_id)}</code></td>"
                f"<td>{html.escape(finding.region)}</td>"
                f"<td><span class='badge sev-{sev_val.lower()}'>{sev_val}</span></td>"
                f"<td><span class='badge status-{status_val.lower()}'>{status_val}</span></td>"
                f"<td>{html.escape(finding.message)}</td>"
                f"<td>{html.escape(finding.remediation)}</td>"
                "</tr>"
            )

        tbody_content = (
            "\n".join(rows_html)
            if rows_html
            else "<tr><td colspan='8'>No findings recorded.</td></tr>"
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cloud Misconfiguration Scan Report</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; margin: 24px; background: #f8fafc; color: #0f172a; }}
    h1 {{ margin-bottom: 8px; }}
    .meta {{ color: #475569; margin-bottom: 20px; font-size: 0.95rem; }}
    .cards {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }}
    .card {{ background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 18px; min-width: 110px; }}
    .card .label {{ font-size: 0.8rem; color: #64748b; text-transform: uppercase; }}
    .card .value {{ font-size: 1.5rem; font-weight: 700; margin-top: 4px; }}
    table {{ width: 100%; border-collapse: collapse; background: #ffffff; border: 1px solid #e2e8f0; }}
    th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #e2e8f0; font-size: 0.9rem; vertical-align: top; }}
    th {{ background: #f1f5f9; font-weight: 600; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.78rem; font-weight: 600; }}
    .status-pass {{ background: #dcfce7; color: #166534; }}
    .status-fail {{ background: #fee2e2; color: #991b1b; }}
    .status-error {{ background: #fef3c7; color: #92400e; }}
    .sev-critical {{ background: #7f1d1d; color: #ffffff; }}
    .sev-high {{ background: #fee2e2; color: #991b1b; }}
    .sev-medium {{ background: #ffedd5; color: #9a3412; }}
    .sev-low {{ background: #e0f2fe; color: #075985; }}
    .sev-info {{ background: #f1f5f9; color: #334155; }}
  </style>
</head>
<body>
  <h1>Cloud Misconfiguration Scan Report</h1>
  <div class="meta">
    <strong>Account ID:</strong> {account_id} |
    <strong>Regions:</strong> {regions_str} |
    <strong>Services:</strong> {services_str} |
    <strong>Started:</strong> {started_at} |
    <strong>Finished:</strong> {finished_at}
  </div>
  <div class="cards">
    <div class="card"><div class="label">Total Checks</div><div class="value">{summary["total"]}</div></div>
    <div class="card"><div class="label">Passed</div><div class="value">{summary["PASS"]}</div></div>
    <div class="card"><div class="label">Failed</div><div class="value">{summary["FAIL"]}</div></div>
    <div class="card"><div class="label">Errors</div><div class="value">{summary["ERROR"]}</div></div>
    <div class="card"><div class="label">Critical Fails</div><div class="value">{fail_by_sev["CRITICAL"]}</div></div>
    <div class="card"><div class="label">High Fails</div><div class="value">{fail_by_sev["HIGH"]}</div></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Rule ID</th>
        <th>Service</th>
        <th>Resource</th>
        <th>Region</th>
        <th>Severity</th>
        <th>Status</th>
        <th>Message</th>
        <th>Remediation</th>
      </tr>
    </thead>
    <tbody>
      {tbody_content}
    </tbody>
  </table>
</body>
</html>
"""

    def export(self, result: ScanResult, output_path: str | Path) -> Path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render(result), encoding="utf-8")
        return path
