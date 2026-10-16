
import html
import json
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
REPORT_DIR = BASE_DIR / "reports"


def _escape(value):
    """Escape values before inserting them into HTML."""
    if value is None:
        return "N/A"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    return html.escape(str(value), quote=True)


def _severity(finding):
    value = finding.get("severity", "INFO")
    return str(value).upper()


def _render_finding(finding, index):
    severity = _severity(finding)
    allowed_severities = {
        "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    }

    if severity not in allowed_severities:
        severity = "INFO"

    title = finding.get("name") or finding.get("title") or "Security finding"
    check_id = finding.get("check_id") or finding.get("rule_id") or "N/A"
    file_path = (
        finding.get("file_path")
        or finding.get("path")
        or finding.get("file")
        or finding.get("location")
        or "N/A"
    )
    line = finding.get("line_number") or finding.get("start_line") or finding.get("line") or "N/A"
    description = finding.get("description") or finding.get("message") or "No description provided."
    impact = finding.get("business_impact") or "Not specified."
    if finding.get("scanner") == "gitleaks":
        description = "Potential secret detected. Value withheld."
    remediation = finding.get("remediation") or "Review the finding and apply the recommended secure coding fix."

    return f"""
    <article class="finding">
      <div class="finding-header">
        <span class="severity {severity.lower()}">{_escape(severity)}</span>
        <span class="finding-number">Finding #{index}</span>
      </div>
      <h3>{_escape(title)}</h3>
      <dl>
        <dt>Rule ID</dt><dd>{_escape(check_id)}</dd>
        <dt>Location</dt><dd>{_escape(file_path)}:{_escape(line)}</dd>
        <dt>Description</dt><dd>{_escape(description)}</dd>
        <dt>Business impact</dt><dd>{_escape(impact)}</dd>
        <dt>Remediation</dt><dd>{_escape(remediation)}</dd>
      </dl>
    </article>
    """


def generate_html_report(result, output_path=None):
    """Generate a human-readable HTML report from the agent result."""
    if output_path is None:
        output_path = REPORT_DIR / "release-report.html"
    else:
        output_path = Path(output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    findings = result.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    counts = {name: 0 for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    for finding in findings:
        if isinstance(finding, dict):
            severity = _severity(finding)
            if severity in counts:
                counts[severity] += 1
            else:
                counts["INFO"] += 1

    decision = str(
        result.get("decision")
        or result.get("release_decision")
        or result.get("status")
        or "REVIEW"
    ).upper()

    decision_class = decision.lower()
    if decision not in {"PASS", "BLOCK", "REVIEW"}:
        decision = "REVIEW"
        decision_class = "review"

    risk_score = result.get("risk_score", "N/A")
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if findings:
        findings_html = "\n".join(
            _render_finding(finding, index)
            for index, finding in enumerate(findings, start=1)
            if isinstance(finding, dict)
        )
    else:
        findings_html = """
        <div class="empty-state">
          <h3>No findings were reported</h3>
          <p>Confirm that the security scan completed successfully and that
          the release policy permits a clean scan to pass.</p>
        </div>
        """

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure Code Release Agent - Security Report</title>
<style>
:root {{
  color-scheme: light;
  font-family: Inter, "Segoe UI", Arial, sans-serif;
  color: #172033;
  background: #f3f5f9;
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; line-height: 1.55; }}
header {{ background: #172033; color: white; padding: 28px 20px; }}
.container {{ max-width: 1080px; margin: auto; }}
header h1 {{ margin: 0 0 5px; font-size: 26px; }}
header p {{ color: #cbd5e1; margin: 0; }}
main {{ padding: 24px 20px 40px; }}
.topline {{ display: flex; align-items: center; justify-content: space-between;
  gap: 12px; flex-wrap: wrap; margin-bottom: 20px; }}
.decision {{ display: inline-block; padding: 7px 13px; border-radius: 8px;
  font-weight: 800; font-size: 13px; }}
.block {{ color: #991b1b; background: #fee2e2; }}
.pass {{ color: #166534; background: #dcfce7; }}
.review {{ color: #92400e; background: #fef3c7; }}
.cards {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px; margin-bottom: 28px; }}
.card, .finding, .empty-state {{ background: white; border: 1px solid #e2e8f0;
  border-radius: 12px; padding: 18px; }}
.card .label {{ color: #64748b; font-size: 13px; }}
.card .value {{ font-size: 29px; font-weight: 750; margin-top: 5px; }}
h2 {{ font-size: 20px; margin: 26px 0 14px; }}
.finding {{ margin-bottom: 14px; }}
.finding-header {{ display: flex; justify-content: space-between; gap: 12px;
  align-items: center; flex-wrap: wrap; }}
.severity {{ font-size: 12px; font-weight: 800; padding: 4px 9px;
  border-radius: 6px; }}
.critical {{ background: #7f1d1d; color: white; }}
.high {{ background: #fee2e2; color: #991b1b; }}
.medium {{ background: #ffedd5; color: #9a3412; }}
.low {{ background: #fef9c3; color: #854d0e; }}
.info {{ background: #e0f2fe; color: #075985; }}
.finding-number {{ font-size: 12px; color: #64748b; }}
.finding h3 {{ margin: 12px 0; font-size: 17px; }}
dl {{ display: grid; grid-template-columns: 150px minmax(0, 1fr);
  gap: 8px 14px; margin: 0; overflow-wrap: anywhere; }}
dt {{ color: #64748b; font-size: 13px; }}
dd {{ margin: 0; white-space: pre-wrap; }}
.empty-state {{ text-align: center; padding: 32px; }}
footer {{ color: #64748b; font-size: 12px; margin-top: 25px; }}
@media (max-width: 640px) {{
  .cards {{ grid-template-columns: 1fr; }}
  dl {{ grid-template-columns: 1fr; gap: 3px; }}
  dd {{ margin-bottom: 9px; }}
}}
@media print {{
  :root {{ background: white; }}
  header {{ background: #172033 !important; print-color-adjust: exact; }}
  main {{ padding: 10px 0; }}
  .finding, .card {{ break-inside: avoid; }}
  .finding {{ box-shadow: none; }}
}}
</style>
</head>
<body>
<header>
  <div class="container">
    <h1>Secure Code Release Agent</h1>
    <p>Security Assessment &amp; Release Gate Report</p>
  </div>
</header>
<main class="container">
  <div class="topline">
    <div>
      <strong>Release assessment</strong><br>
      <span>Generated: {_escape(generated_at)}</span>
    </div>
    <span class="decision {decision_class}">{_escape(decision)}</span>
  </div>

  <section class="cards" aria-label="Report summary">
    <div class="card">
      <div class="label">Risk score</div>
      <div class="value">{_escape(risk_score)}</div>
    </div>
    <div class="card">
      <div class="label">Total findings</div>
      <div class="value">{len(findings)}</div>
    </div>
    <div class="card">
      <div class="label">Critical / High</div>
      <div class="value">{counts["CRITICAL"]} / {counts["HIGH"]}</div>
    </div>
  </section>

  <h2>Severity breakdown</h2>
  <section class="cards" aria-label="Severity breakdown">
    <div class="card"><div class="label">Critical</div>
      <div class="value">{counts["CRITICAL"]}</div></div>
    <div class="card"><div class="label">High / Medium</div>
      <div class="value">{counts["HIGH"]} / {counts["MEDIUM"]}</div></div>
    <div class="card"><div class="label">Low / Info</div>
      <div class="value">{counts["LOW"]} / {counts["INFO"]}</div></div>
  </section>

  <h2>Security findings</h2>
  {findings_html}

  <footer>
    Generated by Secure Code Release Agent. Review findings and scan errors
    before making a release decision. A clean result is not proof that code
    is free of vulnerabilities.
  </footer>
</main>
</body>
</html>
"""

    output_path.write_text(page, encoding="utf-8")
    return output_path
