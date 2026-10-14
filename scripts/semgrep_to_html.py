
import html
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
INPUT = ROOT / "reports" / "semgrep.json"
OUTPUT = ROOT / "reports" / "semgrep.html"


def esc(value):
    if value is None:
        return "N/A"
    return html.escape(str(value), quote=True)


def main():
    if not INPUT.is_file() or INPUT.stat().st_size == 0:
        raise SystemExit(f"Missing or empty report: {INPUT}")

    try:
        report = json.loads(INPUT.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid Semgrep JSON: {exc}")

    if not isinstance(report, dict):
        raise SystemExit("Expected a Semgrep JSON object.")

    findings = report.get("results", [])
    errors = report.get("errors", [])

    if not isinstance(findings, list) or not isinstance(errors, list):
        raise SystemExit("Invalid Semgrep report structure.")

    severity_counts = Counter()
    rows = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        extra = finding.get("extra") or {}
        metadata = extra.get("metadata") or {}
        start = finding.get("start") or {}

        severity = str(
            extra.get("severity")
            or metadata.get("severity")
            or "INFO"
        ).upper()

        if severity == "ERROR":
            severity = "HIGH"
        elif severity == "WARNING":
            severity = "MEDIUM"

        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            severity = "INFO"

        severity_counts[severity] += 1

        rule_id = finding.get("check_id", "N/A")
        message = extra.get("message", "No description provided.")
        file_path = finding.get("path", "N/A")
        line = start.get("line", "N/A")
        category = metadata.get("category", "N/A")
        fix = metadata.get("fix", "Review the finding and apply an appropriate fix.")

        rows.append(f"""
        <article class="finding">
          <div class="finding-top">
            <span class="severity {severity.lower()}">{esc(severity)}</span>
            <code>{esc(rule_id)}</code>
          </div>
          <h3>{esc(message)}</h3>
          <p><strong>File:</strong> <code>{esc(file_path)}:{esc(line)}</code></p>
          <p><strong>Category:</strong> {esc(category)}</p>
          <p><strong>Remediation:</strong> {esc(fix)}</p>
        </article>
        """)

    errors_html = "".join(
        f"<li>{esc(json.dumps(error, ensure_ascii=False))}</li>"
        for error in errors
    ) or "<li>No scanner errors reported.</li>"

    if not rows:
        rows.append("""
        <div class="empty">
          <h3>No findings reported</h3>
          <p>This means Semgrep reported no findings in its results array.
          Confirm that the scan completed successfully and evaluated the
          intended files before interpreting this as a clean scan.</p>
        </div>
        """)

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Semgrep Security Report</title>
<style>
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  background: #f3f5f9;
  color: #172033;
  font-family: "Segoe UI", Arial, sans-serif;
  line-height: 1.55;
}}
header {{ background: #172033; color: white; padding: 28px 20px; }}
.container {{ max-width: 1050px; margin: auto; }}
header h1 {{ margin: 0; }}
header p {{ color: #cbd5e1; margin-bottom: 0; }}
main {{ padding: 24px 20px 40px; }}
.meta {{ color: #64748b; font-size: 13px; }}
.cards {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin: 20px 0 28px;
}}
.card, .finding, .empty {{
  background: white;
  border: 1px solid #e2e8f0;
  border-radius: 12px;
  padding: 18px;
}}
.card .label {{ color: #64748b; font-size: 13px; }}
.card .value {{ font-size: 28px; font-weight: 750; }}
.finding {{ margin-bottom: 14px; overflow-wrap: anywhere; }}
.finding-top {{ display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }}
.severity {{ font-size: 12px; font-weight: 800; padding: 4px 9px; border-radius: 5px; }}
.critical {{ background: #7f1d1d; color: white; }}
.high {{ background: #fee2e2; color: #991b1b; }}
.medium {{ background: #ffedd5; color: #9a3412; }}
.low {{ background: #fef9c3; color: #854d0e; }}
.info {{ background: #e0f2fe; color: #075985; }}
code {{ overflow-wrap: anywhere; }}
.empty {{ text-align: center; padding: 32px; }}
.errors {{ border-left: 4px solid #dc2626; padding-left: 16px; }}
footer {{ color: #64748b; font-size: 12px; margin-top: 28px; }}
@media print {{
  body {{ background: white; }}
  header {{ print-color-adjust: exact; }}
  .finding, .card {{ break-inside: avoid; }}
}}
</style>
</head>
<body>
<header>
  <div class="container">
    <h1>Semgrep Security Report</h1>
    <p>Static Application Security Testing (SAST)</p>
  </div>
</header>
<main class="container">
  <p class="meta">Semgrep version: {esc(report.get("version", "Unknown"))}
  &bull; Generated: {esc(generated)}</p>

  <section class="cards">
    <div class="card"><div class="label">Total findings</div>
      <div class="value">{len(findings)}</div></div>
    <div class="card"><div class="label">Critical</div>
      <div class="value">{severity_counts["CRITICAL"]}</div></div>
    <div class="card"><div class="label">High</div>
      <div class="value">{severity_counts["HIGH"]}</div></div>
    <div class="card"><div class="label">Medium</div>
      <div class="value">{severity_counts["MEDIUM"]}</div></div>
    <div class="card"><div class="label">Low / Info</div>
      <div class="value">{severity_counts["LOW"] + severity_counts["INFO"]}</div></div>
  </section>

  <h2>Findings</h2>
  {"".join(rows)}

  <h2>Scanner errors ({len(errors)})</h2>
  <ul class="errors">{errors_html}</ul>

  <footer>
    Generated from the Semgrep JSON report. A zero-finding report is not
    proof that the application is free of vulnerabilities.
  </footer>
</main>
</body>
</html>
"""

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(page, encoding="utf-8")
    print(f"Semgrep HTML report saved to: {OUTPUT}")


if __name__ == "__main__":
    main()
