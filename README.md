# Secure Code Release Agent

Deterministic security release gate for Semgrep, Trivy, and Gitleaks. Scanner execution and policy decisions are deliberately separate: an unavailable, invalid, or incomplete required scan blocks a release; it is never counted as zero findings.

## Local usage

Run an existing Semgrep JSON report through the normalization, risk, policy, and reporting pipeline:

```powershell
python -m engine.agent reports/semgrep.json
```

Run all configured adapters (requires the `semgrep`, `trivy`, and `gitleaks` executables on `PATH`):

```powershell
python -m engine.agent --scan --target .
```

The command writes `reports/release-report.json` and `reports/release-report.html`. Raw scanner JSON is retained only when that scanner was actually run. Gitleaks findings intentionally contain `[REDACTED]` evidence; do not upload reports that contain raw scanner output without reviewing tool configuration.

## Policy and outcomes

`policies/release-policy.json` is the single source of truth. It configures blocked/review severities, risk cap, required scanners, and whether missing required scans fail. Outcomes are `PASS`, `REVIEW`, and `BLOCK`; only `PASS` authorizes the CLI gate.

Risk is the sum of unique-finding severity weights, capped at 100: Critical 10, High 7, Medium 4, Low 1, Info/Unknown 0. Deduplication is by a stable scanner/rule/location/package fingerprint. Risk is evidence, not the decision itself.

## Development

```powershell
python -m unittest discover -s tests -v
```

`pytest` is optional and is not required by the runtime. CI should install the scanners on the hosted Linux runner and preserve raw JSON plus the combined reports as artifacts, even when the release is blocked.
