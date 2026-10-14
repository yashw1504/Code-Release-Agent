
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPORT_PATH = PROJECT_ROOT / "reports" / "release-report.json"


def save_report(result: dict, output_path=None) -> Path:
    """Save the agent result as valid JSON and return the report path."""
    if not isinstance(result, dict):
        raise ValueError("Report result must be a dictionary")

    report_path = (
        Path(output_path)
        if output_path is not None
        else DEFAULT_REPORT_PATH
    )

    report_path.parent.mkdir(parents=True, exist_ok=True)

    # Write to a temporary file first, so an interrupted write
    # is less likely to leave an empty or partially written report.
    temp_path = report_path.with_suffix(report_path.suffix + ".tmp")

    try:
        with temp_path.open("w", encoding="utf-8", newline="\n") as file:
            json.dump(result, file, indent=2, ensure_ascii=False)
            file.write("\n")
            file.flush()

        temp_path.replace(report_path)
    finally:
        if temp_path.exists():
            temp_path.unlink()

    return report_path
