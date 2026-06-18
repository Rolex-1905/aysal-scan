import json
from pathlib import Path
from aysal_scan.models import ScanReport


def write_json_report(report: ScanReport, output_path: Path | None = None) -> str:
    """
    Serialize the report to JSON.
    If output_path is given, write to file. Otherwise return the JSON string.
    """
    data = report.model_dump(mode="json")
    json_str = json.dumps(data, indent=2, default=str)

    if output_path:
        output_path.write_text(json_str, encoding="utf-8")

    return json_str
