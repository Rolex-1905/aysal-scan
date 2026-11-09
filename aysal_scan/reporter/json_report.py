import json
from pathlib import Path

from aysal_scan.models import ScanReport


def write_json_report(report: ScanReport, output_path: Path | None = None) -> str:
    """Serialize the report to JSON (schema_version 2).

    If ``output_path`` is given the JSON is also written there (parent directories are
    created). The JSON string is always returned.
    """
    data = report.model_dump(mode="json")
    json_str = json.dumps(data, indent=2, default=str)

    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json_str, encoding="utf-8")

    return json_str
