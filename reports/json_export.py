"""
Export to JSON
"""
import json
from typing import Dict, Any
import os

def export_json(report: Dict[str, Any], output_path: str = "report.json") -> None:
    """
    Exports the generated report to a JSON file.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)
    print(f"Report successfully exported to {output_path}")
