"""Executive Threat Posture and Cryptographic Audit Bulletin Generator."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List
from ..core.config import EvaluationDecision
from .telemetry_streamer import EdgeMetricSnapshot


class ThreatBulletinGenerator:
    """Produces tamper-evident JSON and Markdown Edge Security Audit reports."""

    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        snapshot: EdgeMetricSnapshot,
        decisions: List[EvaluationDecision],
    ) -> Dict[str, Any]:
        timestamp = datetime.now(timezone.utc).isoformat()

        report_data = {
            "platform": "Zero-Trust Cloud Edge & Intelligent WAF Bot Defense Mesh",
            "author": "Kosha Gohil",
            "generated_at": timestamp,
            "metrics": snapshot.to_dict(),
            "decisions_sample": [d.to_dict() for d in decisions[:50]],
        }

        # Calculate SHA-256 Digest for cryptographic integrity verification
        canonical_json = json.dumps(report_data, sort_keys=True).encode("utf-8")
        sha256_hash = hashlib.sha256(canonical_json).hexdigest()
        report_data["sha256_checksum"] = sha256_hash

        return report_data

    def save_report(self, report_data: Dict[str, Any], filename: str = "sample_waf_telemetry.json") -> Path:
        out_file = self.output_dir / filename
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        return out_file
