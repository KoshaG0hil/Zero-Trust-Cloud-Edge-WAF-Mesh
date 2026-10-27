"""Configuration and data structures for Zero-Trust Edge request inspection."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml


class MitigationAction(str, Enum):
    ALLOW = "ALLOW"
    CHALLENGE_CAPTCHA = "CHALLENGE_CAPTCHA"
    DIVERT_HONEYPOT = "DIVERT_HONEYPOT"
    BLOCK = "BLOCK"


@dataclass
class RequestContext:
    """Represents an inbound HTTP request captured at the CloudFront / WAF edge."""

    client_ip: str
    method: str
    uri: str
    headers: Dict[str, str] = field(default_factory=dict)
    query_string: str = ""
    body: str = ""
    country_code: str = "US"
    asn: int = 15169
    request_id: str = "req-default-000"

    def get_header(self, name: str, default: str = "") -> str:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default


@dataclass
class EvaluationDecision:
    """Final decision rendered by the Zero-Trust Edge Evaluator."""

    request_id: str
    client_ip: str
    risk_score: int
    action: MitigationAction
    matched_rules: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    execution_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "client_ip": self.client_ip,
            "risk_score": self.risk_score,
            "action": self.action.value,
            "matched_rules": self.matched_rules,
            "reasons": self.reasons,
            "execution_time_ms": self.execution_time_ms,
        }


class ZeroTrustConfig:
    """Loads and encapsulates security rulesets and risk matrix parameters."""

    def __init__(self, config_dir: Optional[Path] = None):
        if config_dir is None:
            config_dir = Path(__file__).resolve().parent.parent.parent / "rulesets"
        self.config_dir = config_dir

        self.matrix: Dict[str, Any] = self._load_yaml("zero_trust_matrix.yaml")
        self.bot_signatures: Dict[str, Any] = self._load_yaml("bot_signatures.yaml")

    def _load_yaml(self, filename: str) -> Dict[str, Any]:
        file_path = self.config_dir / filename
        if not file_path.exists():
            return {}
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}

    @property
    def sanctioned_countries(self) -> List[str]:
        return self.matrix.get("sanctioned_geo_countries", ["KP", "IR", "SY", "CU"])

    @property
    def risk_thresholds(self) -> Dict[str, int]:
        return self.matrix.get(
            "risk_thresholds",
            {
                "allow_max_score": 25,
                "captcha_challenge_min_score": 26,
                "captcha_challenge_max_score": 65,
                "honeypot_divert_min_score": 66,
                "honeypot_divert_max_score": 85,
                "hard_block_min_score": 86,
            },
        )
