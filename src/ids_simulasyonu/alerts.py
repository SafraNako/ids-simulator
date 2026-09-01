from __future__ import annotations

from dataclasses import dataclass

YUKSEK = "YUKSEK"
ORTA = "ORTA"
DUSUK = "DUSUK"


@dataclass
class Alert:
    rule_name: str
    severity: str
    source_ip: str
    timestamp: float
    description: str
