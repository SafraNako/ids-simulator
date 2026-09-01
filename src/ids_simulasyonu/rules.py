from __future__ import annotations

import re
from dataclasses import dataclass

from .alerts import ORTA, YUKSEK
from .events import NetworkEvent


@dataclass
class SignatureRule:
    """A stateless, per-event rule: does this one event's payload
    match a known-bad pattern? (Contrast with the stateful detectors
    in detectors.py, which need to see a sequence of events over
    time.)"""

    name: str
    severity: str
    pattern: re.Pattern
    description: str

    def matches(self, event: NetworkEvent) -> bool:
        if not event.payload:
            return False
        return bool(self.pattern.search(event.payload))


DEFAULT_SIGNATURES: list[SignatureRule] = [
    SignatureRule(
        name="XSS Denemesi",
        severity=YUKSEK,
        pattern=re.compile(r"<script[^>]*>", re.IGNORECASE),
        description="İstek gövdesinde bir <script> etiketi tespit edildi.",
    ),
    SignatureRule(
        name="SQL Injection Denemesi",
        severity=YUKSEK,
        pattern=re.compile(r"(\bOR\b\s+['\"]?1['\"]?\s*=\s*['\"]?1|--\s*$|;\s*DROP\s+TABLE)", re.IGNORECASE),
        description="İstek gövdesinde klasik bir SQL injection kalıbı tespit edildi.",
    ),
    SignatureRule(
        name="Dizin Gezinme (Path Traversal)",
        severity=ORTA,
        pattern=re.compile(r"\.\./"),
        description="İstek yolunda dizin gezinme (../) kalıbı tespit edildi.",
    ),
    SignatureRule(
        name="Hassas Dosya Erişimi",
        severity=ORTA,
        pattern=re.compile(r"/etc/passwd|\.env\b|\.git/config"),
        description="Hassas bir dosyaya erişim denemesi tespit edildi.",
    ),
    SignatureRule(
        name="Komut Enjeksiyonu Denemesi",
        severity=YUKSEK,
        pattern=re.compile(r";\s*(rm|cat|wget|curl)\s|\$\(.*\)|`[^`]+`"),
        description="İstek gövdesinde bir komut enjeksiyonu kalıbı tespit edildi.",
    ),
]
