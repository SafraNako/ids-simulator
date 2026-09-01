from __future__ import annotations

from .alerts import Alert
from .detectors import BruteForceDetector, PortScanDetector
from .events import NetworkEvent
from .rules import DEFAULT_SIGNATURES, SignatureRule


class IDSEngine:
    """Combines stateless signature matching with stateful behavioral
    detectors into one pass over an ordered event stream."""

    def __init__(
        self,
        *,
        signatures: list[SignatureRule] | None = None,
        port_scan_detector: PortScanDetector | None = None,
        brute_force_detector: BruteForceDetector | None = None,
    ):
        self.signatures = signatures if signatures is not None else list(DEFAULT_SIGNATURES)
        self.port_scan_detector = port_scan_detector or PortScanDetector()
        self.brute_force_detector = brute_force_detector or BruteForceDetector()

    def process(self, events: list[NetworkEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        for event in events:
            for signature in self.signatures:
                if signature.matches(event):
                    alerts.append(
                        Alert(
                            rule_name=signature.name,
                            severity=signature.severity,
                            source_ip=event.source_ip,
                            timestamp=event.timestamp,
                            description=signature.description,
                        )
                    )

            port_scan_alert = self.port_scan_detector.observe(event)
            if port_scan_alert is not None:
                alerts.append(port_scan_alert)

            brute_force_alert = self.brute_force_detector.observe(event)
            if brute_force_alert is not None:
                alerts.append(brute_force_alert)

        return alerts
