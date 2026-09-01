from __future__ import annotations

from .alerts import Alert, YUKSEK
from .events import NetworkEvent


class PortScanDetector:
    """Stateful, behavior-based detection: the same source IP touching
    many distinct destination ports within a short time window is
    classic port-scan behavior, even though no single connection looks
    malicious on its own."""

    def __init__(self, *, port_threshold: int = 6, window_seconds: float = 10.0):
        self.port_threshold = port_threshold
        self.window_seconds = window_seconds
        self._history: dict[str, list[tuple[float, int]]] = {}
        self._last_alert: dict[str, float] = {}

    def observe(self, event: NetworkEvent) -> Alert | None:
        if event.event_type != "connection" or event.dest_port is None:
            return None

        history = self._history.setdefault(event.source_ip, [])
        history.append((event.timestamp, event.dest_port))
        cutoff = event.timestamp - self.window_seconds
        while history and history[0][0] < cutoff:
            history.pop(0)

        distinct_ports = {port for _, port in history}
        if len(distinct_ports) < self.port_threshold:
            return None

        last_alert = self._last_alert.get(event.source_ip)
        if last_alert is not None and event.timestamp - last_alert < self.window_seconds:
            return None  # already alerted for this ongoing scan; don't spam

        self._last_alert[event.source_ip] = event.timestamp
        return Alert(
            rule_name="Port Taraması",
            severity=YUKSEK,
            source_ip=event.source_ip,
            timestamp=event.timestamp,
            description=(
                f"{event.source_ip}, {self.window_seconds:.0f} saniye içinde "
                f"{len(distinct_ports)} farklı porta bağlandı."
            ),
        )


class BruteForceDetector:
    """Stateful detection for repeated failed login attempts from the
    same source within a short window."""

    def __init__(self, *, failure_threshold: int = 5, window_seconds: float = 30.0):
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds
        self._history: dict[str, list[float]] = {}
        self._last_alert: dict[str, float] = {}

    def observe(self, event: NetworkEvent) -> Alert | None:
        if event.event_type != "login_attempt" or event.success is not False:
            return None

        history = self._history.setdefault(event.source_ip, [])
        history.append(event.timestamp)
        cutoff = event.timestamp - self.window_seconds
        while history and history[0] < cutoff:
            history.pop(0)

        if len(history) < self.failure_threshold:
            return None

        last_alert = self._last_alert.get(event.source_ip)
        if last_alert is not None and event.timestamp - last_alert < self.window_seconds:
            return None

        self._last_alert[event.source_ip] = event.timestamp
        return Alert(
            rule_name="Brute-Force Girişimi",
            severity=YUKSEK,
            source_ip=event.source_ip,
            timestamp=event.timestamp,
            description=(
                f"{event.source_ip}, {self.window_seconds:.0f} saniye içinde "
                f"{len(history)} başarısız giriş denemesi yaptı."
            ),
        )
