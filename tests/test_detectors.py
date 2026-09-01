from __future__ import annotations

from ids_simulasyonu.detectors import BruteForceDetector, PortScanDetector
from ids_simulasyonu.events import NetworkEvent


def test_port_scan_detector_fires_once_threshold_crossed():
    detector = PortScanDetector(port_threshold=3, window_seconds=10.0)
    ports = [22, 80, 443, 8080]
    alerts = []
    for i, port in enumerate(ports):
        event = NetworkEvent(timestamp=float(i), source_ip="1.2.3.4", event_type="connection", dest_port=port)
        alert = detector.observe(event)
        if alert:
            alerts.append(alert)
    assert len(alerts) == 1
    assert alerts[0].source_ip == "1.2.3.4"
    assert alerts[0].rule_name == "Port Taraması"


def test_port_scan_detector_ignores_events_outside_the_window():
    detector = PortScanDetector(port_threshold=3, window_seconds=5.0)
    events = [
        NetworkEvent(timestamp=0.0, source_ip="1.2.3.4", event_type="connection", dest_port=22),
        NetworkEvent(timestamp=10.0, source_ip="1.2.3.4", event_type="connection", dest_port=80),
        NetworkEvent(timestamp=20.0, source_ip="1.2.3.4", event_type="connection", dest_port=443),
    ]
    alerts = [alert for event in events if (alert := detector.observe(event)) is not None]
    assert alerts == []


def test_port_scan_detector_ignores_non_connection_events():
    detector = PortScanDetector(port_threshold=1)
    event = NetworkEvent(timestamp=0.0, source_ip="1.2.3.4", event_type="http_request", dest_port=80, payload="x")
    assert detector.observe(event) is None


def test_port_scan_detector_tracks_sources_independently():
    detector = PortScanDetector(port_threshold=2, window_seconds=10.0)
    e1 = NetworkEvent(timestamp=0.0, source_ip="1.1.1.1", event_type="connection", dest_port=22)
    e2 = NetworkEvent(timestamp=0.1, source_ip="2.2.2.2", event_type="connection", dest_port=22)
    assert detector.observe(e1) is None
    assert detector.observe(e2) is None  # different source, its own count starts at 1


def test_brute_force_detector_fires_on_repeated_failures():
    detector = BruteForceDetector(failure_threshold=3, window_seconds=30.0)
    alerts = []
    for i in range(3):
        event = NetworkEvent(timestamp=float(i), source_ip="9.9.9.9", event_type="login_attempt", success=False)
        alert = detector.observe(event)
        if alert:
            alerts.append(alert)
    assert len(alerts) == 1
    assert alerts[0].rule_name == "Brute-Force Girişimi"


def test_brute_force_detector_ignores_successful_logins():
    detector = BruteForceDetector(failure_threshold=2)
    for i in range(5):
        event = NetworkEvent(timestamp=float(i), source_ip="9.9.9.9", event_type="login_attempt", success=True)
        assert detector.observe(event) is None


def test_brute_force_detector_does_not_spam_repeat_alerts():
    detector = BruteForceDetector(failure_threshold=2, window_seconds=100.0)
    alerts = []
    for i in range(6):
        event = NetworkEvent(timestamp=float(i), source_ip="9.9.9.9", event_type="login_attempt", success=False)
        alert = detector.observe(event)
        if alert:
            alerts.append(alert)
    assert len(alerts) == 1


def test_brute_force_detector_ignores_non_login_events():
    detector = BruteForceDetector(failure_threshold=1)
    event = NetworkEvent(timestamp=0.0, source_ip="9.9.9.9", event_type="connection", dest_port=22)
    assert detector.observe(event) is None
