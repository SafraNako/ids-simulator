from __future__ import annotations

from .events import NetworkEvent


def normal_traffic_scenario() -> list[NetworkEvent]:
    """Ordinary, benign traffic — nothing here should trigger an alert."""
    return [
        NetworkEvent(timestamp=0.0, source_ip="10.0.0.5", event_type="connection", dest_port=443),
        NetworkEvent(
            timestamp=0.5, source_ip="10.0.0.5", event_type="http_request",
            dest_port=443, payload="GET /index.html HTTP/1.1",
        ),
        NetworkEvent(timestamp=1.0, source_ip="10.0.0.6", event_type="login_attempt", success=True),
    ]


def port_scan_scenario() -> list[NetworkEvent]:
    attacker = "203.0.113.9"
    ports = [21, 22, 23, 25, 80, 443, 3306, 8080]
    return [
        NetworkEvent(timestamp=float(i), source_ip=attacker, event_type="connection", dest_port=port)
        for i, port in enumerate(ports)
    ]


def brute_force_scenario() -> list[NetworkEvent]:
    attacker = "203.0.113.50"
    return [
        NetworkEvent(timestamp=float(i) * 2, source_ip=attacker, event_type="login_attempt", success=False)
        for i in range(6)
    ]


def sqli_scenario() -> list[NetworkEvent]:
    attacker = "198.51.100.20"
    return [
        NetworkEvent(
            timestamp=0.0, source_ip=attacker, event_type="http_request", dest_port=80,
            payload="GET /login?username=admin' OR '1'='1--&password=x HTTP/1.1",
        ),
    ]


def xss_scenario() -> list[NetworkEvent]:
    attacker = "198.51.100.21"
    return [
        NetworkEvent(
            timestamp=0.0, source_ip=attacker, event_type="http_request", dest_port=80,
            payload="GET /yorum-ekle?mesaj=<script>alert(1)</script> HTTP/1.1",
        ),
    ]


def mixed_scenario() -> list[NetworkEvent]:
    """Every scenario above, concatenated — a busier, more realistic
    stream where the engine has to pick the real attacks out from
    ordinary background traffic."""
    events: list[NetworkEvent] = []
    events += normal_traffic_scenario()
    events += port_scan_scenario()
    events += brute_force_scenario()
    events += sqli_scenario()
    events += xss_scenario()
    return events


SCENARIOS = {
    "normal": normal_traffic_scenario,
    "port-tarama": port_scan_scenario,
    "bruteforce": brute_force_scenario,
    "sqli": sqli_scenario,
    "xss": xss_scenario,
    "karisik": mixed_scenario,
}
