from __future__ import annotations

from ids_simulasyonu.engine import IDSEngine
from ids_simulasyonu.events import NetworkEvent


def test_engine_flags_sqli_payload():
    engine = IDSEngine()
    events = [
        NetworkEvent(
            timestamp=0.0, source_ip="1.2.3.4", event_type="http_request", dest_port=80,
            payload="username=admin' OR '1'='1--",
        )
    ]
    alerts = engine.process(events)
    assert any(a.rule_name == "SQL Injection Denemesi" for a in alerts)


def test_engine_flags_port_scan():
    engine = IDSEngine()
    events = [
        NetworkEvent(timestamp=float(i), source_ip="5.5.5.5", event_type="connection", dest_port=port)
        for i, port in enumerate([21, 22, 23, 80, 443, 8080])
    ]
    alerts = engine.process(events)
    assert any(a.rule_name == "Port Taraması" for a in alerts)


def test_engine_flags_brute_force():
    engine = IDSEngine()
    events = [
        NetworkEvent(timestamp=float(i) * 2, source_ip="6.6.6.6", event_type="login_attempt", success=False)
        for i in range(5)
    ]
    alerts = engine.process(events)
    assert any(a.rule_name == "Brute-Force Girişimi" for a in alerts)


def test_engine_produces_no_alerts_for_benign_traffic():
    engine = IDSEngine()
    events = [
        NetworkEvent(timestamp=0.0, source_ip="10.0.0.5", event_type="connection", dest_port=443),
        NetworkEvent(
            timestamp=0.5, source_ip="10.0.0.5", event_type="http_request",
            dest_port=443, payload="GET /index.html HTTP/1.1",
        ),
        NetworkEvent(timestamp=1.0, source_ip="10.0.0.6", event_type="login_attempt", success=True),
    ]
    assert engine.process(events) == []


def test_engine_can_be_given_a_custom_signature_set():
    from ids_simulasyonu.rules import SignatureRule
    from ids_simulasyonu.alerts import DUSUK
    import re

    custom_rule = SignatureRule(
        name="Özel Kural", severity=DUSUK, pattern=re.compile(r"yasakli-kelime"), description="test",
    )
    engine = IDSEngine(signatures=[custom_rule])
    events = [
        NetworkEvent(timestamp=0.0, source_ip="1.2.3.4", event_type="http_request", payload="yasakli-kelime var"),
        NetworkEvent(timestamp=0.1, source_ip="1.2.3.4", event_type="http_request", payload="<script>alert(1)</script>"),
    ]
    alerts = engine.process(events)
    assert [a.rule_name for a in alerts] == ["Özel Kural"]
