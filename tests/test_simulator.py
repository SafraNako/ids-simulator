from __future__ import annotations

from ids_simulasyonu.engine import IDSEngine
from ids_simulasyonu.simulator import SCENARIOS


def test_every_scenario_produces_at_least_one_event():
    for name, builder in SCENARIOS.items():
        assert len(builder()) > 0, name


def test_port_scan_scenario_triggers_the_port_scan_detector():
    alerts = IDSEngine().process(SCENARIOS["port-tarama"]())
    assert any(a.rule_name == "Port Taraması" for a in alerts)


def test_bruteforce_scenario_triggers_the_brute_force_detector():
    alerts = IDSEngine().process(SCENARIOS["bruteforce"]())
    assert any(a.rule_name == "Brute-Force Girişimi" for a in alerts)


def test_sqli_scenario_triggers_the_sqli_signature():
    alerts = IDSEngine().process(SCENARIOS["sqli"]())
    assert any(a.rule_name == "SQL Injection Denemesi" for a in alerts)


def test_xss_scenario_triggers_the_xss_signature():
    alerts = IDSEngine().process(SCENARIOS["xss"]())
    assert any(a.rule_name == "XSS Denemesi" for a in alerts)


def test_normal_scenario_triggers_nothing():
    assert IDSEngine().process(SCENARIOS["normal"]()) == []


def test_mixed_scenario_triggers_every_detector_and_signature():
    alerts = IDSEngine().process(SCENARIOS["karisik"]())
    names = {a.rule_name for a in alerts}
    assert {
        "Port Taraması",
        "Brute-Force Girişimi",
        "SQL Injection Denemesi",
        "XSS Denemesi",
    } <= names
