from __future__ import annotations

from ids_simulasyonu.events import NetworkEvent
from ids_simulasyonu.rules import DEFAULT_SIGNATURES


def _event(payload: str) -> NetworkEvent:
    return NetworkEvent(timestamp=0.0, source_ip="1.2.3.4", event_type="http_request", dest_port=80, payload=payload)


def _rule(name: str):
    return next(r for r in DEFAULT_SIGNATURES if r.name == name)


def test_xss_signature_matches_script_tag():
    assert _rule("XSS Denemesi").matches(_event("mesaj=<script>alert(1)</script>"))


def test_xss_signature_does_not_match_benign_text():
    assert not _rule("XSS Denemesi").matches(_event("mesaj=merhaba dunya"))


def test_sqli_signature_matches_or_1_equals_1():
    assert _rule("SQL Injection Denemesi").matches(_event("username=admin' OR '1'='1--"))


def test_sqli_signature_does_not_match_benign_query():
    assert not _rule("SQL Injection Denemesi").matches(_event("username=ayse&password=hunter2"))


def test_path_traversal_signature_matches_dot_dot_slash():
    assert _rule("Dizin Gezinme (Path Traversal)").matches(_event("GET /../../etc/shadow"))


def test_sensitive_file_signature_matches_etc_passwd():
    assert _rule("Hassas Dosya Erişimi").matches(_event("GET /etc/passwd"))


def test_sensitive_file_signature_does_not_match_path_traversal_alone():
    assert not _rule("Hassas Dosya Erişimi").matches(_event("GET /../../etc/shadow"))


def test_command_injection_signature_matches_semicolon_rm():
    assert _rule("Komut Enjeksiyonu Denemesi").matches(_event("host=example.com; rm -rf /"))


def test_signature_does_not_match_event_with_no_payload():
    event = NetworkEvent(timestamp=0.0, source_ip="1.2.3.4", event_type="connection", dest_port=80)
    assert not _rule("XSS Denemesi").matches(event)


def test_signature_names_are_unique():
    names = [r.name for r in DEFAULT_SIGNATURES]
    assert len(names) == len(set(names))
