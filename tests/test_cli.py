from __future__ import annotations

import io
import json

from ids_simulasyonu.cli import build_parser, run


def test_build_parser_defaults():
    parser = build_parser()
    args = parser.parse_args([])
    assert args.senaryo == "karisik"
    assert args.dosya is None


def test_run_default_scenario_reports_alerts():
    parser = build_parser()
    args = parser.parse_args([])
    out = io.StringIO()
    exit_code = run(args, out=out)
    assert exit_code == 0
    text = out.getvalue()
    assert "olay işlendi" in text
    assert "Port Taraması" in text


def test_run_normal_scenario_reports_zero_alerts():
    parser = build_parser()
    args = parser.parse_args(["--senaryo", "normal"])
    out = io.StringIO()
    run(args, out=out)
    assert "0 uyarı üretildi" in out.getvalue()


def test_run_with_custom_event_file(tmp_path):
    events = [
        {
            "timestamp": 0.0, "source_ip": "1.2.3.4", "event_type": "http_request",
            "dest_port": 80, "payload": "mesaj=<script>alert(1)</script>",
        },
    ]
    path = tmp_path / "olaylar.json"
    path.write_text(json.dumps(events))

    parser = build_parser()
    args = parser.parse_args(["--dosya", str(path)])
    out = io.StringIO()
    exit_code = run(args, out=out)
    assert exit_code == 0
    assert "XSS Denemesi" in out.getvalue()


def test_run_reports_error_for_missing_file():
    parser = build_parser()
    args = parser.parse_args(["--dosya", "/does/not/exist.json"])
    exit_code = run(args)
    assert exit_code == 1


def test_run_reports_error_for_malformed_file(tmp_path):
    path = tmp_path / "bozuk.json"
    path.write_text("not json{{{")
    parser = build_parser()
    args = parser.parse_args(["--dosya", str(path)])
    exit_code = run(args)
    assert exit_code == 1
