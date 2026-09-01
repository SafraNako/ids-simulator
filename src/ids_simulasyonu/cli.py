from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import IDSEngine
from .events import NetworkEvent
from .simulator import SCENARIOS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ids-simulasyonu",
        description=(
            "İmza tabanlı (XSS/SQLi/path traversal/komut enjeksiyonu) ve "
            "davranışsal (port taraması, brute-force) bir IDS motorunu, "
            "sentetik trafik senaryolarına ya da kendi olay dosyana karşı "
            "çalıştırır. Canlı paket yakalama yapmaz — bir olay akışını "
            "(gerçek ya da sentetik) analiz eder."
        ),
    )
    parser.add_argument(
        "--senaryo", choices=sorted(SCENARIOS), default="karisik",
        help="çalıştırılacak yerleşik sentetik senaryo (varsayılan: karisik)",
    )
    parser.add_argument(
        "--dosya", dest="dosya",
        help="senaryo yerine bir JSON olay dosyası kullan (NetworkEvent alanlarının listesi)",
    )
    return parser


def _load_events_from_file(path: str) -> list[NetworkEvent]:
    data = json.loads(Path(path).read_text())
    return [NetworkEvent(**item) for item in data]


def run(args, *, out=sys.stdout) -> int:
    if args.dosya:
        try:
            events = _load_events_from_file(args.dosya)
        except Exception as exc:
            print(f"Hata: '{args.dosya}' okunamadı ({exc}).", file=sys.stderr)
            return 1
    else:
        events = SCENARIOS[args.senaryo]()

    engine = IDSEngine()
    alerts = engine.process(events)

    print(f"{len(events)} olay işlendi, {len(alerts)} uyarı üretildi.\n", file=out)
    for alert in alerts:
        print(f"[{alert.severity}] {alert.rule_name} — kaynak: {alert.source_ip}", file=out)
        print(f"  {alert.description}", file=out)
        print(file=out)

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
