# ids-simulasyonu

[![Tests](https://github.com/SafraNako/ids-simulasyonu/actions/workflows/tests.yml/badge.svg)](https://github.com/SafraNako/ids-simulasyonu/actions/workflows/tests.yml)

A small intrusion-detection engine, run against synthetic traffic
instead of a live network. No raw sockets, no packet capture, no root
privileges — you feed it an ordered stream of events (built-in demo
scenarios, or your own JSON file) and it tells you what a real IDS
would have flagged and why.

Two detection styles, combined in one pass:

- **Signature-based** (stateless): does *this one event's* payload
  match a known-bad pattern? `<script>` tags, classic `' OR '1'='1`
  SQL injection, `../` path traversal, `/etc/passwd`-style sensitive
  file access, shell command injection.
- **Behavior-based** (stateful): does a *sequence* of events from the
  same source look wrong, even though no single one does? Port
  scanning (many distinct ports, one source, short window) and
  brute-force login attempts (many failures, one source, short
  window) both need a sliding time window to detect at all.

## Usage

```bash
ids-simulasyonu --senaryo karisik
```

```
19 olay işlendi, 4 uyarı üretildi.

[YUKSEK] Port Taraması — kaynak: 203.0.113.9
  203.0.113.9, 10 saniye içinde 6 farklı porta bağlandı.

[YUKSEK] Brute-Force Girişimi — kaynak: 203.0.113.50
  203.0.113.50, 30 saniye içinde 5 başarısız giriş denemesi yaptı.

[YUKSEK] SQL Injection Denemesi — kaynak: 198.51.100.20
  İstek gövdesinde klasik bir SQL injection kalıbı tespit edildi.

[YUKSEK] XSS Denemesi — kaynak: 198.51.100.21
  İstek gövdesinde bir <script> etiketi tespit edildi.
```

Built-in scenarios: `normal`, `port-tarama`, `bruteforce`, `sqli`,
`xss`, `karisik` (all of the above concatenated). `normal` is the
control case — it should never produce an alert:

```bash
ids-simulasyonu --senaryo normal
# 3 olay işlendi, 0 uyarı üretildi.
```

Or point it at your own event stream instead of a built-in scenario:

```bash
ids-simulasyonu --dosya olaylar.json
```

```json
[
  {"timestamp": 0.0, "source_ip": "9.9.9.9", "event_type": "http_request",
   "dest_port": 80, "payload": "cmd=; cat /etc/passwd"}
]
```

## Why "simulation" instead of live capture

This isn't a lighter version of a real IDS — it's the detection logic
(signatures + stateful windowing) with the packet-capture layer
removed on purpose. Real traffic capture needs raw sockets, elevated
privileges, and — if pointed at anyone else's network — the same
authorization boundary as any other network tool. None of that is
needed to demonstrate or test *detection logic*, so this project
doesn't have it. If you want to feed it real data, translate your own
logs into the same JSON event shape and use `--dosya`.

## How the detectors decide "this is one scan, not fifty alerts"

A naive port-scan detector re-fires on every single connection once
the threshold is crossed. `PortScanDetector` and `BruteForceDetector`
both track the last time they alerted for a given source IP, and stay
quiet for one more window afterward — so a 20-port scan produces one
alert, not fourteen.

## Setup

```bash
git clone https://github.com/SafraNako/ids-simulasyonu.git
cd ids-simulasyonu
pip install -e .
```

No external dependencies — pure standard library.

## Development

```bash
pip install -e ".[dev]"
pytest -v
```

Every regex signature was checked by hand against real matching and
non-matching payloads before being written into `rules.py` — including
the negative cases (e.g. the sensitive-file rule shouldn't fire on a
plain path-traversal payload that never mentions `/etc/passwd`). The
stateful detectors are tested for exact windowing behavior: events
just outside the time window don't count, and a sustained attack
produces one alert, not one per event.

## License

MIT — see [LICENSE](LICENSE).
