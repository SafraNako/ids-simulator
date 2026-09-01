from __future__ import annotations

from dataclasses import dataclass


@dataclass
class NetworkEvent:
    """One event in a traffic/log stream — synthetic or real. Only the
    fields relevant to a given event_type need to be set; the rest
    keep their defaults."""

    timestamp: float
    source_ip: str
    event_type: str  # "connection" | "http_request" | "login_attempt"
    dest_port: int | None = None
    payload: str = ""
    success: bool | None = None  # only meaningful for "login_attempt"
