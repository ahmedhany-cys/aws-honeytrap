"""Core data model shared by ingestion, detection, enrichment, storage and the dashboard."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum, StrEnum
from typing import Any


class DataOrigin(StrEnum):
    """Where a record came from. Never mix these up in reporting.

    LIVE        - captured by an internet-exposed sensor from real, unsolicited traffic.
    SIMULATION  - produced by our own controlled attack scripts against a honeypot we own.
    SYNTHETIC   - generated offline for demos and tests; no honeypot was involved.
    """

    LIVE = "live"
    SIMULATION = "simulation"
    SYNTHETIC = "synthetic"


class Severity(int, Enum):
    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[value.strip().upper()]

    def escalate(self, steps: int = 1) -> Severity:
        return Severity(min(Severity.CRITICAL, self + steps))


# Cowrie event IDs grouped into the categories the engine reasons about.
EVENT_CATEGORIES: dict[str, str] = {
    "cowrie.session.connect": "connection",
    "cowrie.session.closed": "connection",
    "cowrie.client.version": "client",
    "cowrie.client.kex": "client",
    "cowrie.client.size": "client",
    "cowrie.client.var": "client",
    "cowrie.client.fingerprint": "client",
    "cowrie.login.failed": "authentication",
    "cowrie.login.success": "authentication",
    "cowrie.command.input": "command",
    "cowrie.command.failed": "command",
    "cowrie.command.success": "command",
    "cowrie.session.file_download": "download",
    "cowrie.session.file_download.failed": "download",
    "cowrie.session.file_upload": "download",
    "cowrie.session.file_write": "file_write",  # synthetic id: Cowrie logs shell redirections as file_download
    "cowrie.direct-tcpip.request": "tunnel",
    "cowrie.direct-tcpip.data": "tunnel",
    "cowrie.log.closed": "session",
    "cowrie.session.params": "session",
    "cowrie.telnet.exploit_attempt": "exploit",
}


@dataclass
class Event:
    """A normalised Cowrie event. Passwords never appear in clear text here."""

    event_id: str
    timestamp: str  # ISO-8601 UTC, e.g. 2026-10-30T12:00:00.123456Z
    event_type: str
    category: str
    session_id: str | None
    src_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None  # ssh | telnet
    sensor: str | None = None
    data_origin: str = DataOrigin.SIMULATION.value
    username: str | None = None
    password_masked: str | None = None
    password_fingerprint: str | None = None
    password_length: int | None = None
    credential_fingerprint: str | None = None
    login_success: bool | None = None
    command: str | None = None
    url: str | None = None
    file_path: str | None = None  # destination path inside the fake filesystem
    file_sha256: str | None = None
    duration_seconds: float | None = None
    client_version: str | None = None
    hassh: str | None = None
    tunnel_destination: str | None = None
    message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Event:
        known = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class TechniqueMapping:
    technique_id: str
    name: str
    tactics: list[str]
    url: str
    confidence: str  # high | medium | low
    evidence: list[str] = field(default_factory=list)


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    rule_name: str
    severity: str  # Severity label
    entity: str  # "ip:1.2.3.4", "session:abc", "credential:<fp>"
    src_ip: str | None
    first_seen: str
    last_seen: str
    summary: str
    data_origin: str
    session_ids: list[str] = field(default_factory=list)
    related_ips: list[str] = field(default_factory=list)
    evidence_event_ids: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    techniques: list[TechniqueMapping] = field(default_factory=list)
    severity_reasons: list[str] = field(default_factory=list)
    classification: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Alert:
        known = cls.__dataclass_fields__.keys()
        values = {k: v for k, v in data.items() if k in known}
        values["techniques"] = [
            t if isinstance(t, TechniqueMapping) else TechniqueMapping(**t)
            for t in values.get("techniques", [])
        ]
        return cls(**values)

    @property
    def severity_level(self) -> Severity:
        return Severity.parse(self.severity)
