"""Alert notification sinks."""

from __future__ import annotations

import json
import logging

from honeytrap.models import Alert

log = logging.getLogger(__name__)


def format_message(alert: Alert) -> tuple[str, str]:
    origin = alert.data_origin.upper()
    subject = f"[HoneyTrap][{origin}][{alert.severity}] {alert.rule_name}"[:100]
    techniques = ", ".join(f"{t.technique_id} {t.name}" for t in alert.techniques) or "none"
    body = "\n".join([
        f"Data origin : {origin}" + ("" if alert.data_origin == "live" else "  (NOT real external activity)"),
        f"Severity    : {alert.severity}  ({'; '.join(alert.severity_reasons)})",
        f"Rule        : {alert.rule_id} - {alert.rule_name}",
        f"Summary     : {alert.summary}",
        f"Source IP   : {alert.src_ip or ', '.join(alert.related_ips[:10])}",
        f"Window      : {alert.first_seen} -> {alert.last_seen}",
        f"ATT&CK      : {techniques}",
        f"Alert ID    : {alert.alert_id}",
        "",
        "Evidence:",
        json.dumps(alert.evidence, indent=2, default=str)[:2500],
    ])
    return subject, body


class LogNotifier:
    def __init__(self) -> None:
        self.sent: list[Alert] = []

    def notify(self, alert: Alert) -> None:
        subject, _ = format_message(alert)
        log.info("ALERT %s", subject)
        self.sent.append(alert)


class SNSNotifier:
    def __init__(self, topic_arn: str, client=None) -> None:
        if client is None:
            import boto3

            client = boto3.client("sns")
        self.topic_arn = topic_arn
        self.client = client

    def notify(self, alert: Alert) -> None:
        subject, body = format_message(alert)
        self.client.publish(
            TopicArn=self.topic_arn, Subject=subject, Message=body,
            MessageAttributes={
                "severity": {"DataType": "String", "StringValue": alert.severity},
                "data_origin": {"DataType": "String", "StringValue": alert.data_origin},
                "rule_id": {"DataType": "String", "StringValue": alert.rule_id},
            },
        )
