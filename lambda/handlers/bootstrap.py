"""Shared cold-start setup for the HoneyTrap Lambdas.

Secrets (HMAC key, optional AbuseIPDB / VirusTotal keys) are read from SSM
Parameter Store SecureStrings once per container, never from plain env vars.
"""

from __future__ import annotations

import json
import logging
import os
import time
from functools import lru_cache

import boto3

from honeytrap.enrichment.service import EnrichmentService
from honeytrap.ingestion.redaction import Redactor
from honeytrap.notify import SNSNotifier
from honeytrap.storage.repository import StoreCache
from honeytrap.storage.store import S3Store

log = logging.getLogger()
log.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def _param(name: str | None, required: bool = False) -> str | None:
    if not name:
        if required:
            raise RuntimeError("required SSM parameter name not configured")
        return None
    ssm = boto3.client("ssm")
    try:
        value = ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    except ssm.exceptions.ParameterNotFound:
        if required:
            raise
        log.info("optional parameter %s not found; integration disabled", name)
        return None
    # Placeholder values created by Terraform mean "not configured".
    return None if value in ("", "unset", "CHANGE_ME") else value


@lru_cache(maxsize=1)
def context() -> dict:
    bucket = os.environ["TELEMETRY_BUCKET"]
    store = S3Store(bucket)
    redactor = Redactor(_param(os.environ.get("HMAC_KEY_PARAM"), required=True))

    from honeytrap.enrichment.providers import AbuseIPDB, GeoIP, VirusTotal

    providers = [
        AbuseIPDB(api_key=_param(os.environ.get("ABUSEIPDB_KEY_PARAM")) or ""),
        VirusTotal(api_key=_param(os.environ.get("VIRUSTOTAL_KEY_PARAM")) or ""),
        GeoIP(city_db=os.environ.get("HONEYTRAP_GEOIP_CITY_DB", "")),
    ]
    enrichment = EnrichmentService(providers=providers, cache=StoreCache(store),
                                   ttl_hours=float(os.environ.get("ENRICHMENT_TTL_HOURS", "24")))
    topic = os.environ.get("SNS_TOPIC_ARN")
    return {
        "bucket": bucket,
        "store": store,
        "redactor": redactor,
        "enrichment": enrichment,
        "notifier": SNSNotifier(topic) if topic else None,
        "lookup_limit": int(os.environ.get("ENRICHMENT_LOOKUP_LIMIT", "25")),
    }


def emit_metrics(function: str, metrics: dict[str, int]) -> None:
    """CloudWatch Embedded Metric Format: metrics from a log line, no PutMetricData calls."""
    print(json.dumps({
        "_aws": {"Timestamp": int(time.time() * 1000), "CloudWatchMetrics": [{
            "Namespace": "HoneyTrap", "Dimensions": [["Function"]],
            "Metrics": [{"Name": k, "Unit": "Count"} for k in metrics]}]},
        "Function": function, **metrics,
    }))
