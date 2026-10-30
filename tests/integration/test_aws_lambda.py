"""Lambda handlers against moto-emulated S3, SSM and SNS (no real AWS calls, no cost)."""

import gzip
import importlib
import json

import boto3
import pytest
from moto import mock_aws

BUCKET = "honeytrap-test-telemetry-000000000000"
REGION = "us-west-1"


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": REGION})
        ssm = boto3.client("ssm", region_name=REGION)
        ssm.put_parameter(Name="/ht/hmac-key", Value="integration-hmac-key", Type="SecureString")
        ssm.put_parameter(Name="/ht/abuseipdb-api-key", Value="unset", Type="SecureString")
        topic = boto3.client("sns", region_name=REGION).create_topic(Name="ht-alerts")["TopicArn"]
        monkeypatch.setenv("TELEMETRY_BUCKET", BUCKET)
        monkeypatch.setenv("HMAC_KEY_PARAM", "/ht/hmac-key")
        monkeypatch.setenv("ABUSEIPDB_KEY_PARAM", "/ht/abuseipdb-api-key")
        monkeypatch.setenv("VIRUSTOTAL_KEY_PARAM", "/ht/missing")
        monkeypatch.setenv("SNS_TOPIC_ARN", topic)
        import handlers.bootstrap as bootstrap

        bootstrap.context.cache_clear()
        yield {"s3": s3, "topic": topic}
        bootstrap.context.cache_clear()


def event_for(key, size=1000, bucket=BUCKET):
    return {"source": "aws.s3", "detail-type": "Object Created",
            "detail": {"bucket": {"name": bucket}, "object": {"key": key, "size": size}}}


def test_processor_end_to_end(aws, fixture_lines):
    processor = importlib.import_module("handlers.processor")
    key = "raw/origin=simulation/sensor=local/dt=2026-10-30/batch-1.json.gz"
    aws["s3"].put_object(Bucket=BUCKET, Key=key, Body=gzip.compress("\n".join(fixture_lines).encode()))

    result = processor.handler(event_for(key), None)
    assert result["status"] == "ok"
    assert result["events"] == len(fixture_lines)
    assert result["alerts_new"] > 0
    assert result["notifications"] >= 3

    keys = [o["Key"] for o in aws["s3"].list_objects_v2(Bucket=BUCKET)["Contents"]]
    assert any(k.startswith("processed/events/origin=simulation/") for k in keys)
    alert_keys = [k for k in keys if k.startswith("processed/alerts/origin=simulation/")]
    assert len(alert_keys) == result["alerts_new"]
    head = aws["s3"].head_object(Bucket=BUCKET, Key=alert_keys[0])
    assert head["ServerSideEncryption"] == "AES256"
    body = aws["s3"].get_object(Bucket=BUCKET, Key=alert_keys[0])["Body"].read()
    assert json.loads(body)["data_origin"] == "simulation"

    # Same object delivered twice (EventBridge is at-least-once): no new alerts, no new notifications.
    again = processor.handler(event_for(key), None)
    assert again["alerts_new"] == 0 and again["notifications"] == 0


def test_processor_ignores_foreign_objects(aws):
    processor = importlib.import_module("handlers.processor")
    assert processor.handler(event_for("processed/x.json"), None)["status"] == "ignored"
    assert processor.handler(event_for("raw/origin=live/x", bucket="other-bucket"), None)["status"] == "ignored"
    assert processor.handler(event_for("raw/origin=live/x.json", size=10**9), None)["status"] == "rejected"


def test_processor_requires_hmac_key(aws, monkeypatch):
    import handlers.bootstrap as bootstrap

    bootstrap.context.cache_clear()
    monkeypatch.setenv("HMAC_KEY_PARAM", "/ht/does-not-exist")
    processor = importlib.import_module("handlers.processor")
    with pytest.raises(Exception):
        processor.handler(event_for("raw/origin=live/sensor=a/dt=2026-10-30/x.json"), None)


def test_correlator_builds_profiles(aws, fixture_lines):
    processor = importlib.import_module("handlers.processor")
    correlator = importlib.import_module("handlers.correlator")
    key = "raw/origin=simulation/sensor=local/dt=2026-10-30/batch-2.json"
    aws["s3"].put_object(Bucket=BUCKET, Key=key, Body="\n".join(fixture_lines).encode())
    processor.handler(event_for(key), None)

    import os

    os.environ["CORRELATION_HOURS"] = str(24 * 3650)
    result = correlator.handler({}, None)
    assert result["status"] == "ok" and result["profiles"] >= 1
    profiles = json.loads(aws["s3"].get_object(
        Bucket=BUCKET, Key="processed/profiles/origin=simulation/latest.json")["Body"].read())
    assert profiles[0]["src_ip"] == "127.0.0.1"


def test_dashboard_reads_s3_store(aws, fixture_lines, monkeypatch):
    processor = importlib.import_module("handlers.processor")
    key = "raw/origin=simulation/sensor=local/dt=2026-10-30/batch-3.json"
    aws["s3"].put_object(Bucket=BUCKET, Key=key, Body="\n".join(fixture_lines).encode())
    processor.handler(event_for(key), None)

    import data

    ds = data.load(f"s3://{BUCKET}")
    assert len(ds.events) == len(fixture_lines)
    assert set(ds.events["data_origin"]) == {"simulation"}
    assert not ds.alerts.empty and not ds.profiles.empty
