"""Object storage abstraction: the same key layout on a local directory and on S3.

Key layout (see docs/architecture and athena/):

    raw/origin=<o>/sensor=<s>/dt=YYYY-MM-DD/<batch>.json.gz   raw Cowrie JSON - contains passwords, restricted
    processed/events/origin=<o>/dt=YYYY-MM-DD/<batch>.json.gz normalised events (NDJSON, no clear-text passwords)
    processed/alerts/origin=<o>/dt=YYYY-MM-DD/<alert_id>.json one alert per object (single-line JSON)
    processed/enrichment/<ip>.json                            enrichment cache
    processed/profiles/origin=<o>/latest.json                 attacker profile snapshot
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Protocol


class Store(Protocol):
    def put_bytes(self, key: str, data: bytes, content_type: str = "application/json") -> None: ...
    def get_bytes(self, key: str) -> bytes | None: ...
    def list_keys(self, prefix: str) -> Iterator[str]: ...
    def exists(self, key: str) -> bool: ...


class LocalStore:
    def __init__(self, root: str | os.PathLike) -> None:
        self.root = Path(root)

    def _path(self, key: str) -> Path:
        path = (self.root / key).resolve()
        if self.root.resolve() not in path.parents and path != self.root.resolve():
            raise ValueError(f"key escapes store root: {key}")
        return path

    def put_bytes(self, key: str, data: bytes, content_type: str = "application/json") -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(path)

    def get_bytes(self, key: str) -> bytes | None:
        path = self._path(key)
        return path.read_bytes() if path.exists() else None

    def list_keys(self, prefix: str) -> Iterator[str]:
        base = self.root / prefix
        search_root = base if base.is_dir() else base.parent
        if not search_root.exists():
            return
        for path in sorted(search_root.rglob("*")):
            if path.is_file() and not path.name.endswith(".tmp"):
                key = path.relative_to(self.root).as_posix()
                if key.startswith(prefix):
                    yield key

    def exists(self, key: str) -> bool:
        return self._path(key).exists()


class S3Store:
    def __init__(self, bucket: str, client=None) -> None:
        if client is None:
            import boto3

            client = boto3.client("s3")
        self.bucket = bucket
        self.client = client

    def put_bytes(self, key: str, data: bytes, content_type: str = "application/json") -> None:
        extra = {"ContentEncoding": "gzip"} if key.endswith(".gz") else {}
        self.client.put_object(Bucket=self.bucket, Key=key, Body=data, ContentType=content_type,
                               ServerSideEncryption="AES256", **extra)

    def get_bytes(self, key: str) -> bytes | None:
        try:
            return self.client.get_object(Bucket=self.bucket, Key=key)["Body"].read()
        except self.client.exceptions.NoSuchKey:
            return None

    def list_keys(self, prefix: str) -> Iterator[str]:
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                yield obj["Key"]

    def exists(self, key: str) -> bool:
        from botocore.exceptions import ClientError

        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("404", "NoSuchKey", "NotFound"):
                return False
            raise


def store_from_uri(uri: str) -> Store:
    """``s3://bucket`` or a local directory path."""
    if uri.startswith("s3://"):
        return S3Store(uri[5:].split("/", 1)[0])
    return LocalStore(uri)
