"""Repository-level secret and data-handling checks (complements gitleaks in CI)."""

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = {".git", ".venv", ".terraform", "node_modules", "data", "build", "runtime", "__pycache__", ".pytest_cache"}
TEXT_SUFFIXES = {".py", ".tf", ".tftpl", ".md", ".toml", ".yml", ".yaml", ".json", ".cfg", ".txt", ".sh", ".sql", ""}

PATTERNS = {
    "aws_access_key_id": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "aws_secret_assignment": re.compile(r"aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}"),
    "private_key": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
}


def repo_files():
    for path in ROOT.rglob("*"):
        if path.is_file() and not (set(path.relative_to(ROOT).parts) & SKIP_DIRS) and path.suffix in TEXT_SUFFIXES:
            if path.stat().st_size < 2_000_000:
                yield path


@pytest.mark.parametrize("name", sorted(PATTERNS))
def test_no_secrets_committed(name):
    hits = [str(p.relative_to(ROOT)) for p in repo_files()
            if PATTERNS[name].search(p.read_text(errors="ignore"))]
    assert not hits, f"{name} pattern found in {hits}"


def test_gitignore_excludes_sensitive_and_generated_data():
    ignore = (ROOT / ".gitignore").read_text()
    for entry in ["data/", "honeypot/runtime/", "build/", "*.tfstate", "*.tfvars.local", ".env", ".terraform/"]:
        assert entry in ignore, entry


def test_decoy_credentials_are_obviously_fake():
    src = (ROOT / "honeypot/configuration/build_fs.py").read_text()
    for value in re.findall(r"(?:PASSWORD|KEY)=([^\\\"]+)", src):
        assert value.startswith("decoy-"), value


def test_tracked_files_contain_no_raw_cowrie_logs():
    try:
        files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        pytest.skip("not a git checkout")
    tracked = files.splitlines()
    assert not [f for f in tracked if f.startswith(("data/", "honeypot/runtime/")) or f.endswith(".tfstate")]
    raw = [f for f in tracked if f.endswith(".json") and "cowrie" in f and not f.startswith("tests/fixtures/")]
    assert not raw, raw
