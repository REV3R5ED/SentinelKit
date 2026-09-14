"""Core defensive analysis helpers used by SentinelKit."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import Counter
from pathlib import Path

HASH_LENGTHS = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 96: "SHA-384", 128: "SHA-512"}

IOC_PATTERNS = {
    "ipv4": re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"),
    "url": re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE),
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    "hash": re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"),
}


def identify_hash(value: str) -> str | None:
    """Return a likely digest family based on hexadecimal form and length."""
    value = value.strip()
    if not re.fullmatch(r"[a-fA-F0-9]+", value):
        return None
    return HASH_LENGTHS.get(len(value))


def sha256_file(path: str | Path) -> str:
    """Calculate a SHA-256 digest without loading the whole file into memory."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_ip(value: str) -> dict[str, object]:
    """Validate an IP address and return defensive classification metadata."""
    address = ipaddress.ip_address(value.strip())
    return {
        "address": str(address),
        "version": address.version,
        "private": address.is_private,
        "global": address.is_global,
        "loopback": address.is_loopback,
        "multicast": address.is_multicast,
        "reserved": address.is_reserved,
    }


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Extract common indicators from arbitrary text and remove duplicates."""
    results: dict[str, list[str]] = {}
    for name, pattern in IOC_PATTERNS.items():
        values = pattern.findall(text)
        if name == "ipv4":
            values = [v for v in values if _valid_ipv4(v)]
        results[name] = sorted(set(values))
    return results


def summarize_auth_log(text: str) -> dict[str, object]:
    """Summarize common SSH authentication events from text logs."""
    failed = re.findall(r"Failed password.*?from\s+([^\s]+)", text, flags=re.IGNORECASE)
    accepted = re.findall(r"Accepted (?:password|publickey).*?from\s+([^\s]+)", text, flags=re.IGNORECASE)
    failure_counts = Counter(failed)
    return {
        "failed_attempts": len(failed),
        "successful_logins": len(accepted),
        "top_failed_sources": failure_counts.most_common(10),
        "successful_sources": sorted(set(accepted)),
    }


def _valid_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False
