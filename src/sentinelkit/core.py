"""Core defensive analysis helpers used by SentinelKit."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

HASH_LENGTHS = {
    32: "MD5",
    40: "SHA-1",
    64: "SHA-256",
    96: "SHA-384",
    128: "SHA-512",
}

IOC_PATTERNS = {
    "ipv4": re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"),
    "url": re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE),
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    "hash": re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"),
}

DOMAIN_PATTERN = re.compile(
    r"\b(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}\b",
    re.IGNORECASE,
)
IPV6_CANDIDATE_PATTERN = re.compile(
    r"(?<![\w:.])\[?[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]+\]?(?![\w:.])"
)
DEFANGED_DOT_PATTERN = re.compile(r"\[(?:\.|dot)\]|\((?:\.|dot)\)", re.IGNORECASE)
DEFANGED_SCHEME_PATTERN = re.compile(r"\bhxxps?://", re.IGNORECASE)


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
    """Extract and normalize common indicators from arbitrary text."""
    normalized_text = _refang_ioc_text(text)
    results: dict[str, list[str]] = {}
    for name, pattern in IOC_PATTERNS.items():
        values = pattern.findall(normalized_text)
        if name == "ipv4":
            values = [v for v in values if _valid_ipv4(v)]
        results[name] = sorted(set(values))

    results["ipv6"] = _extract_ipv6(normalized_text)

    domains = set(DOMAIN_PATTERN.findall(normalized_text))
    for url in results["url"]:
        hostname = urlparse(url).hostname
        if hostname and not _valid_ip(hostname):
            domains.add(hostname)
    for email in results["email"]:
        domains.add(email.rsplit("@", 1)[-1])

    results["domain"] = sorted(d.lower() for d in domains if not _valid_ip(d))
    return results


def summarize_iocs(text: str) -> dict[str, object]:
    """Return deterministic IOC counts and an explainable triage priority.

    Priority is intentionally heuristic rather than a threat verdict: URLs or hashes
    are high priority, network addresses are medium priority, and other extracted
    indicators are low priority. SentinelKit performs no network enrichment here.
    """
    indicators = extract_iocs(text)
    ordered_types = ("ipv4", "ipv6", "url", "email", "hash", "domain")
    counts = {name: len(indicators[name]) for name in ordered_types}
    reasons: list[str] = []

    if counts["url"]:
        reasons.append("URL present")
    if counts["hash"]:
        reasons.append("cryptographic hash present")
    if counts["ipv4"] or counts["ipv6"]:
        reasons.append("network address present")

    if counts["url"] or counts["hash"]:
        priority = "high"
    elif counts["ipv4"] or counts["ipv6"]:
        priority = "medium"
    else:
        priority = "low"

    return {
        "total_indicators": sum(counts.values()),
        "counts": counts,
        "triage_priority": priority,
        "reasons": reasons,
    }


def summarize_auth_log(text: str) -> dict[str, object]:
    """Summarize common SSH authentication events from text logs."""
    failed = re.findall(r"Failed password.*?from\s+([^\s]+)", text, flags=re.IGNORECASE)
    accepted = re.findall(
        r"Accepted (?:password|publickey).*?from\s+([^\s]+)",
        text,
        flags=re.IGNORECASE,
    )
    invalid_users = re.findall(r"Invalid user\s+([^\s]+)", text, flags=re.IGNORECASE)
    failure_counts = Counter(failed)
    return {
        "failed_attempts": len(failed),
        "successful_logins": len(accepted),
        "top_failed_sources": failure_counts.most_common(10),
        "successful_sources": sorted(set(accepted)),
        "invalid_user_attempts": len(invalid_users),
        "top_invalid_usernames": Counter(invalid_users).most_common(10),
    }


def _extract_ipv6(text: str) -> list[str]:
    """Extract valid IPv6 literals and return canonical, deduplicated values."""
    values: set[str] = set()
    for match in IPV6_CANDIDATE_PATTERN.finditer(text):
        candidate = match.group(0).strip("[]").rstrip(".")
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.version == 6:
            values.add(str(address))
    return sorted(values)


def _refang_ioc_text(text: str) -> str:
    """Normalize common analyst-safe IOC defanging without resolving or contacting it."""
    normalized = DEFANGED_DOT_PATTERN.sub(".", text)

    def _restore_scheme(match: re.Match[str]) -> str:
        return "https://" if match.group(0).lower().startswith("hxxps") else "http://"

    return DEFANGED_SCHEME_PATTERN.sub(_restore_scheme, normalized)


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _valid_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False
