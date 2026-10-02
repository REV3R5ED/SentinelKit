"""Dependency-free STIX 2.1 bundle export for extracted IOCs.

The bundle is hand-built per the STIX 2.1 specification (bundle, identity,
and indicator objects with STIX Cyber-observable pattern expressions) so
findings can be imported into threat-intel platforms without adding
dependencies or network calls.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from .core import identify_hash

STIX_SPEC_VERSION = "2.1"

# Stable identity so repeated exports from this tool share one producer.
_IDENTITY_ID = f"identity--{uuid.uuid5(uuid.NAMESPACE_URL, 'sentinelkit:identity')}"
_IDENTITY_NAME = "SentinelKit"
_IDENTITY_DESCRIPTION = (
    "SentinelKit: offline, dependency-free defensive security toolkit "
    "for SOC/Blue Team analysis."
)

_HASH_PATTERN_NAMES = {
    "MD5": "MD5",
    "SHA-1": "SHA-1",
    "SHA-256": "SHA-256",
    "SHA-384": "SHA-384",
    "SHA-512": "SHA-512",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _stix_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _pattern_for(ioc_type: str, value: str) -> str | None:
    """Map an extracted IOC to a STIX 2.1 pattern expression."""
    safe = _stix_escape(value)
    if ioc_type == "ipv4":
        return f"[ipv4-addr:value = '{safe}']"
    if ioc_type == "ipv6":
        return f"[ipv6-addr:value = '{safe}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{safe}']"
    if ioc_type == "url":
        return f"[url:value = '{safe}']"
    if ioc_type == "email":
        return f"[email-addr:value = '{safe}']"
    if ioc_type == "hash":
        digest = identify_hash(value)
        hash_name = _HASH_PATTERN_NAMES.get(digest or "")
        if hash_name is None:
            return None
        return f"[file:hashes.'{hash_name}' = '{safe}']"
    return None


def export_stix(indicators: dict[str, list[str]]) -> dict[str, object]:
    """Build a STIX 2.1 bundle of indicator objects from extracted IOCs.

    IDs are deterministic (UUIDv5 over the IOC type and value) so identical
    input produces an identical bundle across runs.
    """
    timestamp = _utc_now()
    identity = {
        "type": "identity",
        "spec_version": STIX_SPEC_VERSION,
        "id": _IDENTITY_ID,
        "created": timestamp,
        "modified": timestamp,
        "name": _IDENTITY_NAME,
        "description": _IDENTITY_DESCRIPTION,
        "identity_class": "tool",
    }

    indicator_objects: list[dict[str, object]] = []
    for ioc_type in ("ipv4", "ipv6", "domain", "url", "email", "hash"):
        for value in indicators.get(ioc_type, []):
            pattern = _pattern_for(ioc_type, value)
            if pattern is None:
                continue
            indicator_id = "indicator--" + str(
                uuid.uuid5(uuid.NAMESPACE_URL, f"sentinelkit:{ioc_type}:{value}")
            )
            indicator_objects.append(
                {
                    "type": "indicator",
                    "spec_version": STIX_SPEC_VERSION,
                    "id": indicator_id,
                    "created": timestamp,
                    "modified": timestamp,
                    "name": f"SentinelKit IOC: {ioc_type} {value}",
                    "description": (
                        "Indicator extracted offline by SentinelKit from "
                        "analyst-supplied text; heuristic, not a verdict."
                    ),
                    "indicator_types": ["anomalous-activity"],
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": timestamp,
                }
            )

    indicator_objects.sort(key=lambda obj: str(obj["id"]))
    bundle_id = uuid.uuid5(
        uuid.NAMESPACE_URL,
        "sentinelkit:bundle:" + "|".join(str(obj["id"]) for obj in indicator_objects),
    )
    return {
        "type": "bundle",
        "id": f"bundle--{bundle_id}",
        "objects": [identity, *indicator_objects],
    }


__all__ = ["export_stix"]
