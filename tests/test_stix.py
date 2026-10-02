"""Tests for dependency-free STIX 2.1 bundle export."""

from sentinelkit.core import extract_iocs
from sentinelkit.stix import export_stix


def _indicators_by_type(bundle):
    return {obj["id"]: obj for obj in bundle["objects"] if obj["type"] == "indicator"}


def test_export_stix_produces_valid_bundle_shape():
    bundle = export_stix(extract_iocs("see https://example.com/x and 203.0.113.7"))

    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    objects = bundle["objects"]
    assert objects[0]["type"] == "identity"
    assert objects[0]["identity_class"] == "tool"
    assert objects[0]["name"] == "SentinelKit"
    assert objects[0]["spec_version"] == "2.1"


def test_export_stix_maps_each_ioc_type_to_pattern():
    indicators = {
        "ipv4": ["203.0.113.7"],
        "ipv6": ["2001:db8::1"],
        "domain": ["example.com"],
        "url": ["https://example.com/x"],
        "email": ["soc@example.com"],
        "hash": ["a" * 64],
    }
    bundle = export_stix(indicators)

    patterns = {
        obj["pattern"] for obj in bundle["objects"] if obj["type"] == "indicator"
    }
    assert patterns == {
        "[ipv4-addr:value = '203.0.113.7']",
        "[ipv6-addr:value = '2001:db8::1']",
        "[domain-name:value = 'example.com']",
        "[url:value = 'https://example.com/x']",
        "[email-addr:value = 'soc@example.com']",
        "[file:hashes.'SHA-256' = '" + "a" * 64 + "']",
    }


def test_export_stix_uses_correct_hash_pattern_names():
    bundle = export_stix(
        {
            "ipv4": [],
            "ipv6": [],
            "domain": [],
            "url": [],
            "email": [],
            "hash": ["b" * 96, "c" * 128, "d" * 32],
        }
    )

    patterns = sorted(
        obj["pattern"] for obj in bundle["objects"] if obj["type"] == "indicator"
    )
    assert patterns == [
        "[file:hashes.'MD5' = '" + "d" * 32 + "']",
        "[file:hashes.'SHA-384' = '" + "b" * 96 + "']",
        "[file:hashes.'SHA-512' = '" + "c" * 128 + "']",
    ]


def test_export_stix_is_deterministic_for_same_input():
    indicators = extract_iocs("see https://example.com/x and " + "a" * 64)

    first = export_stix(indicators)
    second = export_stix(indicators)

    assert first["id"] == second["id"]
    assert [o["id"] for o in first["objects"]] == [o["id"] for o in second["objects"]]


def test_export_stix_indicators_carry_required_fields():
    bundle = export_stix(
        {
            "ipv4": ["203.0.113.7"],
            "ipv6": [],
            "domain": [],
            "url": [],
            "email": [],
            "hash": [],
        }
    )

    indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
    assert indicator["id"].startswith("indicator--")
    assert indicator["pattern_type"] == "stix"
    assert indicator["indicator_types"] == ["anomalous-activity"]
    assert indicator["valid_from"]
    assert indicator["created"] == indicator["modified"]


def test_export_stix_handles_empty_indicator_sets():
    bundle = export_stix(
        {"ipv4": [], "ipv6": [], "domain": [], "url": [], "email": [], "hash": []}
    )

    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) == 1  # identity only


def test_export_stix_skips_unidentified_hash_lengths():
    bundle = export_stix(
        {
            "ipv4": [],
            "ipv6": [],
            "domain": [],
            "url": [],
            "email": [],
            "hash": ["f" * 48],  # valid hex, not a known digest length
        }
    )

    assert [o for o in bundle["objects"] if o["type"] == "indicator"] == []
