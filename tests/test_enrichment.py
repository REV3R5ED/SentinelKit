"""Tests for offline, rule-based IOC enrichment."""

import sys

import pytest

import sentinelkit.core as core_module
from sentinelkit.core import (
    EnrichmentConfig,
    SentinelKitError,
    enrich_iocs,
    extract_iocs,
    load_enrichment_config,
    summarize_iocs,
)


def test_enrichment_flags_rfc1918_addresses():
    findings = enrich_iocs(
        extract_iocs("internal hosts 10.1.2.3 172.16.0.9 192.168.1.5")
    )

    assert len(findings["private_addresses"]) == 3
    assert any(
        "10.1.2.3" in item and "10.0.0.0/8" in item
        for item in findings["private_addresses"]
    )
    assert findings["cgnat_addresses"] == []


def test_enrichment_flags_cgnat_addresses():
    findings = enrich_iocs(extract_iocs("carrier NAT egress 100.64.0.9"))

    assert findings["private_addresses"] == []
    assert findings["cgnat_addresses"] == ["100.64.0.9 (CGNAT 100.64.0.0/10)"]


def test_enrichment_ignores_public_addresses():
    findings = enrich_iocs(extract_iocs("external host 203.0.113.7"))

    assert findings["private_addresses"] == []
    assert findings["cgnat_addresses"] == []


def test_enrichment_flags_suspicious_tlds():
    findings = enrich_iocs(extract_iocs("visit https://invoice-update.zip/claim"))

    assert findings["suspicious_hosts"] == ["invoice-update.zip (suspicious TLD: .zip)"]


def test_enrichment_flags_punycode_and_long_labels():
    findings = enrich_iocs(
        extract_iocs(
            "see https://xn--pple-43d.example/ and https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example/x"
        )
    )

    assert any("punycode" in item for item in findings["suspicious_hosts"])
    assert any("long DNS label" in item for item in findings["suspicious_hosts"])


def test_enrichment_flags_ip_literal_url_host():
    findings = enrich_iocs(extract_iocs("visit https://192.0.2.10/login"))

    assert "192.0.2.10 (URL uses IP literal host)" in findings["suspicious_hosts"]


def test_enrichment_flags_blocklisted_hash_and_domain(tmp_path):
    config_file = tmp_path / "blocklists.toml"
    config_file.write_text(
        f'[blocklists]\nhashes = ["{"a" * 64}"]\ndomains = ["evil.example"]\n',
        encoding="utf-8",
    )
    config = load_enrichment_config(config_file)

    findings = enrich_iocs(
        extract_iocs("payload " + "a" * 64 + " from evil.example and clean.example"),
        config,
    )

    assert any("blocklisted hash" in item for item in findings["blocklisted"])
    assert any("evil.example" in item for item in findings["blocklisted"])
    assert not any("clean.example" in item for item in findings["blocklisted"])


def test_load_enrichment_config_supports_simple_yaml(tmp_path):
    config_file = tmp_path / "blocklists.yaml"
    config_file.write_text(
        "# analyst blocklists\nhashes:\n"
        "  - " + "b" * 64 + "\n"
        "domains:\n"
        "  - bad.example\n",
        encoding="utf-8",
    )
    config = load_enrichment_config(config_file)

    assert "b" * 64 in config.hash_blocklist
    assert "bad.example" in config.domain_blocklist


def test_load_enrichment_config_rejects_unsupported_suffix(tmp_path):
    config_file = tmp_path / "blocklists.txt"
    config_file.write_text("hashes: []", encoding="utf-8")

    with pytest.raises(SentinelKitError, match="unsupported"):
        load_enrichment_config(config_file)


def test_load_enrichment_config_rejects_broken_toml(tmp_path):
    config_file = tmp_path / "blocklists.toml"
    config_file.write_text("[blocklists\nhashes = [", encoding="utf-8")

    with pytest.raises(SentinelKitError, match="cannot parse"):
        load_enrichment_config(config_file)


def test_load_enrichment_config_rejects_missing_file(tmp_path):
    with pytest.raises(SentinelKitError, match="cannot read"):
        load_enrichment_config(tmp_path / "nope.toml")


def test_summarize_iocs_folds_enrichment_into_reasons():
    summary = summarize_iocs("internal pivot 192.168.1.5 phoning https://update.zip/x")

    assert "private address: 192.168.1.5 (RFC1918 192.168.0.0/16)" in summary["reasons"]
    assert "suspicious host: update.zip (suspicious TLD: .zip)" in summary["reasons"]
    # URL still drives the high priority; reasons stay explainable.
    assert summary["triage_priority"] == "high"


def test_summarize_iocs_escalates_blocklist_match_to_high():
    config = EnrichmentConfig(domain_blocklist={"evil.example"})
    summary = summarize_iocs("saw beacon to evil.example", config)

    assert summary["triage_priority"] == "high"
    assert "domain evil.example (blocklisted domain)" in summary["reasons"]


def test_summarize_iocs_keeps_default_behavior_without_config():
    summary = summarize_iocs("Observed source 203.0.113.7")

    assert summary["triage_priority"] == "medium"
    assert summary["reasons"] == ["network address present"]
    assert summary["enrichment"]["blocklisted"] == []


def test_enrichment_config_normalizes_case_and_whitespace():
    config = EnrichmentConfig(
        hash_blocklist={"  " + "A" * 64 + "  "},
        domain_blocklist={" Evil.Example "},
    )

    assert "a" * 64 in config.hash_blocklist
    assert "evil.example" in config.domain_blocklist


@pytest.mark.skipif(
    sys.version_info < (3, 11), reason="stdlib tomllib needs Python 3.11+"
)
def test_load_enrichment_config_supports_toml_section(tmp_path):
    config_file = tmp_path / "blocklists.toml"
    config_file.write_text(
        '[blocklists]\nhashes = []\ndomains = ["evil.example"]\n',
        encoding="utf-8",
    )

    config = load_enrichment_config(config_file)

    assert "evil.example" in config.domain_blocklist


def test_load_enrichment_config_toml_without_stdlib_fails_cleanly(
    tmp_path, monkeypatch
):
    """Python 3.10 has no stdlib tomllib; the failure must stay user-facing."""
    config_file = tmp_path / "blocklists.toml"
    config_file.write_text("[blocklists]\ndomains = []\n", encoding="utf-8")
    monkeypatch.setattr(core_module, "tomllib", None)

    with pytest.raises(SentinelKitError, match=r"Python 3\.11"):
        load_enrichment_config(config_file)


def test_enrichment_skips_ipv6_for_rfc1918_cgnat_rules():
    findings = enrich_iocs(extract_iocs("observed 2001:db8::1 and fe80::1"))

    assert findings["private_addresses"] == []
    assert findings["cgnat_addresses"] == []


def test_load_enrichment_config_yaml_inline_and_scalar_values(tmp_path):
    config_file = tmp_path / "blocklists.yaml"
    config_file.write_text(
        "hashes: [aaa, bbb]\nnote: analyst reviewed\n", encoding="utf-8"
    )

    config = load_enrichment_config(config_file)

    assert config.hash_blocklist == {"aaa", "bbb"}


@pytest.mark.skipif(
    sys.version_info < (3, 11), reason="stdlib tomllib needs Python 3.11+"
)
def test_load_enrichment_config_toml_scalar_string_value(tmp_path):
    config_file = tmp_path / "blocklists.toml"
    config_file.write_text(
        '[blocklists]\nhashes = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n',
        encoding="utf-8",
    )

    config = load_enrichment_config(config_file)

    assert config.hash_blocklist == {"a" * 32}
