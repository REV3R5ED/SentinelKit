from sentinelkit.core import (
    extract_iocs,
    identify_hash,
    inspect_ip,
    summarize_auth_log,
)


def test_identify_hash():
    assert identify_hash("a" * 64) == "SHA-256"
    assert identify_hash("not-a-hash") is None


def test_inspect_ip():
    result = inspect_ip("127.0.0.1")
    assert result["version"] == 4
    assert result["loopback"] is True


def test_extract_iocs_filters_invalid_ipv4_and_extracts_domains():
    text = (
        "Contact admin@example.com from 192.168.1.5; ignore 999.999.999.999. "
        "Investigate https://sub.example.org/path and suspicious.test."
    )
    result = extract_iocs(text)
    assert "admin@example.com" in result["email"]
    assert "192.168.1.5" in result["ipv4"]
    assert "999.999.999.999" not in result["ipv4"]
    assert "example.com" in result["domain"]
    assert "sub.example.org" in result["domain"]
    assert "suspicious.test" in result["domain"]


def test_extract_iocs_normalizes_common_defanged_indicators():
    text = (
        "Investigate hxxps://portal[.]example/path and notify soc@alerts[.]example. "
        "Related host: malware(dot)test."
    )
    result = extract_iocs(text)

    assert "https://portal.example/path" in result["url"]
    assert "soc@alerts.example" in result["email"]
    assert "portal.example" in result["domain"]
    assert "alerts.example" in result["domain"]
    assert "malware.test" in result["domain"]


def test_extract_iocs_extracts_and_canonicalizes_ipv6():
    text = (
        "Observed 2001:0db8:0:0:0:0:0:1 and compressed 2001:db8::1 plus fe80::a:b:c:d."
    )
    result = extract_iocs(text)

    assert result["ipv6"] == ["2001:db8::1", "fe80::a:b:c:d"]


def test_extract_iocs_handles_bracketed_ipv6_url_without_domain_pollution():
    text = "Investigate https://[2001:db8::5]/login and ignore timestamp 12:34:56."
    result = extract_iocs(text)

    assert result["ipv6"] == ["2001:db8::5"]
    assert "2001:db8::5" not in result["domain"]
    assert "12:34:56" not in result["ipv6"]


def test_auth_summary():
    text = """
    sshd: Invalid user oracle from 203.0.113.7 port 22
    sshd: Failed password for root from 203.0.113.7 port 22 ssh2
    sshd: Failed password for root from 203.0.113.7 port 22 ssh2
    sshd: Accepted publickey for alice from 10.0.0.5 port 22 ssh2
    """
    result = summarize_auth_log(text)
    assert result["failed_attempts"] == 2
    assert result["successful_logins"] == 1
    assert result["top_failed_sources"][0] == ("203.0.113.7", 2)
    assert result["invalid_user_attempts"] == 1
    assert result["top_invalid_usernames"][0] == ("oracle", 1)
