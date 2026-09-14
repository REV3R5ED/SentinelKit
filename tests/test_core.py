from sentinelkit.core import extract_iocs, identify_hash, inspect_ip, summarize_auth_log


def test_identify_hash():
    assert identify_hash("a" * 64) == "SHA-256"
    assert identify_hash("not-a-hash") is None


def test_inspect_ip():
    result = inspect_ip("127.0.0.1")
    assert result["version"] == 4
    assert result["loopback"] is True


def test_extract_iocs_filters_invalid_ipv4():
    text = "Contact admin@example.com from 192.168.1.5; ignore 999.999.999.999."
    result = extract_iocs(text)
    assert "admin@example.com" in result["email"]
    assert "192.168.1.5" in result["ipv4"]
    assert "999.999.999.999" not in result["ipv4"]


def test_auth_summary():
    text = """
    sshd: Failed password for root from 203.0.113.7 port 22 ssh2
    sshd: Failed password for root from 203.0.113.7 port 22 ssh2
    sshd: Accepted publickey for alice from 10.0.0.5 port 22 ssh2
    """
    result = summarize_auth_log(text)
    assert result["failed_attempts"] == 2
    assert result["successful_logins"] == 1
    assert result["top_failed_sources"][0] == ("203.0.113.7", 2)
