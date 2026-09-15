from sentinelkit.core import extract_iocs

from pathlib import Path

SCENARIO = Path(__file__).parents[1] / "examples" / "soc_phishing_case.txt"


def test_soc_phishing_case_end_to_end():
    """Keep the documented SOC scenario working as SentinelKit evolves."""
    result = extract_iocs(SCENARIO.read_text(encoding="utf-8"))

    assert "security@accounts.example" in result["email"]
    assert "accounts.example" in result["domain"]
    assert "https://accounts.example/verify" in result["url"]
    assert "198.51.100.42" in result["ipv4"]
    assert "2001:db8::42" in result["ipv6"]
    assert result["domain"].count("accounts.example") == 1
