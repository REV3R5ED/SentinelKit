from sentinelkit.core import summarize_iocs


def test_summarize_iocs_counts_and_prioritizes_indicators():
    text = (
        "User reported hxxps://login[.]example/verify from 198.51.100.42 "
        "and contacted soc@alerts[.]example. Preserve artifact hash "
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef."
    )

    summary = summarize_iocs(text)

    assert summary["total_indicators"] == 6
    assert summary["counts"] == {
        "ipv4": 1,
        "ipv6": 0,
        "url": 1,
        "email": 1,
        "hash": 1,
        "domain": 2,
    }
    assert summary["triage_priority"] == "high"
    assert summary["reasons"] == [
        "URL present",
        "cryptographic hash present",
        "network address present",
    ]


def test_summarize_iocs_uses_explainable_priority_rules():
    assert summarize_iocs("admin@example.com")["triage_priority"] == "low"
    assert summarize_iocs("Observed 203.0.113.7")["triage_priority"] == "medium"
    assert (
        summarize_iocs("Investigate https://example.com/path")["triage_priority"]
        == "high"
    )
