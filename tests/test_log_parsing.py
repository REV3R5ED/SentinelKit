"""Tests for multi-format log parsing and brute-force detection."""

from sentinelkit.core import (
    detect_log_format,
    parse_log_records,
    summarize_auth_log,
)


def _sshd_line(prefix: str, message: str) -> str:
    return f"{prefix} {message}"


_SYSLOG_PREFIXES = [
    "Sep 22 10:14:01 lab sshd[1001]:",
    "Sep 22 10:14:08 lab sshd[1002]:",
    "Sep 22 10:15:10 lab sshd[1003]:",
]
SYSLOG_LOG = "\n".join(
    [
        _sshd_line(
            _SYSLOG_PREFIXES[0],
            "Failed password for invalid user guest from 192.0.2.44 port 51111 ssh2",
        ),
        _sshd_line(
            _SYSLOG_PREFIXES[1],
            "Failed password for analyst from 192.0.2.44 port 51112 ssh2",
        ),
        _sshd_line(
            _SYSLOG_PREFIXES[2],
            "Accepted publickey for analyst from 198.51.100.23 port 51113 ssh2",
        ),
    ]
)

_JOURNAL_PREFIXES = [
    "2026-10-02T14:31:05+00:00 web sshd[2041]:",
    "2026-10-02T14:31:40+00:00 web sshd[2042]:",
    "2026-10-02T14:32:10+00:00 web sshd[2043]:",
]
JOURNAL_LOG = "\n".join(
    [
        _sshd_line(
            _JOURNAL_PREFIXES[0],
            "Failed password for root from 203.0.113.9 port 40211 ssh2",
        ),
        _sshd_line(
            _JOURNAL_PREFIXES[1],
            "Failed password for root from 203.0.113.9 port 40212 ssh2",
        ),
        _sshd_line(
            _JOURNAL_PREFIXES[2],
            "Accepted password for deploy from 198.51.100.7 port 51220 ssh2",
        ),
    ]
)

CSV_LOG = "\n".join(
    [
        "timestamp,host,process,message",
        "2026-10-02T14:31:05+00:00,web,sshd,"
        "Failed password for root from 203.0.113.9 port 40211 ssh2",
        "2026-10-02T14:31:40+00:00,web,sshd,"
        "Failed password for root from 203.0.113.9 port 40212 ssh2",
        "2026-10-02T14:32:10+00:00,web,sshd,"
        "Accepted password for deploy from 198.51.100.7 port 51220 ssh2",
    ]
)


def test_detect_log_format_identifies_each_supported_format():
    assert detect_log_format(SYSLOG_LOG) == "syslog"
    assert detect_log_format(JOURNAL_LOG) == "journal"
    assert detect_log_format(CSV_LOG) == "csv"
    bare = "sshd: Failed password for root from 1.2.3.4 port 22 ssh2"
    assert detect_log_format(bare) == "syslog"
    assert detect_log_format("   \n") == "raw"


def test_parse_syslog_records_carry_timestamps_hosts_and_processes():
    records, detected = parse_log_records(SYSLOG_LOG)

    assert detected == "syslog"
    assert len(records) == 3
    assert records[0].timestamp is not None
    assert records[0].timestamp.hour == 10
    assert records[0].host == "lab"
    assert records[0].process == "sshd"
    assert "Failed password" in records[0].message


def test_parse_journal_records_use_iso_timestamps():
    records, detected = parse_log_records(JOURNAL_LOG)

    assert detected == "journal"
    assert records[0].timestamp is not None
    # Normalized to naive UTC for consistent window arithmetic.
    assert records[0].timestamp.isoformat() == "2026-10-02T14:31:05"
    assert records[0].host == "web"


def test_parse_csv_records_map_flexible_columns():
    records, detected = parse_log_records(CSV_LOG)

    assert detected == "csv"
    assert len(records) == 3
    assert records[0].host == "web"
    assert records[0].process == "sshd"
    assert records[0].timestamp is not None
    assert "Failed password" in records[0].message


def test_parse_csv_records_tolerate_alternate_headers():
    text = (
        "time,hostname,service,msg\n"
        "2026-10-02T14:31:05+00:00,web,sshd,"
        "Failed password for root from 203.0.113.9 port 22 ssh2\n"
    )
    records, detected = parse_log_records(text)

    assert detected == "csv"
    assert len(records) == 1
    assert records[0].host == "web"
    assert records[0].timestamp is not None


def test_parse_bare_sshd_lines_have_no_timestamp():
    records, _ = parse_log_records(
        "sshd: Failed password for root from 203.0.113.9 port 22 ssh2"
    )

    assert len(records) == 1
    assert records[0].timestamp is None
    assert records[0].process == "sshd"


def test_summarize_auth_log_works_for_each_format():
    for log in (SYSLOG_LOG, JOURNAL_LOG, CSV_LOG):
        summary = summarize_auth_log(log, failed_threshold=99)

        assert summary["failed_attempts"] == 2
        assert summary["successful_logins"] == 1
        assert summary["top_failed_sources"][0][0] in {"192.0.2.44", "203.0.113.9"}
        assert summary["brute_force_suspects"] == []


def test_brute_force_detected_inside_sliding_window():
    lines = [
        f"2026-10-02T14:{minute:02d}:00+00:00 web sshd[1]: "
        f"Failed password for root from 203.0.113.9 port 22 ssh2"
        for minute in range(6)
    ]
    summary = summarize_auth_log(
        "\n".join(lines), failed_threshold=5, window_minutes=10
    )

    suspects = summary["brute_force_suspects"]
    assert len(suspects) == 1
    assert suspects[0]["source"] == "203.0.113.9"
    assert suspects[0]["max_failures_in_window"] == 6
    assert "within 10 minutes" in suspects[0]["reason"]
    assert suspects[0]["first_seen"] == "2026-10-02T14:00:00"


def test_brute_force_ignores_failures_spread_beyond_window():
    lines = [
        f"2026-10-02T{hour:02d}:00:00+00:00 web sshd[1]: "
        f"Failed password for root from 203.0.113.9 port 22 ssh2"
        for hour in range(6)
    ]
    summary = summarize_auth_log(
        "\n".join(lines), failed_threshold=5, window_minutes=10
    )

    assert summary["brute_force_suspects"] == []


def test_brute_force_without_timestamps_uses_total_count():
    text = "\n".join(
        "sshd: Failed password for root from 203.0.113.9 port 22 ssh2" for _ in range(5)
    )
    summary = summarize_auth_log(text, failed_threshold=5)

    suspects = summary["brute_force_suspects"]
    assert len(suspects) == 1
    assert suspects[0]["failures"] == 5
    assert "no timestamps" in suspects[0]["reason"]


def test_brute_force_respects_custom_threshold_and_window():
    lines = [
        f"2026-10-02T14:{minute:02d}:00+00:00 web sshd[1]: "
        f"Failed password for root from 203.0.113.9 port 22 ssh2"
        for minute in range(4)
    ]
    text = "\n".join(lines)

    assert summarize_auth_log(text, failed_threshold=4)["brute_force_suspects"]
    assert not summarize_auth_log(text, failed_threshold=5)["brute_force_suspects"]
    # 4 failures span 3 minutes, so a 2-minute window only ever sees 3.
    assert not summarize_auth_log(text, failed_threshold=4, window_minutes=2)[
        "brute_force_suspects"
    ]


def test_brute_force_flags_each_offending_source():
    text = "\n".join(
        f"2026-10-02T14:0{minute}:00+00:00 web sshd[1]: "
        f"Failed password for root from {source} port 22 ssh2"
        for source in ("203.0.113.9", "198.51.100.99")
        for minute in range(5)
    )
    summary = summarize_auth_log(text, failed_threshold=5)

    assert {s["source"] for s in summary["brute_force_suspects"]} == {
        "203.0.113.9",
        "198.51.100.99",
    }


def test_summary_keeps_legacy_keys_and_labels_format():
    summary = summarize_auth_log(SYSLOG_LOG)

    assert summary["log_format"] == "syslog"
    assert summary["failed_attempts"] == 2
    assert summary["successful_logins"] == 1
    assert summary["invalid_user_attempts"] == 1
    assert summary["top_invalid_usernames"][0] == ("guest", 1)


def test_parse_csv_records_skips_rows_without_message():
    text = "\n".join(
        [
            "timestamp,host,process,message",
            "2026-10-02T14:31:05+00:00,web,sshd,",
            "2026-10-02T14:31:40+00:00,web,sshd,"
            "Failed password for root from 203.0.113.9 port 22 ssh2",
        ]
    )
    records, _ = parse_log_records(text)

    assert len(records) == 1
