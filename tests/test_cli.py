import hashlib
import json
import sys

import pytest

from sentinelkit.cli import main


def _run_cli(monkeypatch, capsys, *args: str) -> dict[str, object]:
    monkeypatch.setattr(sys, "argv", ["sentinelkit", *args])
    main()
    return json.loads(capsys.readouterr().out)


def test_hash_command_identifies_digest(monkeypatch, capsys):
    result = _run_cli(monkeypatch, capsys, "hash", "a" * 64)

    assert result == {"value": "a" * 64, "likely_type": "SHA-256"}


def test_hash_command_calculates_file_digest(monkeypatch, capsys, tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sentinelkit")

    result = _run_cli(monkeypatch, capsys, "hash", str(sample))

    assert result["file"] == str(sample)
    assert result["sha256"] == hashlib.sha256(b"sentinelkit").hexdigest()


def test_ip_command_emits_structured_json(monkeypatch, capsys):
    result = _run_cli(monkeypatch, capsys, "ip", "2001:db8::1")

    assert result["address"] == "2001:db8::1"
    assert result["version"] == 6
    assert isinstance(result["private"], bool)


def test_ioc_command_reads_file_and_deduplicates(monkeypatch, capsys, tmp_path):
    sample = tmp_path / "events.log"
    sample.write_text(
        "admin@example.com 192.168.1.5 https://sub.example.org/path "
        "admin@example.com 192.168.1.5",
        encoding="utf-8",
    )

    result = _run_cli(monkeypatch, capsys, "ioc", str(sample))

    assert result["email"] == ["admin@example.com"]
    assert result["ipv4"] == ["192.168.1.5"]
    assert "sub.example.org" in result["domain"]


def test_logs_command_summarizes_authentication_events(monkeypatch, capsys, tmp_path):
    sample = tmp_path / "auth.log"
    sample.write_text(
        "sshd: Failed password for root from 203.0.113.7 port 22 ssh2\n"
        "sshd: Accepted publickey for alice from 10.0.0.5 port 22 ssh2\n",
        encoding="utf-8",
    )

    result = _run_cli(monkeypatch, capsys, "logs", str(sample))

    assert result["failed_attempts"] == 1
    assert result["successful_logins"] == 1
    assert result["successful_sources"] == ["10.0.0.5"]


def test_text_format_is_human_readable(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        ["sentinelkit", "--format", "text", "hash", "a" * 64],
    )

    main()

    output = capsys.readouterr().out
    assert "Value: " + "a" * 64 in output
    assert "Likely Type: SHA-256" in output


def test_json_remains_default_for_automation(monkeypatch, capsys):
    result = _run_cli(monkeypatch, capsys, "hash", "a" * 64)
    assert result["likely_type"] == "SHA-256"


def test_invalid_ip_returns_argparse_error(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["sentinelkit", "ip", "not-an-ip"])

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 2
    assert "not-an-ip" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["ioc", "triage", "logs"])
def test_file_commands_report_missing_input_without_traceback(
    monkeypatch, capsys, tmp_path, command
):
    missing = tmp_path / "missing.log"
    monkeypatch.setattr(sys, "argv", ["sentinelkit", command, str(missing)])

    with pytest.raises(SystemExit) as exc_info:
        main()

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert f"cannot read {missing}" in captured.err
    assert "Traceback" not in captured.err
