import json

from sentinelkit.cli import _print


def test_print_json(capsys):
    _print({"failed_attempts": 2}, as_json=True)
    captured = capsys.readouterr().out
    assert json.loads(captured) == {"failed_attempts": 2}


def test_print_text(capsys):
    _print({"failed_attempts": 2}, as_json=False)
    captured = capsys.readouterr().out
    assert "Failed Attempts: 2" in captured
