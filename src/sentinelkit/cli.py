"""Command-line interface for SentinelKit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import (
    extract_iocs,
    identify_hash,
    inspect_ip,
    sha256_file,
    summarize_auth_log,
    summarize_iocs,
)


def _print(data: object, output_format: str = "json") -> None:
    """Render CLI output while keeping JSON as the stable default."""
    if output_format == "json":
        print(json.dumps(data, indent=2, default=str))
        return

    if isinstance(data, dict):
        for key, value in data.items():
            label = key.replace("_", " ").title()
            if isinstance(value, (dict, list)):
                value = json.dumps(value, sort_keys=True, default=str)
            print(f"{label}: {value}")
        return

    print(data)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinelkit", description="Defensive security analysis toolkit"
    )
    parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
        dest="output_format",
        help="output format (default: json)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    hash_cmd = sub.add_parser(
        "hash", help="calculate SHA-256 and identify digest strings"
    )
    hash_cmd.add_argument("value", help="file path or digest string")

    ip_cmd = sub.add_parser("ip", help="classify an IP address")
    ip_cmd.add_argument("address")

    ioc_cmd = sub.add_parser("ioc", help="extract indicators from a text file")
    ioc_cmd.add_argument("file")

    triage_cmd = sub.add_parser(
        "triage", help="summarize IOC counts and assign an explainable priority"
    )
    triage_cmd.add_argument("file")

    log_cmd = sub.add_parser("logs", help="summarize authentication log events")
    log_cmd.add_argument("file")

    args = parser.parse_args()

    if args.command == "hash":
        candidate = Path(args.value)
        if candidate.is_file():
            _print(
                {"file": str(candidate), "sha256": sha256_file(candidate)},
                args.output_format,
            )
        else:
            _print(
                {"value": args.value, "likely_type": identify_hash(args.value)},
                args.output_format,
            )
    elif args.command == "ip":
        try:
            _print(inspect_ip(args.address), args.output_format)
        except ValueError as exc:
            parser.error(str(exc))
    elif args.command == "ioc":
        _print(
            extract_iocs(Path(args.file).read_text(encoding="utf-8", errors="replace")),
            args.output_format,
        )
    elif args.command == "triage":
        _print(
            summarize_iocs(
                Path(args.file).read_text(encoding="utf-8", errors="replace")
            ),
            args.output_format,
        )
    elif args.command == "logs":
        _print(
            summarize_auth_log(
                Path(args.file).read_text(encoding="utf-8", errors="replace")
            ),
            args.output_format,
        )


if __name__ == "__main__":
    main()
