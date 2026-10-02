"""Command-line interface for SentinelKit."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from . import __version__
from .core import (
    SentinelKitError,
    extract_iocs,
    identify_hash,
    inspect_ip,
    load_enrichment_config,
    sha256_file,
    summarize_auth_log,
    summarize_iocs,
)
from .stix import export_stix


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


def _read_text_file(parser: argparse.ArgumentParser, value: str) -> str:
    """Read analyst-supplied text, or stdin when the file argument is `-`."""
    if value == "-":
        return sys.stdin.read()
    path = Path(value)
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        parser.error(f"cannot read {path}: {exc.strerror or exc}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinelkit", description="Defensive security analysis toolkit"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="print the SentinelKit version and exit",
    )
    # Output-format option shared by the top-level parser and every subcommand
    # so both `sentinelkit --format stix ioc f` and `sentinelkit ioc --format
    # stix f` work. The top-level copy is hidden to keep --help readable.
    format_parent = argparse.ArgumentParser(add_help=False)
    format_parent.add_argument(
        "--format",
        choices=("json", "text", "stix"),
        # SUPPRESS so a subcommand default never overwrites a value given
        # before the subcommand on the top-level parser.
        default=argparse.SUPPRESS,
        dest="output_format",
        help="output format (default: json; stix emits a STIX 2.1 bundle, "
        "only for the ioc command)",
    )
    parser.add_argument(
        "--format",
        choices=("json", "text", "stix"),
        default="json",
        dest="output_format",
        help=argparse.SUPPRESS,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    hash_cmd = sub.add_parser(
        "hash",
        parents=[format_parent],
        help="calculate SHA-256 and identify digest strings",
    )
    hash_cmd.add_argument(
        "value", help="file path, digest string, or - to hash stdin bytes"
    )

    ip_cmd = sub.add_parser(
        "ip", parents=[format_parent], help="classify an IP address"
    )
    ip_cmd.add_argument("address")

    ioc_cmd = sub.add_parser(
        "ioc",
        parents=[format_parent],
        help="extract indicators from a text file",
    )
    ioc_cmd.add_argument("file", help="text file to analyze, or - for stdin")

    triage_cmd = sub.add_parser(
        "triage",
        parents=[format_parent],
        help="summarize IOC counts and assign an explainable priority",
    )
    triage_cmd.add_argument("file", help="text file to analyze, or - for stdin")
    triage_cmd.add_argument(
        "--enrich",
        metavar="CONFIG",
        default=None,
        help="TOML or YAML file with analyst blocklists "
        "(hashes, domains, suspicious_tlds)",
    )

    log_cmd = sub.add_parser(
        "logs",
        parents=[format_parent],
        help="summarize authentication log events",
    )
    log_cmd.add_argument("file", help="log file to analyze, or - for stdin")
    log_cmd.add_argument(
        "--log-format",
        choices=("auto", "syslog", "journal", "csv"),
        default="auto",
        dest="log_format",
        help="log format (default: auto-detect)",
    )
    log_cmd.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="failed logins per source that flag a brute-force suspect (default: 5)",
    )
    log_cmd.add_argument(
        "--window",
        type=int,
        default=10,
        help="sliding window in minutes for brute-force detection (default: 10)",
    )

    args = parser.parse_args()

    if args.output_format == "stix" and args.command != "ioc":
        parser.error("--format stix is only supported by the ioc command")

    if args.command == "hash":
        if args.value == "-":
            digest = hashlib.sha256(sys.stdin.buffer.read()).hexdigest()
            _print({"source": "stdin", "sha256": digest}, args.output_format)
        else:
            candidate = Path(args.value)
            if candidate.is_file():
                try:
                    file_digest = sha256_file(candidate)
                except SentinelKitError as exc:
                    parser.error(str(exc))
                _print(
                    {"file": str(candidate), "sha256": file_digest},
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
        indicators = extract_iocs(_read_text_file(parser, args.file))
        if args.output_format == "stix":
            print(json.dumps(export_stix(indicators), indent=2))
        else:
            _print(indicators, args.output_format)
    elif args.command == "triage":
        enrichment = None
        if args.enrich:
            try:
                enrichment = load_enrichment_config(args.enrich)
            except SentinelKitError as exc:
                parser.error(str(exc))
        _print(
            summarize_iocs(_read_text_file(parser, args.file), enrichment),
            args.output_format,
        )
    elif args.command == "logs":
        if args.threshold < 1:
            parser.error("--threshold must be at least 1")
        if args.window < 1:
            parser.error("--window must be at least 1")
        _print(
            summarize_auth_log(
                _read_text_file(parser, args.file),
                failed_threshold=args.threshold,
                window_minutes=args.window,
            ),
            args.output_format,
        )


if __name__ == "__main__":
    main()
