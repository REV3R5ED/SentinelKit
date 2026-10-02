"""Core defensive analysis helpers used by SentinelKit."""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

try:
    import tomllib  # type: ignore[import-not-found]
except ImportError:  # Python 3.10 ships no stdlib tomllib
    tomllib = None  # type: ignore[assignment]

HASH_LENGTHS = {
    32: "MD5",
    40: "SHA-1",
    64: "SHA-256",
    96: "SHA-384",
    128: "SHA-512",
}

# Match every digest length SentinelKit can identify. Longest alternatives first
# so a SHA-512 value is captured whole rather than partially.
_HASH_ALTERNATIVES = "|".join(
    rf"[a-fA-F0-9]{{{length}}}" for length in sorted(HASH_LENGTHS, reverse=True)
)

IOC_PATTERNS = {
    "ipv4": re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"),
    "url": re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE),
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    "hash": re.compile(rf"\b(?:{_HASH_ALTERNATIVES})\b"),
}

DOMAIN_PATTERN = re.compile(
    r"\b(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}\b",
    re.IGNORECASE,
)
IPV6_CANDIDATE_PATTERN = re.compile(
    r"(?<![\w:.])\[?[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]+\]?(?![\w:.])"
)
DEFANGED_DOT_PATTERN = re.compile(r"\[(?:\.|dot)\]|\((?:\.|dot)\)", re.IGNORECASE)
DEFANGED_SCHEME_PATTERN = re.compile(r"\bhxxps?://", re.IGNORECASE)


class SentinelKitError(Exception):
    """A user-facing failure that the CLI reports without a traceback."""


def identify_hash(value: str) -> str | None:
    """Return a likely digest family based on hexadecimal form and length."""
    value = value.strip()
    if not re.fullmatch(r"[a-fA-F0-9]+", value):
        return None
    return HASH_LENGTHS.get(len(value))


def sha256_file(path: str | Path) -> str:
    """Calculate a SHA-256 digest without loading the whole file into memory.

    Raises SentinelKitError with a concise message when the file cannot be
    read, so callers can report the failure instead of dumping a traceback.
    """
    target = Path(path)
    digest = hashlib.sha256()
    try:
        handle = target.open("rb")
    except OSError as exc:
        raise SentinelKitError(f"cannot read {target}: {exc.strerror or exc}") from exc
    try:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    finally:
        handle.close()
    return digest.hexdigest()


def inspect_ip(value: str) -> dict[str, object]:
    """Validate an IP address and return defensive classification metadata."""
    address = ipaddress.ip_address(value.strip())
    return {
        "address": str(address),
        "version": address.version,
        "private": address.is_private,
        "global": address.is_global,
        "loopback": address.is_loopback,
        "multicast": address.is_multicast,
        "reserved": address.is_reserved,
    }


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Extract and normalize common indicators from arbitrary text."""
    normalized_text = _refang_ioc_text(text)
    results: dict[str, list[str]] = {}
    for name, pattern in IOC_PATTERNS.items():
        values = pattern.findall(normalized_text)
        if name == "ipv4":
            values = [v for v in values if _valid_ipv4(v)]
        results[name] = sorted(set(values))

    results["ipv6"] = _extract_ipv6(normalized_text)

    domains = set(DOMAIN_PATTERN.findall(normalized_text))
    for url in results["url"]:
        hostname = urlparse(url).hostname
        if hostname and not _valid_ip(hostname):
            domains.add(hostname)
    for email in results["email"]:
        domains.add(email.rsplit("@", 1)[-1])

    results["domain"] = sorted(d.lower() for d in domains if not _valid_ip(d))
    return results


# ---------------------------------------------------------------------------
# Offline IOC enrichment
# ---------------------------------------------------------------------------

RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")

# Conservative set of TLDs that are disproportionately seen in phishing and
# malware-delivery infrastructure. Used only as a triage hint, never a verdict.
DEFAULT_SUSPICIOUS_TLDS = frozenset(
    {
        "top",
        "xyz",
        "click",
        "zip",
        "mov",
        "rest",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "sbs",
        "icu",
        "cyou",
        "quest",
        "lol",
        "buzz",
        "monster",
        "cam",
        "tube",
        "surf",
    }
)

_LONG_LABEL_LENGTH = 32


@dataclass
class EnrichmentConfig:
    """Analyst-supplied enrichment inputs. Everything stays offline."""

    hash_blocklist: set[str] = field(default_factory=set)
    domain_blocklist: set[str] = field(default_factory=set)
    suspicious_tlds: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.hash_blocklist = {
            h.strip().lower() for h in self.hash_blocklist if h.strip()
        }
        self.domain_blocklist = {
            d.strip().lower() for d in self.domain_blocklist if d.strip()
        }
        if not self.suspicious_tlds:
            self.suspicious_tlds = set(DEFAULT_SUSPICIOUS_TLDS)
        else:
            self.suspicious_tlds = {
                t.strip().lower() for t in self.suspicious_tlds if t.strip()
            }


def load_enrichment_config(path: str | Path) -> EnrichmentConfig:
    """Load analyst blocklists from a TOML or simple YAML file.

    TOML (parsed with stdlib tomllib) accepts a ``[blocklists]`` section or
    top-level keys. YAML files use a tiny hand-rolled parser limited to
    ``key:`` blocks with ``- item`` lists so SentinelKit stays dependency-free.
    Supported keys: ``hashes``, ``domains``, ``suspicious_tlds``.
    """
    target = Path(path)
    try:
        raw = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise SentinelKitError(
            f"cannot read enrichment config {target}: {exc.strerror or exc}"
        ) from exc

    suffix = target.suffix.lower()
    try:
        if suffix == ".toml":
            if tomllib is None:
                raise SentinelKitError(
                    f"TOML enrichment configs need Python 3.11+ "
                    f"({target}); use a YAML config instead"
                )
            parsed = tomllib.loads(raw)
            section = parsed.get("blocklists", parsed)
        elif suffix in {".yaml", ".yml"}:
            parsed = _parse_simple_yaml(raw)
            section = parsed.get("blocklists", parsed)
        else:
            raise SentinelKitError(
                f"unsupported enrichment config format: {target} "
                "(use .toml, .yaml, or .yml)"
            )
    except SentinelKitError:
        raise
    except Exception as exc:  # tomllib.TOMLDecodeError and friends
        raise SentinelKitError(
            f"cannot parse enrichment config {target}: {exc}"
        ) from exc

    if not isinstance(section, dict):
        raise SentinelKitError(f"enrichment config {target} has no usable mapping")
    hashes = _as_str_list(section.get("hashes", []))
    domains = _as_str_list(section.get("domains", []))
    tlds = _as_str_list(section.get("suspicious_tlds", []))
    return EnrichmentConfig(
        hash_blocklist=set(hashes),
        domain_blocklist=set(domains),
        suspicious_tlds=set(tlds),
    )


def enrich_iocs(
    indicators: dict[str, list[str]],
    config: EnrichmentConfig | None = None,
) -> dict[str, list[str]]:
    """Apply offline, rule-based enrichment findings to extracted indicators.

    Findings are grouped by rule category and are purely local heuristics:
    private/CGNAT address ranges, suspicious TLD or host patterns, and
    analyst-supplied blocklists. No network calls are made.
    """
    config = config or EnrichmentConfig()
    findings: dict[str, list[str]] = {
        "private_addresses": [],
        "cgnat_addresses": [],
        "suspicious_hosts": [],
        "blocklisted": [],
    }

    for value in indicators.get("ipv4", []) + indicators.get("ipv6", []):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.version != 4:
            continue
        for network in RFC1918_NETWORKS:
            if address in network:
                findings["private_addresses"].append(f"{value} (RFC1918 {network})")
                break
        else:
            if address in CGNAT_NETWORK:
                findings["cgnat_addresses"].append(f"{value} (CGNAT {CGNAT_NETWORK})")

    hosts: dict[str, str] = {}
    for url in indicators.get("url", []):
        hostname = urlparse(url).hostname or ""
        if hostname:
            hosts[hostname.lower()] = f"URL host {hostname}"
            if _valid_ip(hostname):
                findings["suspicious_hosts"].append(
                    f"{hostname} (URL uses IP literal host)"
                )
    for domain in indicators.get("domain", []):
        hosts.setdefault(domain.lower(), f"domain {domain}")
    for email in indicators.get("email", []):
        hosts.setdefault(email.rsplit("@", 1)[-1].lower(), f"email domain {email}")

    for host, _origin in sorted(hosts.items()):
        tld = host.rsplit(".", 1)[-1].lower()
        if tld in config.suspicious_tlds:
            findings["suspicious_hosts"].append(f"{host} (suspicious TLD: .{tld})")
        labels = host.split(".")
        if any(label.startswith("xn--") for label in labels):
            findings["suspicious_hosts"].append(
                f"{host} (punycode label: possible homograph)"
            )
        if any(len(label) >= _LONG_LABEL_LENGTH for label in labels):
            findings["suspicious_hosts"].append(f"{host} (unusually long DNS label)")

    for value in indicators.get("hash", []):
        if value.lower() in config.hash_blocklist:
            findings["blocklisted"].append(f"hash {value} (blocklisted hash)")
    for domain in indicators.get("domain", []):
        if domain.lower() in config.domain_blocklist:
            findings["blocklisted"].append(f"domain {domain} (blocklisted domain)")

    for category, values in findings.items():
        findings[category] = sorted(set(values))
    return findings


def summarize_iocs(
    text: str, enrichment: EnrichmentConfig | None = None
) -> dict[str, object]:
    """Return deterministic IOC counts and an explainable triage priority.

    Priority is intentionally heuristic rather than a threat verdict: URLs,
    hashes, or blocklist matches are high priority, network addresses are
    medium priority, and other extracted indicators are low priority.
    Offline enrichment findings are folded into ``reasons`` so every priority
    decision stays explainable. SentinelKit performs no network enrichment.
    """
    indicators = extract_iocs(text)
    ordered_types = ("ipv4", "ipv6", "url", "email", "hash", "domain")
    counts = {name: len(indicators[name]) for name in ordered_types}
    reasons: list[str] = []

    if counts["url"]:
        reasons.append("URL present")
    if counts["hash"]:
        reasons.append("cryptographic hash present")
    if counts["ipv4"] or counts["ipv6"]:
        reasons.append("network address present")

    findings = enrich_iocs(indicators, enrichment)
    reasons.extend(f"private address: {item}" for item in findings["private_addresses"])
    reasons.extend(f"CGNAT address: {item}" for item in findings["cgnat_addresses"])
    reasons.extend(f"suspicious host: {item}" for item in findings["suspicious_hosts"])
    reasons.extend(findings["blocklisted"])

    if counts["url"] or counts["hash"] or findings["blocklisted"]:
        priority = "high"
    elif counts["ipv4"] or counts["ipv6"]:
        priority = "medium"
    else:
        priority = "low"

    return {
        "total_indicators": sum(counts.values()),
        "counts": counts,
        "triage_priority": priority,
        "reasons": reasons,
        "enrichment": findings,
    }


# ---------------------------------------------------------------------------
# Authentication log parsing (syslog, systemd journal, CSV)
# ---------------------------------------------------------------------------

_SYSLOG_TS = r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
_ISO_TS = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
_LOG_LINE_RE = re.compile(
    rf"^(?:(?P<ts>(?:{_SYSLOG_TS})|(?:{_ISO_TS}))\s+)?"
    r"(?:(?P<host>[A-Za-z0-9_.-]+)\s+)?"
    r"(?P<proc>[A-Za-z0-9_./-]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)

_FAILED_RE = re.compile(r"Failed password.*?from\s+([^\s]+)", re.IGNORECASE)
_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey).*?from\s+([^\s]+)", re.IGNORECASE
)
_INVALID_USER_RE = re.compile(r"Invalid user\s+([^\s]+)", re.IGNORECASE)

_CSV_COLUMN_ALIASES = {
    "timestamp": ("timestamp", "time", "datetime", "date", "event_time"),
    "host": ("host", "hostname", "server", "machine"),
    "process": ("process", "program", "service", "app", "application"),
    "message": ("message", "msg", "event", "log", "detail", "details"),
}


@dataclass
class LogRecord:
    """One parsed log line; timestamps may be absent for bare sshd output."""

    timestamp: datetime | None
    host: str
    process: str
    message: str
    raw: str


def detect_log_format(text: str) -> str:
    """Best-effort log format detection: csv, journal, syslog, or raw."""
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return "raw"
    if _looks_like_csv(lines[0]):
        return "csv"
    if any(re.match(rf"^{_ISO_TS}\s+\S+", line) for line in lines):
        return "journal"
    if any(_LOG_LINE_RE.match(line) for line in lines):
        return "syslog"
    return "raw"


def parse_log_records(
    text: str, log_format: str = "auto"
) -> tuple[list[LogRecord], str]:
    """Parse log text into structured records with a detected format label."""
    detected = detect_log_format(text) if log_format == "auto" else log_format
    if detected == "csv":
        return _parse_csv_records(text), detected
    records: list[LogRecord] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        match = _LOG_LINE_RE.match(line)
        if match:
            timestamp = _parse_timestamp(match.group("ts") or "")
            records.append(
                LogRecord(
                    timestamp=timestamp,
                    host=match.group("host") or "",
                    process=match.group("proc") or "",
                    message=match.group("msg") or "",
                    raw=line,
                )
            )
        else:
            records.append(
                LogRecord(timestamp=None, host="", process="", message=line, raw=line)
            )
    return records, detected


def summarize_auth_log(
    text: str, *, failed_threshold: int = 5, window_minutes: int = 10
) -> dict[str, object]:
    """Summarize SSH authentication events from syslog, journal, or CSV logs.

    Beyond the legacy counts this also flags ``brute_force_suspects``:
    sources reaching ``failed_threshold`` failed logins inside a sliding
    ``window_minutes`` window. Timestamps may be absent; in that case the
    threshold is applied to total per-source failures and the reason is noted.
    """
    records, detected = parse_log_records(text)

    failed: list[tuple[datetime | None, str]] = []
    accepted: list[str] = []
    invalid_users: list[str] = []
    for record in records:
        message = record.message
        failed.extend(
            (record.timestamp, source) for source in _FAILED_RE.findall(message)
        )
        accepted.extend(_ACCEPTED_RE.findall(message))
        invalid_users.extend(_INVALID_USER_RE.findall(message))

    failure_counts = Counter(source for _, source in failed)
    suspects = _detect_brute_force(
        failed, failed_threshold=failed_threshold, window_minutes=window_minutes
    )
    return {
        "log_format": detected,
        "failed_attempts": len(failed),
        "successful_logins": len(accepted),
        "top_failed_sources": failure_counts.most_common(10),
        "successful_sources": sorted(set(accepted)),
        "invalid_user_attempts": len(invalid_users),
        "top_invalid_usernames": Counter(invalid_users).most_common(10),
        "brute_force_suspects": suspects,
    }


def _detect_brute_force(
    failed: list[tuple[datetime | None, str]],
    *,
    failed_threshold: int,
    window_minutes: int,
) -> list[dict[str, object]]:
    """Flag sources with burst failures via a sliding time window."""
    window = window_minutes * 60
    by_source: dict[str, list[datetime | None]] = {}
    for timestamp, source in failed:
        by_source.setdefault(source, []).append(timestamp)

    suspects: list[dict[str, object]] = []
    for source in sorted(by_source):
        stamps = by_source[source]
        timed = sorted(t for t in stamps if t is not None)
        if not timed:
            if len(stamps) >= failed_threshold:
                suspects.append(
                    {
                        "source": source,
                        "failures": len(stamps),
                        "window_minutes": window_minutes,
                        "first_seen": None,
                        "last_seen": None,
                        "reason": (
                            "no timestamps available; "
                            "threshold applied to total failures"
                        ),
                    }
                )
            continue
        best = 0
        best_first: datetime | None = None
        best_last: datetime | None = None
        start = 0
        for end, current in enumerate(timed):
            while (current - timed[start]).total_seconds() > window:
                start += 1
            span = end - start + 1
            if span > best:
                best = span
                best_first = timed[start]
                best_last = current
        if best >= failed_threshold and best_first and best_last:
            suspects.append(
                {
                    "source": source,
                    "failures": len(stamps),
                    "window_minutes": window_minutes,
                    "max_failures_in_window": best,
                    "first_seen": best_first.isoformat(),
                    "last_seen": best_last.isoformat(),
                    "reason": (f"{best} failed logins within {window_minutes} minutes"),
                }
            )
    return suspects


def _looks_like_csv(first_line: str) -> bool:
    if "," not in first_line:
        return False
    cells = {cell.strip().strip("\"'").lower() for cell in first_line.split(",")}
    known = {alias for aliases in _CSV_COLUMN_ALIASES.values() for alias in aliases}
    return bool(cells & known)


def _parse_csv_records(text: str) -> list[LogRecord]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return []
    columns = {name.strip().lower(): name for name in reader.fieldnames if name}
    mapping: dict[str, str] = {}
    for logical, aliases in _CSV_COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in columns:
                mapping[logical] = columns[alias]
                break
    records: list[LogRecord] = []
    for row in reader:
        message = ""
        if "message" in mapping:
            message = row.get(mapping["message"], "") or ""
        if not message.strip():
            continue
        timestamp = (
            _parse_timestamp(row.get(mapping["timestamp"], "") or "")
            if "timestamp" in mapping
            else None
        )
        records.append(
            LogRecord(
                timestamp=timestamp,
                host=(row.get(mapping["host"], "") or "") if "host" in mapping else "",
                process=(row.get(mapping["process"], "") or "")
                if "process" in mapping
                else "",
                message=message,
                raw=",".join(str(value or "") for value in row.values()),
            )
        )
    return records


def _parse_timestamp(value: str) -> datetime | None:
    """Parse syslog or ISO-8601 timestamps, normalizing to naive UTC.

    Syslog timestamps carry no zone, so everything is normalized to naive UTC
    to keep brute-force window arithmetic consistent within one log.
    """
    value = value.strip()
    if not value:
        return None
    iso_candidate = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(iso_candidate)
    except ValueError:
        parsed = None
    if parsed is not None:
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    match = re.match(rf"^({_SYSLOG_TS})$", value)
    if match:
        try:
            return datetime.strptime(match.group(1), "%b %d %H:%M:%S").replace(
                year=datetime.now(timezone.utc).year
            )
        except ValueError:
            return None
    return None


def _parse_simple_yaml(text: str) -> dict[str, object]:
    """Parse a minimal YAML subset: top-level ``key:`` blocks with ``- item`` lists.

    This is intentionally not a general YAML parser; it covers the blocklist
    config shape SentinelKit documents and avoids a third-party dependency.
    """
    data: dict[str, object] = {}
    current_key: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line[:1].isspace() and ":" in stripped:
            key, _, rest = stripped.partition(":")
            key = key.strip()
            rest = rest.strip()
            if rest.startswith("[") and rest.endswith("]"):
                data[key] = [
                    item.strip().strip("'\"")
                    for item in rest[1:-1].split(",")
                    if item.strip()
                ]
                current_key = None
            elif rest:
                data[key] = rest.strip("'\"")
                current_key = None
            else:
                data[key] = []
                current_key = key
        elif stripped.startswith("- ") and current_key is not None:
            items = data.get(current_key)
            if isinstance(items, list):
                items.append(stripped[2:].strip().strip("'\""))
    return data


def _as_str_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return []


def _extract_ipv6(text: str) -> list[str]:
    """Extract valid IPv6 literals and return canonical, deduplicated values."""
    values: set[str] = set()
    for match in IPV6_CANDIDATE_PATTERN.finditer(text):
        candidate = match.group(0).strip("[]").rstrip(".")
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.version == 6:
            values.add(str(address))
    return sorted(values)


def _refang_ioc_text(text: str) -> str:
    """Normalize analyst-safe IOC defanging without contacting the indicator."""
    normalized = DEFANGED_DOT_PATTERN.sub(".", text)

    def _restore_scheme(match: re.Match[str]) -> str:
        return "https://" if match.group(0).lower().startswith("hxxps") else "http://"

    return DEFANGED_SCHEME_PATTERN.sub(_restore_scheme, normalized)


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _valid_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


__all__ = [
    "CGNAT_NETWORK",
    "DEFAULT_SUSPICIOUS_TLDS",
    "HASH_LENGTHS",
    "IOC_PATTERNS",
    "RFC1918_NETWORKS",
    "EnrichmentConfig",
    "LogRecord",
    "SentinelKitError",
    "detect_log_format",
    "enrich_iocs",
    "extract_iocs",
    "identify_hash",
    "inspect_ip",
    "load_enrichment_config",
    "parse_log_records",
    "sha256_file",
    "summarize_auth_log",
    "summarize_iocs",
]
