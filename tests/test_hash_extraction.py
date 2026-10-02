"""Regression tests for SHA-384/SHA-512 IOC extraction.

The IOC extractor previously only matched 32/40/64-hex digests even though
``identify_hash`` advertised SHA-384 (96) and SHA-512 (128) support, so those
IOCs were silently never extracted.
"""

from sentinelkit.core import extract_iocs, identify_hash


def test_identify_hash_covers_sha384_and_sha512():
    assert identify_hash("b" * 96) == "SHA-384"
    assert identify_hash("c" * 128) == "SHA-512"


def test_extract_iocs_captures_sha384_and_sha512():
    sha384 = "b" * 96
    sha512 = "c" * 128
    result = extract_iocs(f"artifact digests: {sha384} and {sha512}")

    assert sha384 in result["hash"]
    assert sha512 in result["hash"]


def test_extract_iocs_captures_all_digest_lengths_together():
    text = " ".join(
        [
            "d" * 32,  # MD5
            "e" * 40,  # SHA-1
            "f" * 64,  # SHA-256
            "a" * 96,  # SHA-384
            "b" * 128,  # SHA-512
        ]
    )
    result = extract_iocs(text)

    assert len(result["hash"]) == 5
    assert sorted(len(h) for h in result["hash"]) == [32, 40, 64, 96, 128]


def test_extract_iocs_does_not_split_long_digests():
    """A SHA-512 digest must not be reported as two SHA-256 digests."""
    sha512 = "c" * 128
    result = extract_iocs(f"digest {sha512} end")

    assert result["hash"] == [sha512]


def test_extract_iocs_rejects_near_miss_lengths():
    result = extract_iocs("values " + "a" * 31 + " and " + "b" * 65)

    assert result["hash"] == []


def test_extract_iocs_rejects_non_hex_strings():
    result = extract_iocs("serial " + "z" * 64 + " and " + "g" * 96)

    assert result["hash"] == []


def test_extract_iocs_hash_is_case_insensitive():
    mixed = "AbCd" * 16  # 64 hex chars, mixed case
    result = extract_iocs(f"digest {mixed}")

    assert mixed in result["hash"]
