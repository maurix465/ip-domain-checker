"""Tests for target validation and normalization."""

import pytest

from blacklist_checker.models import TargetType
from blacklist_checker.utils import TargetValidationError, parse_target


@pytest.mark.parametrize(
    ("raw", "normalized", "target_type"),
    [
        ("192.0.2.1", "192.0.2.1", TargetType.IPV4),
        (" 192.0.2.1 ", "192.0.2.1", TargetType.IPV4),
        ("2001:0db8::1", "2001:db8::1", TargetType.IPV6),
        ("EXAMPLE.COM", "example.com", TargetType.DOMAIN),
        ("example.com.", "example.com", TargetType.DOMAIN),
        ("bücher.example", "xn--bcher-kva.example", TargetType.DOMAIN),
    ],
)
def test_parse_target_normalizes_supported_targets(
    raw: str,
    normalized: str,
    target_type: TargetType,
) -> None:
    target = parse_target(raw)

    assert target.original == raw
    assert target.normalized == normalized
    assert target.type is target_type


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "localhost",
        "invalid_domain.example",
        "-invalid.example",
        "invalid-.example",
        "example..com",
        "example.123",
        "999.1.1.1",
        "fe80::1%eth0",
    ],
)
def test_parse_target_rejects_invalid_targets(raw: str) -> None:
    with pytest.raises(TargetValidationError):
        parse_target(raw)


def test_parse_target_accepts_63_character_domain_label() -> None:
    domain = f"{'a' * 63}.example"

    assert parse_target(domain).normalized == domain


def test_parse_target_rejects_domain_label_over_63_characters() -> None:
    with pytest.raises(TargetValidationError):
        parse_target(f"{'a' * 64}.example")


def test_parse_target_accepts_maximum_length_domain() -> None:
    domain = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))

    assert len(domain) == 253
    assert parse_target(domain).normalized == domain


def test_parse_target_rejects_domain_over_maximum_length() -> None:
    domain = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 62))

    assert len(domain) == 254
    with pytest.raises(TargetValidationError):
        parse_target(domain)


def test_parse_target_rejects_multiple_trailing_dots() -> None:
    with pytest.raises(TargetValidationError):
        parse_target("example.com..")


def test_parse_target_rejects_malformed_idna_input() -> None:
    with pytest.raises(TargetValidationError):
        parse_target("\ud800.example")


def test_parse_target_rejects_bracketed_ipv6() -> None:
    with pytest.raises(TargetValidationError):
        parse_target("[2001:db8::1]")


@pytest.mark.parametrize(
    ("raw", "target_type"),
    [
        ("10.0.0.1", TargetType.IPV4),
        ("192.0.2.1", TargetType.IPV4),
        ("fc00::1", TargetType.IPV6),
        ("2001:db8::1", TargetType.IPV6),
    ],
)
def test_parse_target_accepts_private_and_reserved_addresses(
    raw: str,
    target_type: TargetType,
) -> None:
    assert parse_target(raw).type is target_type
