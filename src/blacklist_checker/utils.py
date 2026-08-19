"""Validation and normalization helpers."""

from __future__ import annotations

import ipaddress
import re

from blacklist_checker.models import Target, TargetType

_DOMAIN_LABEL_PATTERN = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
    flags=re.ASCII,
)
_MAX_DOMAIN_LENGTH = 253


class TargetValidationError(ValueError):
    """Raised when a scan target is neither an IP address nor a valid domain."""


def normalize_domain(value: str) -> str:
    """Validate and normalize a dotted domain name to lowercase ASCII."""
    candidate = value[:-1] if value.endswith(".") else value

    try:
        normalized = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise TargetValidationError("target is not a valid domain name") from error

    if len(normalized) > _MAX_DOMAIN_LENGTH:
        raise TargetValidationError("domain name exceeds 253 characters")

    labels = normalized.split(".")
    if len(labels) < 2:
        raise TargetValidationError("domain target must contain at least one dot")
    if any(_DOMAIN_LABEL_PATTERN.fullmatch(label) is None for label in labels):
        raise TargetValidationError("target is not a valid domain name")
    if labels[-1].isdigit():
        raise TargetValidationError("domain name must not end with a numeric label")

    return normalized


def parse_target(value: str) -> Target:
    """Parse an IP address or strict dotted domain into a normalized target."""
    original = value
    candidate = value.strip()
    if not candidate:
        raise TargetValidationError("target must not be empty")

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        normalized = normalize_domain(candidate)
        return Target(
            original=original,
            normalized=normalized,
            type=TargetType.DOMAIN,
        )

    if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
        raise TargetValidationError("scoped IPv6 addresses are not supported")

    target_type = (
        TargetType.IPV4
        if isinstance(address, ipaddress.IPv4Address)
        else TargetType.IPV6
    )
    return Target(original=original, normalized=str(address), type=target_type)
