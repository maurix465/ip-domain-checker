"""Application models for targets, sources, and check results."""

from __future__ import annotations

import codecs
import math
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit


class TargetType(StrEnum):
    """Supported scan target types."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"


class SourceKind(StrEnum):
    """Supported blacklist source kinds."""

    DNSBL = "dnsbl"
    HTTP_STATIC = "http_static"
    LOCAL_STATIC = "local_static"


class ListFormat(StrEnum):
    """Supported static-list formats."""

    TXT = "txt"
    CSV = "csv"


class CheckStatus(StrEnum):
    """Outcome of checking one target against one source."""

    LISTED = "listed"
    NOT_LISTED = "not_listed"
    SKIPPED = "skipped"
    ERROR = "error"


class ErrorKind(StrEnum):
    """Stable categories for per-source failures."""

    DNS_TIMEOUT = "dns_timeout"
    DNS_SERVFAIL = "dns_servfail"
    DNS_RESOLUTION = "dns_resolution"
    HTTP_TIMEOUT = "http_timeout"
    HTTP_CONNECTION = "http_connection"
    HTTP_STATUS = "http_status"
    DOWNLOAD_TOO_LARGE = "download_too_large"
    FILE_TOO_LARGE = "file_too_large"
    DECODE = "decode_error"
    PARSE = "parse_error"
    FILE_NOT_FOUND = "file_not_found"
    FILE_PERMISSION = "file_permission"
    FILE_READ = "file_read"
    UNEXPECTED = "unexpected"


@dataclass(frozen=True, slots=True)
class Target:
    """A validated and normalized scan target."""

    original: str
    normalized: str
    type: TargetType


@dataclass(frozen=True, slots=True, kw_only=True)
class CsvOptions:
    """Parsing options for a CSV static list."""

    has_header: bool
    column: str | int
    delimiter: str = ","

    def __post_init__(self) -> None:
        if not isinstance(self.has_header, bool):
            raise TypeError("has_header must be a boolean")
        if (
            not isinstance(self.delimiter, str)
            or len(self.delimiter) != 1
            or self.delimiter in {"\0", "\n", "\r"}
        ):
            raise ValueError("CSV delimiter must be one non-newline character")

        if self.has_header:
            if not isinstance(self.column, str) or not self.column.strip():
                raise ValueError("header-based CSV column must be a non-empty name")
        elif (
            isinstance(self.column, bool)
            or not isinstance(self.column, int)
            or self.column < 0
        ):
            raise ValueError(
                "headerless CSV column must be a non-negative integer index"
            )


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceConfig:
    """Fields shared by every validated source configuration."""

    name: str
    category: str
    supports: frozenset[TargetType]
    enabled: bool = True

    def __post_init__(self) -> None:
        if type(self) is SourceConfig:
            raise TypeError(
                "SourceConfig must be instantiated through a source subtype"
            )
        _require_non_empty_string(self.name, "source name")
        _require_non_empty_string(self.category, "source category")
        if not isinstance(self.supports, frozenset):
            raise TypeError("source supports must be a frozenset")
        if not self.supports:
            raise ValueError("source supports must not be empty")
        if any(
            not isinstance(target_type, TargetType) for target_type in self.supports
        ):
            raise TypeError("source supports must contain only TargetType values")
        if not isinstance(self.enabled, bool):
            raise TypeError("source enabled flag must be a boolean")


@dataclass(frozen=True, slots=True, kw_only=True)
class DnsblSourceConfig(SourceConfig):
    """Configuration for an IP DNSBL with an optional timeout override."""

    kind: Literal[SourceKind.DNSBL] = field(
        default=SourceKind.DNSBL,
        init=False,
    )

    host: str
    timeout_seconds: float | None = None

    def __post_init__(self) -> None:
        SourceConfig.__post_init__(self)
        _require_non_empty_string(self.host, "DNSBL host")
        if TargetType.DOMAIN in self.supports:
            raise ValueError("DNSBL sources must not support domain targets")
        _validate_positive_number(self.timeout_seconds, "DNSBL timeout override")


@dataclass(frozen=True, slots=True, kw_only=True)
class RemoteStaticSourceConfig(SourceConfig):
    """HTTP static list with optional timeout and size-limit overrides."""

    kind: Literal[SourceKind.HTTP_STATIC] = field(
        default=SourceKind.HTTP_STATIC,
        init=False,
    )

    url: str
    format: ListFormat
    encoding: str = "utf-8-sig"
    comment_prefixes: tuple[str, ...] = ("#", ";")
    csv: CsvOptions | None = None
    timeout_seconds: float | None = None
    max_static_bytes: int | None = None

    def __post_init__(self) -> None:
        SourceConfig.__post_init__(self)
        _validate_http_url(self.url)
        _validate_static_options(
            list_format=self.format,
            encoding=self.encoding,
            comment_prefixes=self.comment_prefixes,
            csv_options=self.csv,
            max_static_bytes=self.max_static_bytes,
        )
        _validate_positive_number(self.timeout_seconds, "HTTP timeout override")


@dataclass(frozen=True, slots=True, kw_only=True)
class LocalStaticSourceConfig(SourceConfig):
    """Local static list with an optional size-limit override."""

    kind: Literal[SourceKind.LOCAL_STATIC] = field(
        default=SourceKind.LOCAL_STATIC,
        init=False,
    )

    path: Path
    format: ListFormat
    encoding: str = "utf-8-sig"
    comment_prefixes: tuple[str, ...] = ("#", ";")
    csv: CsvOptions | None = None
    max_static_bytes: int | None = None

    def __post_init__(self) -> None:
        SourceConfig.__post_init__(self)
        if not isinstance(self.path, Path):
            raise TypeError("static-list path must be a Path")
        _validate_static_options(
            list_format=self.format,
            encoding=self.encoding,
            comment_prefixes=self.comment_prefixes,
            csv_options=self.csv,
            max_static_bytes=self.max_static_bytes,
        )


type BlacklistSourceConfig = (
    DnsblSourceConfig | RemoteStaticSourceConfig | LocalStaticSourceConfig
)


@dataclass(frozen=True, slots=True, kw_only=True)
class AppConfig:
    """Validated configuration and the sole owner of global defaults.

    A ``None`` timeout or size limit on a source means that the corresponding
    value defined here applies. Non-``None`` source values are explicit
    per-source overrides.
    """

    sources: tuple[BlacklistSourceConfig, ...]
    dns_timeout_seconds: float = 5.0
    http_timeout_seconds: float = 15.0
    max_static_bytes: int = 10_485_760

    def __post_init__(self) -> None:
        if not isinstance(self.sources, tuple):
            raise TypeError("sources must be a tuple")
        if not self.sources:
            raise ValueError("configuration must contain at least one source")
        if any(not isinstance(source, SourceConfig) for source in self.sources):
            raise TypeError("sources must contain only supported source models")

        source_names = [source.name for source in self.sources]
        if len(source_names) != len(set(source_names)):
            raise ValueError("source names must be unique")

        _validate_positive_number(self.dns_timeout_seconds, "default DNS timeout")
        _validate_positive_number(self.http_timeout_seconds, "default HTTP timeout")
        _validate_positive_integer(self.max_static_bytes, "default static size limit")


@dataclass(frozen=True, slots=True)
class CheckFailure:
    """A structured failure produced by an individual source."""

    kind: ErrorKind
    message: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ErrorKind):
            raise TypeError("failure kind must be an ErrorKind")
        _require_non_empty_string(self.message, "failure message")


@dataclass(frozen=True, slots=True, kw_only=True)
class CheckResult:
    """Result of checking a target against one configured source.

    Listed results contain evidence, not-listed results contain neither evidence
    nor explanatory payloads, skipped results contain a reason, and error
    results contain only a structured failure.
    """

    source_name: str
    source_kind: SourceKind
    category: str
    target: Target
    status: CheckStatus
    evidence: tuple[str, ...] = ()
    reason: str | None = None
    failure: CheckFailure | None = None
    entries_read: int = 0
    malformed_entries: int = 0
    duplicate_entries: int = 0

    def __post_init__(self) -> None:
        _require_non_empty_string(self.source_name, "result source name")
        _require_non_empty_string(self.category, "result source category")
        if not isinstance(self.source_kind, SourceKind):
            raise TypeError("result source kind must be a SourceKind")
        if not isinstance(self.target, Target):
            raise TypeError("result target must be a Target")
        if not isinstance(self.status, CheckStatus):
            raise TypeError("result status must be a CheckStatus")
        if self.failure is not None and not isinstance(self.failure, CheckFailure):
            raise TypeError("result failure must be a CheckFailure")
        if not isinstance(self.evidence, tuple):
            raise TypeError("result evidence must be a tuple")
        if any(not isinstance(item, str) or not item for item in self.evidence):
            raise ValueError("result evidence entries must be non-empty strings")
        _validate_non_negative_integer(self.entries_read, "entries_read")
        _validate_non_negative_integer(self.malformed_entries, "malformed_entries")
        _validate_non_negative_integer(self.duplicate_entries, "duplicate_entries")
        if self.malformed_entries + self.duplicate_entries > self.entries_read:
            raise ValueError(
                "malformed and duplicate entry counts must not exceed entries_read"
            )

        if self.status is CheckStatus.LISTED:
            if not self.evidence:
                raise ValueError("a listed result must include evidence")
            self._reject_reason_and_failure()
        elif self.status is CheckStatus.NOT_LISTED:
            if self.evidence:
                raise ValueError("a not-listed result must not include evidence")
            self._reject_reason_and_failure()
        elif self.status is CheckStatus.SKIPPED:
            if self.evidence:
                raise ValueError("a skipped result must not include evidence")
            _require_non_empty_string(self.reason, "skip reason")
            if self.failure is not None:
                raise ValueError("a skipped result must not include a failure")
        elif self.status is CheckStatus.ERROR:
            if self.evidence:
                raise ValueError("an error result must not include evidence")
            if self.reason is not None:
                raise ValueError("an error result must not include a skip reason")
            if self.failure is None:
                raise ValueError("an error result must include a failure")

    def _reject_reason_and_failure(self) -> None:
        if self.reason is not None:
            raise ValueError(f"a {self.status.value} result must not include a reason")
        if self.failure is not None:
            raise ValueError(f"a {self.status.value} result must not include a failure")


def _require_non_empty_string(value: str | None, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must not be empty")


def _validate_positive_number(value: float | None, field_name: str) -> None:
    if value is None:
        return
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError(f"{field_name} must be a positive finite number")


def _validate_positive_integer(value: int | None, field_name: str) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field_name} must be a positive integer")


def _validate_non_negative_integer(value: int, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")


def _validate_http_url(value: str) -> None:
    _require_non_empty_string(value, "static-list URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("static-list URL is invalid") from error
    if parsed.scheme.lower() not in {"http", "https"} or parsed.hostname is None:
        raise ValueError("static-list URL must use HTTP or HTTPS with a host")
    if port is not None and not 1 <= port <= 65_535:
        raise ValueError("static-list URL port must be between 1 and 65535")


def _validate_static_options(
    *,
    list_format: ListFormat,
    encoding: str,
    comment_prefixes: tuple[str, ...],
    csv_options: CsvOptions | None,
    max_static_bytes: int | None,
) -> None:
    if not isinstance(list_format, ListFormat):
        raise TypeError("static-list format must be a ListFormat")
    _require_non_empty_string(encoding, "static-list encoding")
    try:
        codecs.lookup(encoding)
    except LookupError as error:
        raise ValueError(f"unknown static-list encoding {encoding!r}") from error
    if not isinstance(comment_prefixes, tuple):
        raise TypeError("comment prefixes must be a tuple")
    if any(not isinstance(prefix, str) or not prefix for prefix in comment_prefixes):
        raise ValueError("comment prefixes must be non-empty strings")
    if list_format is ListFormat.CSV and csv_options is None:
        raise ValueError("CSV format requires CSV options")
    if list_format is ListFormat.TXT and csv_options is not None:
        raise ValueError("TXT format must not include CSV options")
    if csv_options is not None and not isinstance(csv_options, CsvOptions):
        raise TypeError("csv must be a CsvOptions instance")
    _validate_positive_integer(max_static_bytes, "static size-limit override")
