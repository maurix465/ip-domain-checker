"""Blacklist source checker implementations."""

from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import math
from collections.abc import Iterable, Iterator
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

import aiohttp
import dns.asyncresolver
import dns.exception
import dns.rcode
import dns.resolver

from blacklist_checker.models import (
    CheckFailure,
    CheckResult,
    CheckStatus,
    CsvOptions,
    DnsblSourceConfig,
    ErrorKind,
    ListFormat,
    LocalStaticSourceConfig,
    RemoteStaticSourceConfig,
    Target,
    TargetType,
)
from blacklist_checker.utils import TargetValidationError, parse_target

type StaticSourceConfig = LocalStaticSourceConfig | RemoteStaticSourceConfig


class DnsAddressRecord(Protocol):
    """Minimal interface exposed by an A-record response."""

    address: str


class AsyncDnsResolver(Protocol):
    """Injectable subset of dnspython's asynchronous resolver interface."""

    async def resolve(
        self,
        qname: str,
        rdtype: str,
        *,
        lifetime: float,
        search: bool,
    ) -> Iterable[DnsAddressRecord]:
        """Resolve one DNS record set."""


class AsyncHttpResponseStream(Protocol):
    """Minimal interface for incrementally reading an HTTP response body."""

    async def read(self, size: int = -1) -> bytes:
        """Read up to ``size`` response bytes."""


class AsyncHttpResponse(Protocol):
    """Minimal response interface needed by the remote-list checker."""

    @property
    def status(self) -> int:
        """HTTP status code."""

    @property
    def content_length(self) -> int | None:
        """Declared response length, when supplied by the server."""

    @property
    def content(self) -> AsyncHttpResponseStream:
        """Streaming response body."""


class AsyncHttpSession(Protocol):
    """Injectable subset of aiohttp's shared client-session interface."""

    def get(
        self,
        url: str,
        *,
        timeout: aiohttp.ClientTimeout,
    ) -> AbstractAsyncContextManager[AsyncHttpResponse]:
        """Start one bounded-time HTTP GET request."""


@dataclass(frozen=True, slots=True)
class ParsedStaticList:
    """Normalized unique indicators and parsing statistics for a static list."""

    ipv4: frozenset[str]
    ipv6: frozenset[str]
    domains: frozenset[str]
    entries_read: int
    malformed_entries: int
    duplicate_entries: int

    def contains(self, target: Target) -> bool:
        """Return whether the normalized target is an exact list member."""
        indicators = {
            TargetType.IPV4: self.ipv4,
            TargetType.IPV6: self.ipv6,
            TargetType.DOMAIN: self.domains,
        }[target.type]
        return target.normalized in indicators


class StaticListParseError(ValueError):
    """A structural or decoding failure in static-list data."""

    def __init__(self, kind: ErrorKind, message: str) -> None:
        super().__init__(message)
        self.kind = kind


class _StaticListTooLargeError(OSError):
    """Raised when a bounded local read reaches beyond its configured limit."""


class _RemoteListTooLargeError(OSError):
    """Raised when a remote response exceeds its configured byte limit."""


def build_dnsbl_query(target: Target, host: str) -> str:
    """Build a traditional reverse-address DNSBL query name."""
    zone = host.strip().rstrip(".")
    if not zone:
        raise ValueError("DNSBL host must not be empty")

    if target.type is TargetType.IPV4:
        reversed_address = ".".join(reversed(target.normalized.split(".")))
    elif target.type is TargetType.IPV6:
        address = ipaddress.IPv6Address(target.normalized)
        reversed_address = ".".join(reversed(address.exploded.replace(":", "")))
    else:
        raise ValueError("traditional DNSBL queries require an IP address")
    return f"{reversed_address}.{zone}"


async def check_dnsbl(
    source: DnsblSourceConfig,
    target: Target,
    *,
    default_timeout_seconds: float,
    resolver: AsyncDnsResolver | None = None,
) -> CheckResult:
    """Check one IP target using a traditional asynchronous DNSBL query."""
    if target.type is TargetType.DOMAIN:
        return CheckResult(
            source_name=source.name,
            source_kind=source.kind,
            category=source.category,
            target=target,
            status=CheckStatus.SKIPPED,
            reason="traditional DNSBL sources do not support domain targets",
        )
    if target.type not in source.supports:
        return CheckResult(
            source_name=source.name,
            source_kind=source.kind,
            category=source.category,
            target=target,
            status=CheckStatus.SKIPPED,
            reason=f"source does not support {target.type.value} targets",
        )

    validated_default_timeout = _validate_default_timeout(default_timeout_seconds)
    timeout = (
        validated_default_timeout
        if source.timeout_seconds is None
        else source.timeout_seconds
    )
    query_name = build_dnsbl_query(target, source.host)

    try:
        active_resolver: AsyncDnsResolver = (
            resolver if resolver is not None else dns.asyncresolver.Resolver()
        )
        answer = await active_resolver.resolve(
            query_name,
            "A",
            lifetime=timeout,
            search=False,
        )
    except asyncio.CancelledError:
        raise
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return _dns_not_listed_result(source, target)
    except (dns.exception.Timeout, TimeoutError):
        return _dns_error_result(
            source,
            target,
            ErrorKind.DNS_TIMEOUT,
            "DNSBL query timed out",
        )
    except dns.resolver.NoNameservers as error:
        if _is_servfail(error):
            return _dns_error_result(
                source,
                target,
                ErrorKind.DNS_SERVFAIL,
                "DNSBL query failed with SERVFAIL",
            )
        return _dns_error_result(
            source,
            target,
            ErrorKind.DNS_RESOLUTION,
            "DNSBL resolution failed",
        )
    except (dns.exception.DNSException, OSError):
        return _dns_error_result(
            source,
            target,
            ErrorKind.DNS_RESOLUTION,
            "DNSBL resolution failed",
        )

    try:
        evidence = _extract_a_record_evidence(answer)
    except ValueError:
        return _dns_error_result(
            source,
            target,
            ErrorKind.DNS_RESOLUTION,
            "DNSBL returned an invalid A response",
        )
    if not evidence:
        return _dns_not_listed_result(source, target)
    return CheckResult(
        source_name=source.name,
        source_kind=source.kind,
        category=source.category,
        target=target,
        status=CheckStatus.LISTED,
        evidence=evidence,
    )


async def check_remote_static(
    source: RemoteStaticSourceConfig,
    target: Target,
    *,
    session: AsyncHttpSession,
    default_timeout_seconds: float,
    default_max_static_bytes: int,
) -> CheckResult:
    """Check one target against a remotely hosted static list.

    The caller owns ``session`` so a single ``aiohttp.ClientSession`` can be
    shared by all remote sources in one scan.
    """
    if target.type not in source.supports:
        return CheckResult(
            source_name=source.name,
            source_kind=source.kind,
            category=source.category,
            target=target,
            status=CheckStatus.SKIPPED,
            reason=f"source does not support {target.type.value} targets",
        )

    validated_default_timeout = _validate_default_timeout(default_timeout_seconds)
    validated_default_size = _validate_default_size(default_max_static_bytes)
    timeout = (
        validated_default_timeout
        if source.timeout_seconds is None
        else source.timeout_seconds
    )
    size_limit = (
        validated_default_size
        if source.max_static_bytes is None
        else source.max_static_bytes
    )

    try:
        request_timeout = aiohttp.ClientTimeout(total=timeout)
        async with session.get(
            source.url,
            timeout=request_timeout,
        ) as response:
            if not 200 <= response.status < 300:
                return _static_error_result(
                    source,
                    target,
                    ErrorKind.HTTP_STATUS,
                    f"remote static-list request returned HTTP {response.status}",
                )
            content = await _read_bounded_http_response(response, size_limit)
    except asyncio.CancelledError:
        raise
    except _RemoteListTooLargeError:
        return _static_error_result(
            source,
            target,
            ErrorKind.DOWNLOAD_TOO_LARGE,
            "remote static-list response exceeds the configured size limit",
        )
    except TimeoutError:
        return _static_error_result(
            source,
            target,
            ErrorKind.HTTP_TIMEOUT,
            "remote static-list request timed out",
        )
    except aiohttp.ClientConnectionError:
        return _static_error_result(
            source,
            target,
            ErrorKind.HTTP_CONNECTION,
            "remote static-list connection failed",
        )
    except aiohttp.ClientPayloadError:
        return _static_error_result(
            source,
            target,
            ErrorKind.HTTP_CONNECTION,
            "remote static-list response could not be read",
        )
    except aiohttp.ClientError:
        return _static_error_result(
            source,
            target,
            ErrorKind.HTTP_CONNECTION,
            "remote static-list request failed",
        )

    try:
        parsed = await asyncio.to_thread(parse_static_list, content, source)
    except StaticListParseError as error:
        return _static_error_result(
            source,
            target,
            error.kind,
            str(error),
        )
    return _static_match_result(source, target, parsed)


def parse_static_list(content: bytes, source: StaticSourceConfig) -> ParsedStaticList:
    """Incrementally decode and parse one bounded static-list payload."""
    newline = None if source.format is ListFormat.TXT else ""
    try:
        with io.TextIOWrapper(
            io.BytesIO(content),
            encoding=source.encoding,
            newline=newline,
        ) as lines:
            if source.format is ListFormat.TXT:
                candidates = _iter_txt_candidates(lines, source.comment_prefixes)
            else:
                if source.csv is None:
                    raise StaticListParseError(
                        ErrorKind.PARSE,
                        "CSV parsing options are missing",
                    )
                candidates = _iter_csv_candidates(
                    lines,
                    source.comment_prefixes,
                    source.csv,
                )
            return _normalize_candidates(candidates)
    except LookupError as error:
        raise StaticListParseError(
            ErrorKind.DECODE,
            f"unknown static-list encoding {source.encoding!r}",
        ) from error
    except UnicodeDecodeError as error:
        raise StaticListParseError(
            ErrorKind.DECODE,
            f"static-list data is not valid {source.encoding} text",
        ) from error


async def check_local_static(
    source: LocalStaticSourceConfig,
    target: Target,
    *,
    default_max_static_bytes: int,
) -> CheckResult:
    """Check one target against a bounded, asynchronously read local list."""
    if target.type not in source.supports:
        return CheckResult(
            source_name=source.name,
            source_kind=source.kind,
            category=source.category,
            target=target,
            status=CheckStatus.SKIPPED,
            reason=f"source does not support {target.type.value} targets",
        )

    validated_default_size = _validate_default_size(default_max_static_bytes)
    size_limit = (
        validated_default_size
        if source.max_static_bytes is None
        else source.max_static_bytes
    )

    try:
        content = await asyncio.to_thread(
            _read_bounded_local_file,
            source.path,
            size_limit,
        )
    except FileNotFoundError:
        return _static_error_result(
            source,
            target,
            ErrorKind.FILE_NOT_FOUND,
            "local static-list file was not found",
        )
    except PermissionError:
        return _static_error_result(
            source,
            target,
            ErrorKind.FILE_PERMISSION,
            "permission denied while reading local static-list file",
        )
    except _StaticListTooLargeError:
        return _static_error_result(
            source,
            target,
            ErrorKind.FILE_TOO_LARGE,
            "local static-list file exceeds the configured size limit",
        )
    except OSError:
        return _static_error_result(
            source,
            target,
            ErrorKind.FILE_READ,
            "local static-list file could not be read",
        )

    try:
        parsed = await asyncio.to_thread(parse_static_list, content, source)
    except StaticListParseError as error:
        return _static_error_result(
            source,
            target,
            error.kind,
            str(error),
        )

    return _static_match_result(source, target, parsed)


async def _read_bounded_http_response(
    response: AsyncHttpResponse,
    size_limit: int,
) -> bytes:
    if response.content_length is not None and response.content_length > size_limit:
        raise _RemoteListTooLargeError

    content = bytearray()
    while True:
        remaining = size_limit - len(content)
        chunk = await response.content.read(min(65_536, remaining + 1))
        if not chunk:
            return bytes(content)
        if len(chunk) > remaining:
            raise _RemoteListTooLargeError
        content.extend(chunk)


def _read_bounded_local_file(path: Path, size_limit: int) -> bytes:
    with path.open("rb") as static_file:
        content = static_file.read(size_limit + 1)
    if len(content) > size_limit:
        raise _StaticListTooLargeError
    return content


def _iter_txt_candidates(
    lines: Iterable[str],
    comment_prefixes: tuple[str, ...],
) -> Iterator[str]:
    for line in lines:
        stripped = line.strip()
        if not stripped or _is_comment(line, comment_prefixes):
            continue
        yield stripped


def _iter_csv_candidates(
    lines: Iterable[str],
    comment_prefixes: tuple[str, ...],
    options: CsvOptions,
) -> Iterator[str | None]:
    filtered_lines = (
        line
        for line in lines
        if line.strip() and not _is_comment(line, comment_prefixes)
    )
    reader = csv.reader(
        filtered_lines,
        delimiter=options.delimiter,
        strict=True,
    )

    try:
        if options.has_header:
            header = next(reader, None)
            if header is None:
                raise StaticListParseError(
                    ErrorKind.PARSE,
                    "CSV list does not contain a header row",
                )
            column_name = cast(str, options.column).strip()
            matching_columns = [
                index
                for index, header_value in enumerate(header)
                if header_value.strip() == column_name
            ]
            if not matching_columns:
                raise StaticListParseError(
                    ErrorKind.PARSE,
                    f"CSV header does not contain column {column_name!r}",
                )
            if len(matching_columns) > 1:
                raise StaticListParseError(
                    ErrorKind.PARSE,
                    f"CSV header contains duplicate column {column_name!r}",
                )
            column_index = matching_columns[0]
        else:
            column_index = cast(int, options.column)

        for row in reader:
            if not row or not any(value.strip() for value in row):
                continue
            if column_index >= len(row):
                yield None
                continue
            yield row[column_index].strip()
    except csv.Error as error:
        raise StaticListParseError(
            ErrorKind.PARSE,
            f"malformed CSV data: {error}",
        ) from error


def _normalize_candidates(
    candidates: Iterable[str | None],
) -> ParsedStaticList:
    indicators: dict[TargetType, set[str]] = {
        TargetType.IPV4: set(),
        TargetType.IPV6: set(),
        TargetType.DOMAIN: set(),
    }
    entries_read = 0
    malformed_entries = 0
    duplicate_entries = 0

    for candidate in candidates:
        entries_read += 1
        if candidate is None:
            malformed_entries += 1
            continue
        try:
            target = parse_target(candidate)
        except TargetValidationError:
            malformed_entries += 1
            continue

        values = indicators[target.type]
        if target.normalized in values:
            duplicate_entries += 1
        else:
            values.add(target.normalized)

    return ParsedStaticList(
        ipv4=frozenset(indicators[TargetType.IPV4]),
        ipv6=frozenset(indicators[TargetType.IPV6]),
        domains=frozenset(indicators[TargetType.DOMAIN]),
        entries_read=entries_read,
        malformed_entries=malformed_entries,
        duplicate_entries=duplicate_entries,
    )


def _is_comment(line: str, comment_prefixes: tuple[str, ...]) -> bool:
    return line.lstrip().startswith(comment_prefixes)


def _static_match_result(
    source: StaticSourceConfig,
    target: Target,
    parsed: ParsedStaticList,
) -> CheckResult:
    listed = parsed.contains(target)
    return CheckResult(
        source_name=source.name,
        source_kind=source.kind,
        category=source.category,
        target=target,
        status=CheckStatus.LISTED if listed else CheckStatus.NOT_LISTED,
        evidence=(target.normalized,) if listed else (),
        entries_read=parsed.entries_read,
        malformed_entries=parsed.malformed_entries,
        duplicate_entries=parsed.duplicate_entries,
    )


def _static_error_result(
    source: StaticSourceConfig,
    target: Target,
    kind: ErrorKind,
    message: str,
) -> CheckResult:
    return CheckResult(
        source_name=source.name,
        source_kind=source.kind,
        category=source.category,
        target=target,
        status=CheckStatus.ERROR,
        failure=CheckFailure(kind=kind, message=message),
    )


def _validate_default_timeout(value: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError("default_timeout_seconds must be a positive finite number")
    return float(value)


def _validate_default_size(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("default_max_static_bytes must be a positive integer")
    return value


def _dns_not_listed_result(
    source: DnsblSourceConfig,
    target: Target,
) -> CheckResult:
    return CheckResult(
        source_name=source.name,
        source_kind=source.kind,
        category=source.category,
        target=target,
        status=CheckStatus.NOT_LISTED,
    )


def _dns_error_result(
    source: DnsblSourceConfig,
    target: Target,
    kind: ErrorKind,
    message: str,
) -> CheckResult:
    return CheckResult(
        source_name=source.name,
        source_kind=source.kind,
        category=source.category,
        target=target,
        status=CheckStatus.ERROR,
        failure=CheckFailure(kind=kind, message=message),
    )


def _extract_a_record_evidence(
    answer: Iterable[DnsAddressRecord],
) -> tuple[str, ...]:
    evidence: list[str] = []
    seen: set[str] = set()

    for record in answer:
        try:
            address = ipaddress.IPv4Address(record.address)
        except (AttributeError, TypeError, ValueError) as error:
            raise ValueError("invalid A record") from error
        normalized = str(address)
        if normalized not in seen:
            seen.add(normalized)
            evidence.append(normalized)

    return tuple(evidence)


def _is_servfail(error: dns.resolver.NoNameservers) -> bool:
    for resolver_error in error.kwargs.get("errors", ()):
        if not isinstance(resolver_error, tuple):
            continue
        if len(resolver_error) >= 4 and str(resolver_error[3]).upper() == "SERVFAIL":
            return True
        if len(resolver_error) < 5 or resolver_error[4] is None:
            continue
        try:
            if resolver_error[4].rcode() == dns.rcode.SERVFAIL:
                return True
        except AttributeError:
            continue
    return "SERVFAIL" in str(error).upper()
