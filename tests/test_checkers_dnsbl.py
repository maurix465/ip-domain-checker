"""Tests for traditional IP DNSBL checks."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import dns.exception
import dns.message
import dns.rcode
import dns.resolver
import pytest

from blacklist_checker import checkers
from blacklist_checker.checkers import build_dnsbl_query, check_dnsbl
from blacklist_checker.models import (
    CheckResult,
    CheckStatus,
    DnsblSourceConfig,
    ErrorKind,
    TargetType,
)
from blacklist_checker.utils import parse_target


@dataclass(frozen=True, slots=True)
class FakeARecord:
    address: str


@dataclass(frozen=True, slots=True)
class ResolveCall:
    qname: str
    rdtype: str
    lifetime: float
    search: bool


class FakeResolver:
    def __init__(
        self,
        records: tuple[FakeARecord, ...] = (),
        *,
        error: BaseException | None = None,
    ) -> None:
        self.records = records
        self.error = error
        self.calls: list[ResolveCall] = []

    async def resolve(
        self,
        qname: str,
        rdtype: str,
        *,
        lifetime: float,
        search: bool,
    ) -> tuple[FakeARecord, ...]:
        self.calls.append(
            ResolveCall(
                qname=qname,
                rdtype=rdtype,
                lifetime=lifetime,
                search=search,
            )
        )
        if self.error is not None:
            raise self.error
        return self.records


def make_dnsbl_source(
    *,
    supports: frozenset[TargetType] = frozenset({TargetType.IPV4, TargetType.IPV6}),
    timeout_seconds: float | None = None,
) -> DnsblSourceConfig:
    return DnsblSourceConfig(
        name="test-dnsbl",
        category="reputation",
        supports=supports,
        host="dnsbl.example.org",
        timeout_seconds=timeout_seconds,
    )


async def run_dnsbl_check(
    target: str,
    resolver: FakeResolver,
    *,
    source: DnsblSourceConfig | None = None,
    default_timeout_seconds: float = 5.0,
) -> CheckResult:
    return await check_dnsbl(
        source or make_dnsbl_source(),
        parse_target(target),
        default_timeout_seconds=default_timeout_seconds,
        resolver=resolver,
    )


def assert_error(result: CheckResult, kind: ErrorKind) -> None:
    assert result.status is CheckStatus.ERROR
    assert result.failure is not None
    assert result.failure.kind is kind


def test_builds_ipv4_reverse_octet_query() -> None:
    query = build_dnsbl_query(parse_target("192.0.2.45"), "dnsbl.example.org.")

    assert query == "45.2.0.192.dnsbl.example.org"


def test_builds_ipv6_reverse_nibble_query() -> None:
    query = build_dnsbl_query(parse_target("2001:db8::1"), "dnsbl.example.org")

    assert query == (
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0."
        "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.dnsbl.example.org"
    )


def test_query_builder_rejects_domain_targets() -> None:
    with pytest.raises(ValueError, match="require an IP address"):
        build_dnsbl_query(parse_target("example.org"), "dnsbl.example.org")


@pytest.mark.asyncio
async def test_valid_a_response_is_listed_with_deduplicated_evidence() -> None:
    resolver = FakeResolver(
        (
            FakeARecord("127.0.0.2"),
            FakeARecord("127.0.0.3"),
            FakeARecord("127.0.0.2"),
        )
    )

    result = await run_dnsbl_check("192.0.2.45", resolver)

    assert result.status is CheckStatus.LISTED
    assert result.evidence == ("127.0.0.2", "127.0.0.3")
    assert resolver.calls == [
        ResolveCall(
            qname="45.2.0.192.dnsbl.example.org",
            rdtype="A",
            lifetime=5.0,
            search=False,
        )
    ]


@pytest.mark.asyncio
async def test_ipv6_check_uses_reverse_nibble_query() -> None:
    resolver = FakeResolver((FakeARecord("127.0.0.2"),))

    result = await run_dnsbl_check("2001:db8::1", resolver)

    assert result.status is CheckStatus.LISTED
    assert resolver.calls[0].qname == (
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0."
        "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.dnsbl.example.org"
    )


@pytest.mark.asyncio
async def test_source_timeout_override_is_applied() -> None:
    resolver = FakeResolver()
    source = make_dnsbl_source(timeout_seconds=1.25)

    result = await run_dnsbl_check(
        "192.0.2.45",
        resolver,
        source=source,
        default_timeout_seconds=9.0,
    )

    assert result.status is CheckStatus.NOT_LISTED
    assert resolver.calls[0].lifetime == 1.25


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer()],
    ids=["nxdomain", "no-answer"],
)
async def test_negative_dns_answers_are_not_listed(error: BaseException) -> None:
    result = await run_dnsbl_check(
        "192.0.2.45",
        FakeResolver(error=error),
    )

    assert result.status is CheckStatus.NOT_LISTED
    assert result.evidence == ()
    assert result.failure is None


@pytest.mark.asyncio
async def test_empty_a_answer_is_not_listed() -> None:
    result = await run_dnsbl_check("192.0.2.45", FakeResolver())

    assert result.status is CheckStatus.NOT_LISTED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [dns.exception.Timeout(), TimeoutError()],
    ids=["dns-timeout", "builtin-timeout"],
)
async def test_timeout_is_a_structured_error(error: BaseException) -> None:
    result = await run_dnsbl_check(
        "192.0.2.45",
        FakeResolver(error=error),
    )

    assert_error(result, ErrorKind.DNS_TIMEOUT)
    assert result.failure is not None
    assert result.failure.message == "DNSBL query timed out"


@pytest.mark.asyncio
async def test_servfail_is_a_structured_error() -> None:
    query = dns.message.make_query("45.2.0.192.dnsbl.example.org", "A")
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.SERVFAIL)
    error = dns.resolver.NoNameservers(
        request=query,
        errors=[("127.0.0.1", False, 53, "SERVFAIL", response)],
    )

    result = await run_dnsbl_check(
        "192.0.2.45",
        FakeResolver(error=error),
    )

    assert_error(result, ErrorKind.DNS_SERVFAIL)
    assert result.failure is not None
    assert result.failure.message == "DNSBL query failed with SERVFAIL"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        dns.resolver.NoNameservers(),
        dns.exception.FormError(),
        OSError("resolver unavailable"),
    ],
    ids=["no-nameservers", "malformed-dns", "operating-system"],
)
async def test_resolver_failures_are_structured_errors(
    error: BaseException,
) -> None:
    result = await run_dnsbl_check(
        "192.0.2.45",
        FakeResolver(error=error),
    )

    assert_error(result, ErrorKind.DNS_RESOLUTION)
    assert result.failure is not None
    assert result.failure.message == "DNSBL resolution failed"


@pytest.mark.asyncio
async def test_resolver_initialization_failure_is_structured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_to_create_resolver() -> None:
        raise dns.resolver.NoResolverConfiguration

    monkeypatch.setattr(
        checkers.dns.asyncresolver,
        "Resolver",
        fail_to_create_resolver,
    )

    result = await check_dnsbl(
        make_dnsbl_source(),
        parse_target("192.0.2.45"),
        default_timeout_seconds=5.0,
    )

    assert_error(result, ErrorKind.DNS_RESOLUTION)


@pytest.mark.asyncio
async def test_invalid_a_response_is_a_structured_error() -> None:
    result = await run_dnsbl_check(
        "192.0.2.45",
        FakeResolver((FakeARecord("2001:db8::1"),)),
    )

    assert_error(result, ErrorKind.DNS_RESOLUTION)
    assert result.failure is not None
    assert result.failure.message == "DNSBL returned an invalid A response"


@pytest.mark.asyncio
async def test_domain_target_is_skipped_without_dns_query() -> None:
    resolver = FakeResolver((FakeARecord("127.0.0.2"),))

    result = await run_dnsbl_check("example.org", resolver)

    assert result.status is CheckStatus.SKIPPED
    assert result.reason == "traditional DNSBL sources do not support domain targets"
    assert resolver.calls == []


@pytest.mark.asyncio
async def test_unsupported_ip_type_is_skipped_without_dns_query() -> None:
    resolver = FakeResolver((FakeARecord("127.0.0.2"),))
    source = make_dnsbl_source(supports=frozenset({TargetType.IPV4}))

    result = await run_dnsbl_check("2001:db8::1", resolver, source=source)

    assert result.status is CheckStatus.SKIPPED
    assert result.reason == "source does not support ipv6 targets"
    assert resolver.calls == []


@pytest.mark.asyncio
async def test_caller_cancellation_is_preserved() -> None:
    resolver = FakeResolver(error=asyncio.CancelledError())

    with pytest.raises(asyncio.CancelledError):
        await run_dnsbl_check("192.0.2.45", resolver)


@pytest.mark.asyncio
@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), True])
async def test_invalid_default_timeout_is_rejected(timeout: float) -> None:
    resolver = FakeResolver()

    with pytest.raises(ValueError, match="positive finite number"):
        await run_dnsbl_check(
            "192.0.2.45",
            resolver,
            default_timeout_seconds=timeout,
        )

    assert resolver.calls == []
