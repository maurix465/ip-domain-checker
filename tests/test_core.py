"""Tests for asynchronous scan orchestration."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

import pytest

from blacklist_checker import core
from blacklist_checker.models import (
    AppConfig,
    BlacklistSourceConfig,
    CheckResult,
    CheckStatus,
    DnsblSourceConfig,
    ErrorKind,
    ListFormat,
    LocalStaticSourceConfig,
    RemoteStaticSourceConfig,
    Target,
    TargetType,
)
from blacklist_checker.utils import parse_target


def make_local_source(
    name: str,
    *,
    supports: frozenset[TargetType] = frozenset({TargetType.DOMAIN}),
    enabled: bool = True,
) -> LocalStaticSourceConfig:
    return LocalStaticSourceConfig(
        name=name,
        category="local",
        supports=supports,
        enabled=enabled,
        path=Path(f"{name}.txt"),
        format=ListFormat.TXT,
    )


def make_remote_source(
    name: str,
    *,
    supports: frozenset[TargetType] = frozenset({TargetType.DOMAIN}),
    enabled: bool = True,
) -> RemoteStaticSourceConfig:
    return RemoteStaticSourceConfig(
        name=name,
        category="remote",
        supports=supports,
        enabled=enabled,
        url=f"https://lists.example.org/{name}.txt",
        format=ListFormat.TXT,
    )


def make_dnsbl_source(name: str = "dnsbl") -> DnsblSourceConfig:
    return DnsblSourceConfig(
        name=name,
        category="dns",
        supports=frozenset({TargetType.IPV4}),
        host="dnsbl.example.org",
    )


def not_listed_result(
    source: BlacklistSourceConfig,
    target: Target,
) -> CheckResult:
    return CheckResult(
        source_name=source.name,
        source_kind=source.kind,
        category=source.category,
        target=target,
        status=CheckStatus.NOT_LISTED,
    )


class FakeHttpSession:
    def __init__(self) -> None:
        self.entered = False
        self.closed = False
        self.exit_exception_type: type[BaseException] | None = None

    async def __aenter__(self) -> FakeHttpSession:
        self.entered = True
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        self.exit_exception_type = exc_type
        self.closed = True
        return False


class FakeHttpSessionFactory:
    def __init__(self) -> None:
        self.sessions: list[FakeHttpSession] = []

    def __call__(self) -> FakeHttpSession:
        session = FakeHttpSession()
        self.sessions.append(session)
        return session


@dataclass(frozen=True, slots=True)
class DnsCall:
    qname: str
    rdtype: str
    lifetime: float
    search: bool


class FakeResolver:
    def __init__(self) -> None:
        self.calls: list[DnsCall] = []

    async def resolve(
        self,
        qname: str,
        rdtype: str,
        *,
        lifetime: float,
        search: bool,
    ) -> tuple[()]:
        self.calls.append(
            DnsCall(
                qname=qname,
                rdtype=rdtype,
                lifetime=lifetime,
                search=search,
            )
        )
        return ()


@pytest.mark.asyncio
async def test_applicable_checks_overlap_and_results_keep_configuration_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources = tuple(make_local_source(name) for name in ("first", "second", "third"))
    target = parse_target("example.org")
    active = 0
    max_active = 0
    completion_order: list[str] = []
    yields_before_completion = {"first": 3, "second": 2, "third": 1}

    async def fake_local_check(
        source: LocalStaticSourceConfig,
        checked_target: Target,
        *,
        default_max_static_bytes: int,
    ) -> CheckResult:
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        try:
            for _ in range(yields_before_completion[source.name]):
                await asyncio.sleep(0)
            completion_order.append(source.name)
            return not_listed_result(source, checked_target)
        finally:
            active -= 1

    monkeypatch.setattr(core, "check_local_static", fake_local_check)

    results = await core.scan(target, AppConfig(sources=sources))

    assert max_active == 3
    assert completion_order == ["third", "second", "first"]
    assert [result.source_name for result in results] == [
        "first",
        "second",
        "third",
    ]


@pytest.mark.asyncio
async def test_unexpected_source_failure_does_not_cancel_siblings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failing = make_local_source("failing")
    successful = make_local_source("successful")
    target = parse_target("example.org")
    successful_completed = False

    async def fake_local_check(
        source: LocalStaticSourceConfig,
        checked_target: Target,
        *,
        default_max_static_bytes: int,
    ) -> CheckResult:
        nonlocal successful_completed
        await asyncio.sleep(0)
        if source is failing:
            raise RuntimeError("secret implementation details")
        successful_completed = True
        return not_listed_result(source, checked_target)

    monkeypatch.setattr(core, "check_local_static", fake_local_check)

    results = await core.scan(
        target,
        AppConfig(sources=(failing, successful)),
    )

    assert successful_completed
    assert results[0].status is CheckStatus.ERROR
    assert results[0].failure is not None
    assert results[0].failure.kind is ErrorKind.UNEXPECTED
    assert results[0].failure.message == "source check failed unexpectedly"
    assert "secret implementation details" not in results[0].failure.message
    assert results[1].status is CheckStatus.NOT_LISTED


@pytest.mark.asyncio
async def test_disabled_sources_are_omitted_and_unsupported_sources_are_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disabled_remote = make_remote_source("disabled", enabled=False)
    unsupported_remote = make_remote_source(
        "unsupported",
        supports=frozenset({TargetType.IPV4}),
    )
    applicable_local = make_local_source("applicable")
    target = parse_target("example.org")
    session_factory = FakeHttpSessionFactory()
    executed: list[str] = []

    async def fail_if_remote_runs(*args: object, **kwargs: object) -> CheckResult:
        raise AssertionError("unsupported or disabled remote source was executed")

    async def fake_local_check(
        source: LocalStaticSourceConfig,
        checked_target: Target,
        *,
        default_max_static_bytes: int,
    ) -> CheckResult:
        executed.append(source.name)
        return not_listed_result(source, checked_target)

    monkeypatch.setattr(core, "check_remote_static", fail_if_remote_runs)
    monkeypatch.setattr(core, "check_local_static", fake_local_check)

    results = await core.scan(
        target,
        AppConfig(
            sources=(disabled_remote, unsupported_remote, applicable_local),
        ),
        http_session_factory=session_factory,
    )

    assert [result.source_name for result in results] == [
        "unsupported",
        "applicable",
    ]
    assert results[0].status is CheckStatus.SKIPPED
    assert results[0].reason == "source does not support domain targets"
    assert results[1].status is CheckStatus.NOT_LISTED
    assert executed == ["applicable"]
    assert session_factory.sessions == []


@pytest.mark.asyncio
async def test_one_http_session_is_shared_and_closed_after_source_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = make_remote_source("first")
    second = make_remote_source("second")
    target = parse_target("example.org")
    session_factory = FakeHttpSessionFactory()
    received_sessions: list[object] = []

    async def fake_remote_check(
        source: RemoteStaticSourceConfig,
        checked_target: Target,
        *,
        session: object,
        default_timeout_seconds: float,
        default_max_static_bytes: int,
    ) -> CheckResult:
        received_sessions.append(session)
        if source is first:
            raise RuntimeError("first remote failed")
        return not_listed_result(source, checked_target)

    monkeypatch.setattr(core, "check_remote_static", fake_remote_check)

    results = await core.scan(
        target,
        AppConfig(sources=(first, second)),
        http_session_factory=session_factory,
    )

    assert len(session_factory.sessions) == 1
    session = session_factory.sessions[0]
    assert session.entered
    assert session.closed
    assert received_sessions == [session, session]
    assert results[0].status is CheckStatus.ERROR
    assert results[0].failure is not None
    assert results[0].failure.kind is ErrorKind.UNEXPECTED
    assert results[1].status is CheckStatus.NOT_LISTED


@pytest.mark.asyncio
async def test_http_session_initialization_failure_isolated_from_other_sources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    remote = make_remote_source(
        "remote",
        supports=frozenset({TargetType.IPV4}),
    )
    dnsbl = make_dnsbl_source()
    local = make_local_source(
        "local",
        supports=frozenset({TargetType.IPV4}),
    )
    target = parse_target("192.0.2.45")
    resolver = FakeResolver()
    local_executed = False

    async def fail_if_remote_runs(*args: object, **kwargs: object) -> CheckResult:
        raise AssertionError("remote checker must not run without a session")

    async def fake_local_check(
        source: LocalStaticSourceConfig,
        checked_target: Target,
        *,
        default_max_static_bytes: int,
    ) -> CheckResult:
        nonlocal local_executed
        local_executed = True
        return not_listed_result(source, checked_target)

    def fail_session_factory() -> FakeHttpSession:
        raise OSError("session initialization failed")

    monkeypatch.setattr(core, "check_remote_static", fail_if_remote_runs)
    monkeypatch.setattr(core, "check_local_static", fake_local_check)

    results = await core.scan(
        target,
        AppConfig(sources=(remote, dnsbl, local)),
        resolver=resolver,
        http_session_factory=fail_session_factory,
    )

    assert [result.source_name for result in results] == ["remote", "dnsbl", "local"]
    assert results[0].status is CheckStatus.ERROR
    assert results[0].failure is not None
    assert results[0].failure.kind is ErrorKind.HTTP_CONNECTION
    assert results[0].failure.message == (
        "HTTP client session could not be initialized"
    )
    assert results[1].status is CheckStatus.NOT_LISTED
    assert results[2].status is CheckStatus.NOT_LISTED
    assert resolver.calls
    assert local_executed


@pytest.mark.asyncio
async def test_http_session_initialization_preserves_caller_cancellation() -> None:
    def cancel_session_factory() -> FakeHttpSession:
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await core.scan(
            parse_target("example.org"),
            AppConfig(sources=(make_remote_source("remote"),)),
            http_session_factory=cancel_session_factory,
        )


@pytest.mark.asyncio
async def test_injected_dns_resolver_is_passed_to_dnsbl_checker() -> None:
    target = parse_target("192.0.2.45")
    resolver = FakeResolver()

    results = await core.scan(
        target,
        AppConfig(sources=(make_dnsbl_source(),), dns_timeout_seconds=2.5),
        resolver=resolver,
    )

    assert results[0].status is CheckStatus.NOT_LISTED
    assert resolver.calls == [
        DnsCall(
            qname="45.2.0.192.dnsbl.example.org",
            rdtype="A",
            lifetime=2.5,
            search=False,
        )
    ]


@pytest.mark.asyncio
async def test_caller_cancellation_propagates_and_closes_http_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = make_remote_source("blocking")
    target = parse_target("example.org")
    session_factory = FakeHttpSessionFactory()
    started = asyncio.Event()
    checker_cancelled = asyncio.Event()

    async def blocking_remote_check(
        source: RemoteStaticSourceConfig,
        checked_target: Target,
        *,
        session: object,
        default_timeout_seconds: float,
        default_max_static_bytes: int,
    ) -> CheckResult:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            checker_cancelled.set()
        return not_listed_result(source, checked_target)

    monkeypatch.setattr(core, "check_remote_static", blocking_remote_check)
    scan_task = asyncio.create_task(
        core.scan(
            target,
            AppConfig(sources=(source,)),
            http_session_factory=session_factory,
        )
    )
    await started.wait()

    scan_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await scan_task
    assert checker_cancelled.is_set()
    assert len(session_factory.sessions) == 1
    session = session_factory.sessions[0]
    assert session.closed
    assert session.exit_exception_type is asyncio.CancelledError
