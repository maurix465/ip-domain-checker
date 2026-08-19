"""Tests for remote HTTP static-list checks."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from dataclasses import dataclass
from types import TracebackType

import aiohttp
import pytest

from blacklist_checker import checkers
from blacklist_checker.checkers import check_remote_static
from blacklist_checker.models import (
    CheckResult,
    CheckStatus,
    CsvOptions,
    ErrorKind,
    ListFormat,
    RemoteStaticSourceConfig,
    TargetType,
)
from blacklist_checker.utils import parse_target


class FakeResponseStream:
    def __init__(
        self,
        body: bytes,
        *,
        error: BaseException | None = None,
    ) -> None:
        self.body = body
        self.error = error
        self.offset = 0
        self.read_sizes: list[int] = []

    async def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        if self.error is not None:
            raise self.error
        if self.offset >= len(self.body):
            return b""
        if size < 0:
            size = len(self.body) - self.offset
        chunk = self.body[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk


class FakeResponse:
    def __init__(
        self,
        body: bytes = b"",
        *,
        status: int = 200,
        content_length: int | None = None,
        enter_error: BaseException | None = None,
        read_error: BaseException | None = None,
    ) -> None:
        self.status = status
        self.content_length = content_length
        self.content = FakeResponseStream(body, error=read_error)
        self.enter_error = enter_error
        self.entered = False
        self.exited = False

    async def __aenter__(self) -> FakeResponse:
        self.entered = True
        if self.enter_error is not None:
            raise self.enter_error
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        self.exited = True
        return False


@dataclass(frozen=True, slots=True)
class RequestCall:
    url: str
    timeout: aiohttp.ClientTimeout


class FakeSession:
    def __init__(
        self,
        responses: list[FakeResponse] | None = None,
        *,
        error: BaseException | None = None,
    ) -> None:
        self.responses = [] if responses is None else responses
        self.error = error
        self.calls: list[RequestCall] = []

    def get(
        self,
        url: str,
        *,
        timeout: aiohttp.ClientTimeout,
    ) -> FakeResponse:
        self.calls.append(RequestCall(url=url, timeout=timeout))
        if self.error is not None:
            raise self.error
        if not self.responses:
            raise AssertionError("fake session has no response configured")
        return self.responses.pop(0)


def make_remote_source(
    *,
    supports: frozenset[TargetType] = frozenset(
        {TargetType.IPV4, TargetType.IPV6, TargetType.DOMAIN}
    ),
    list_format: ListFormat = ListFormat.TXT,
    encoding: str = "utf-8-sig",
    comment_prefixes: tuple[str, ...] = ("#", ";"),
    csv_options: CsvOptions | None = None,
    timeout_seconds: float | None = None,
    max_static_bytes: int | None = None,
) -> RemoteStaticSourceConfig:
    return RemoteStaticSourceConfig(
        name="remote-test",
        category="reputation",
        supports=supports,
        url="https://lists.example.org/indicators.txt",
        format=list_format,
        encoding=encoding,
        comment_prefixes=comment_prefixes,
        csv=csv_options,
        timeout_seconds=timeout_seconds,
        max_static_bytes=max_static_bytes,
    )


async def run_remote_check(
    session: FakeSession,
    target: str = "example.org",
    *,
    source: RemoteStaticSourceConfig | None = None,
    default_timeout_seconds: float = 15.0,
    default_max_static_bytes: int = 10_485_760,
) -> CheckResult:
    return await check_remote_static(
        source or make_remote_source(),
        parse_target(target),
        session=session,
        default_timeout_seconds=default_timeout_seconds,
        default_max_static_bytes=default_max_static_bytes,
    )


def assert_error(result: CheckResult, kind: ErrorKind) -> None:
    assert result.status is CheckStatus.ERROR
    assert result.failure is not None
    assert result.failure.kind is kind


@pytest.mark.asyncio
async def test_txt_response_is_parsed_normalized_and_matched_exactly() -> None:
    response = FakeResponse(b"# comment\nEXAMPLE.ORG.\nexample.org\nnot an indicator\n")
    session = FakeSession([response])

    result = await run_remote_check(session)

    assert result.status is CheckStatus.LISTED
    assert result.evidence == ("example.org",)
    assert result.entries_read == 3
    assert result.malformed_entries == 1
    assert result.duplicate_entries == 1
    assert response.entered
    assert response.exited


@pytest.mark.asyncio
async def test_remote_parsing_is_dispatched_through_asyncio_to_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = b"example.org\n"
    source = make_remote_source()
    calls: list[tuple[Callable[..., object], tuple[object, ...]]] = []

    async def fake_to_thread(
        function: Callable[..., object],
        *args: object,
    ) -> object:
        calls.append((function, args))
        return function(*args)

    monkeypatch.setattr(checkers.asyncio, "to_thread", fake_to_thread)

    result = await run_remote_check(
        FakeSession([FakeResponse(body)]),
        source=source,
    )

    assert result.status is CheckStatus.LISTED
    assert calls == [(checkers.parse_static_list, (body, source))]


@pytest.mark.asyncio
@pytest.mark.parametrize("list_format", [ListFormat.TXT, ListFormat.CSV])
async def test_large_remote_parse_does_not_block_event_loop_heartbeat(
    monkeypatch: pytest.MonkeyPatch,
    list_format: ListFormat,
) -> None:
    row_count = 50_000
    if list_format is ListFormat.TXT:
        body = b"example.org\n" * row_count
        source = make_remote_source()
    else:
        body = b"indicator\n" + b"example.org\n" * row_count
        source = make_remote_source(
            list_format=ListFormat.CSV,
            csv_options=CsvOptions(has_header=True, column="indicator"),
        )
    parse_started = threading.Event()
    release_parse = threading.Event()
    heartbeat_ran = asyncio.Event()
    original_parse = checkers.parse_static_list

    def gated_parse(
        content: bytes,
        source: RemoteStaticSourceConfig,
    ) -> checkers.ParsedStaticList:
        parse_started.set()
        if not release_parse.wait(timeout=2):
            raise AssertionError("event loop did not run while parsing")
        return original_parse(content, source)

    async def heartbeat() -> None:
        while not parse_started.is_set():
            await asyncio.sleep(0)
        heartbeat_ran.set()
        release_parse.set()

    monkeypatch.setattr(checkers, "parse_static_list", gated_parse)
    heartbeat_task = asyncio.create_task(heartbeat())

    result = await asyncio.wait_for(
        run_remote_check(
            FakeSession([FakeResponse(body)]),
            source=source,
        ),
        timeout=5,
    )
    await heartbeat_task

    assert heartbeat_ran.is_set()
    assert result.status is CheckStatus.LISTED
    assert result.entries_read == row_count
    assert result.duplicate_entries == row_count - 1


@pytest.mark.asyncio
async def test_remote_matching_does_not_use_substrings() -> None:
    session = FakeSession([FakeResponse(b"sub.example.org\n")])

    result = await run_remote_check(session)

    assert result.status is CheckStatus.NOT_LISTED
    assert result.evidence == ()


@pytest.mark.asyncio
async def test_csv_response_uses_configured_column_delimiter_and_encoding() -> None:
    body = "description;indicator\naccented;bücher.example\n".encode("latin-1")
    source = make_remote_source(
        list_format=ListFormat.CSV,
        encoding="latin-1",
        csv_options=CsvOptions(
            has_header=True,
            column="indicator",
            delimiter=";",
        ),
    )
    session = FakeSession([FakeResponse(body)])

    result = await run_remote_check(
        session,
        "xn--bcher-kva.example",
        source=source,
    )

    assert result.status is CheckStatus.LISTED
    assert result.evidence == ("xn--bcher-kva.example",)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [301, 404, 503])
async def test_non_success_status_is_structured_without_reading_body(
    status: int,
) -> None:
    secret_body = b"secret response body"
    response = FakeResponse(secret_body, status=status)
    session = FakeSession([response])

    result = await run_remote_check(session)

    assert_error(result, ErrorKind.HTTP_STATUS)
    assert result.failure is not None
    assert result.failure.message == (
        f"remote static-list request returned HTTP {status}"
    )
    assert "secret response body" not in result.failure.message
    assert response.content.read_sizes == []


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_stage", ["request", "response", "body"])
async def test_timeout_at_any_request_stage_is_structured(
    failure_stage: str,
) -> None:
    timeout = TimeoutError("secret response body")
    if failure_stage == "request":
        session = FakeSession(error=timeout)
    elif failure_stage == "response":
        session = FakeSession([FakeResponse(enter_error=timeout)])
    else:
        session = FakeSession([FakeResponse(read_error=timeout)])

    result = await run_remote_check(session)

    assert_error(result, ErrorKind.HTTP_TIMEOUT)
    assert result.failure is not None
    assert result.failure.message == "remote static-list request timed out"
    assert "secret response body" not in result.failure.message


@pytest.mark.asyncio
async def test_connection_failure_is_structured_without_exception_details() -> None:
    session = FakeSession(error=aiohttp.ClientConnectionError("secret response body"))

    result = await run_remote_check(session)

    assert_error(result, ErrorKind.HTTP_CONNECTION)
    assert result.failure is not None
    assert result.failure.message == "remote static-list connection failed"
    assert "secret response body" not in result.failure.message


@pytest.mark.asyncio
async def test_payload_failure_is_structured_without_exception_details() -> None:
    response = FakeResponse(
        read_error=aiohttp.ClientPayloadError("secret response body")
    )

    result = await run_remote_check(FakeSession([response]))

    assert_error(result, ErrorKind.HTTP_CONNECTION)
    assert result.failure is not None
    assert result.failure.message == "remote static-list response could not be read"
    assert "secret response body" not in result.failure.message


@pytest.mark.asyncio
async def test_other_aiohttp_failure_is_structured() -> None:
    result = await run_remote_check(
        FakeSession(error=aiohttp.ClientError("request setup failed"))
    )

    assert_error(result, ErrorKind.HTTP_CONNECTION)
    assert result.failure is not None
    assert result.failure.message == "remote static-list request failed"


@pytest.mark.asyncio
async def test_declared_oversized_response_is_rejected_before_body_read() -> None:
    response = FakeResponse(
        b"invalid text that must not be decoded",
        content_length=100,
    )

    result = await run_remote_check(
        FakeSession([response]),
        default_max_static_bytes=10,
    )

    assert_error(result, ErrorKind.DOWNLOAD_TOO_LARGE)
    assert response.content.read_sizes == []
    assert response.exited


@pytest.mark.asyncio
@pytest.mark.parametrize("declared_length", [None, 1])
async def test_streamed_oversized_response_is_rejected_with_untrusted_length(
    declared_length: int | None,
) -> None:
    response = FakeResponse(b"123456", content_length=declared_length)

    result = await run_remote_check(
        FakeSession([response]),
        default_max_static_bytes=5,
    )

    assert_error(result, ErrorKind.DOWNLOAD_TOO_LARGE)
    assert response.content.read_sizes == [6]
    assert response.exited


@pytest.mark.asyncio
async def test_response_exactly_at_size_limit_is_accepted() -> None:
    body = b"example.org\n"
    response = FakeResponse(body, content_length=len(body))

    result = await run_remote_check(
        FakeSession([response]),
        default_max_static_bytes=len(body),
    )

    assert result.status is CheckStatus.LISTED
    assert response.content.read_sizes == [len(body) + 1, 1]


@pytest.mark.asyncio
async def test_source_size_override_takes_precedence() -> None:
    body = b"example.org\n"
    source = make_remote_source(max_static_bytes=len(body))

    result = await run_remote_check(
        FakeSession([FakeResponse(body)]),
        source=source,
        default_max_static_bytes=1,
    )

    assert result.status is CheckStatus.LISTED


@pytest.mark.asyncio
async def test_shared_session_and_timeouts_are_used_for_multiple_checks() -> None:
    session = FakeSession(
        [
            FakeResponse(b"example.org\n"),
            FakeResponse(b"example.org\n"),
        ]
    )

    first = await run_remote_check(
        session,
        default_timeout_seconds=8.0,
    )
    second = await run_remote_check(
        session,
        source=make_remote_source(timeout_seconds=1.25),
        default_timeout_seconds=8.0,
    )

    assert first.status is CheckStatus.LISTED
    assert second.status is CheckStatus.LISTED
    assert [call.url for call in session.calls] == [
        "https://lists.example.org/indicators.txt",
        "https://lists.example.org/indicators.txt",
    ]
    assert [call.timeout.total for call in session.calls] == [8.0, 1.25]


@pytest.mark.asyncio
async def test_invalid_encoding_returns_decode_error_without_body_content() -> None:
    response = FakeResponse(b"example.org\xffsecret response body")

    result = await run_remote_check(FakeSession([response]))

    assert_error(result, ErrorKind.DECODE)
    assert result.failure is not None
    assert result.failure.message == ("static-list data is not valid utf-8-sig text")
    assert "secret response body" not in result.failure.message


@pytest.mark.asyncio
async def test_malformed_csv_returns_parse_error_without_body_content() -> None:
    secret_body = b'indicator\n"secret response body\n'
    source = make_remote_source(
        list_format=ListFormat.CSV,
        csv_options=CsvOptions(has_header=True, column="indicator"),
    )

    result = await run_remote_check(
        FakeSession([FakeResponse(secret_body)]),
        source=source,
    )

    assert_error(result, ErrorKind.PARSE)
    assert result.failure is not None
    assert "secret response body" not in result.failure.message


@pytest.mark.asyncio
async def test_unsupported_target_is_skipped_without_http_request() -> None:
    source = make_remote_source(supports=frozenset({TargetType.IPV4}))
    session = FakeSession()

    result = await run_remote_check(session, source=source)

    assert result.status is CheckStatus.SKIPPED
    assert result.reason == "source does not support domain targets"
    assert session.calls == []


@pytest.mark.asyncio
async def test_caller_cancellation_is_preserved() -> None:
    session = FakeSession([FakeResponse(read_error=asyncio.CancelledError())])

    with pytest.raises(asyncio.CancelledError):
        await run_remote_check(session)


@pytest.mark.asyncio
@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), True])
async def test_invalid_default_timeout_is_rejected(timeout: float) -> None:
    session = FakeSession()

    with pytest.raises(ValueError, match="positive finite number"):
        await run_remote_check(session, default_timeout_seconds=timeout)

    assert session.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("size_limit", [0, -1, 1.5, True])
async def test_invalid_default_size_limit_is_rejected(size_limit: int) -> None:
    session = FakeSession()

    with pytest.raises(ValueError, match="positive integer"):
        await run_remote_check(session, default_max_static_bytes=size_limit)

    assert session.calls == []
