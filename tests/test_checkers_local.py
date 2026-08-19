"""Tests for shared static-list parsing and local-list checks."""

from __future__ import annotations

import tracemalloc
from collections.abc import Callable
from pathlib import Path

import pytest

from blacklist_checker import checkers
from blacklist_checker.checkers import check_local_static, parse_static_list
from blacklist_checker.models import (
    CheckResult,
    CheckStatus,
    CsvOptions,
    ErrorKind,
    ListFormat,
    LocalStaticSourceConfig,
    RemoteStaticSourceConfig,
    Target,
    TargetType,
)
from blacklist_checker.utils import parse_target


def make_local_source(
    path: Path,
    *,
    supports: frozenset[TargetType] = frozenset(
        {TargetType.IPV4, TargetType.IPV6, TargetType.DOMAIN}
    ),
    list_format: ListFormat = ListFormat.TXT,
    encoding: str = "utf-8-sig",
    comment_prefixes: tuple[str, ...] = ("#", ";"),
    csv_options: CsvOptions | None = None,
    max_static_bytes: int | None = None,
) -> LocalStaticSourceConfig:
    return LocalStaticSourceConfig(
        name="local-test",
        category="test",
        supports=supports,
        path=path,
        format=list_format,
        encoding=encoding,
        comment_prefixes=comment_prefixes,
        csv=csv_options,
        max_static_bytes=max_static_bytes,
    )


async def run_local_check(
    source: LocalStaticSourceConfig,
    target: str,
    *,
    default_max_static_bytes: int = 10_485_760,
) -> CheckResult:
    return await check_local_static(
        source,
        parse_target(target),
        default_max_static_bytes=default_max_static_bytes,
    )


def assert_error(result: CheckResult, kind: ErrorKind) -> None:
    assert result.status is CheckStatus.ERROR
    assert result.failure is not None
    assert result.failure.kind is kind


@pytest.mark.asyncio
async def test_txt_list_normalizes_deduplicates_and_counts(tmp_path: Path) -> None:
    list_path = tmp_path / "indicators.txt"
    list_path.write_text(
        """
        # comment
        ; another comment

        EXAMPLE.COM.
        example.com
        192.0.2.1
        2001:0db8::1
        not an indicator
        """,
        encoding="utf-8",
    )

    result = await run_local_check(make_local_source(list_path), "example.com")

    assert result.status is CheckStatus.LISTED
    assert result.evidence == ("example.com",)
    assert result.entries_read == 5
    assert result.malformed_entries == 1
    assert result.duplicate_entries == 1


@pytest.mark.asyncio
async def test_txt_list_uses_configured_comment_prefixes(tmp_path: Path) -> None:
    list_path = tmp_path / "indicators.txt"
    list_path.write_text(
        "// ignored.example\nexample.com\n",
        encoding="utf-8",
    )
    source = make_local_source(list_path, comment_prefixes=("//",))

    result = await run_local_check(source, "example.com")

    assert result.status is CheckStatus.LISTED
    assert result.entries_read == 1
    assert result.malformed_entries == 0


@pytest.mark.asyncio
async def test_domain_matching_is_exact_not_substring_based(tmp_path: Path) -> None:
    list_path = tmp_path / "domains.txt"
    list_path.write_text("sub.example.com\n", encoding="utf-8")

    result = await run_local_check(make_local_source(list_path), "example.com")

    assert result.status is CheckStatus.NOT_LISTED
    assert result.evidence == ()


@pytest.mark.asyncio
async def test_ip_network_is_malformed_not_a_substring_match(tmp_path: Path) -> None:
    list_path = tmp_path / "addresses.txt"
    list_path.write_text("192.0.2.0/24\n", encoding="utf-8")

    result = await run_local_check(make_local_source(list_path), "192.0.2.1")

    assert result.status is CheckStatus.NOT_LISTED
    assert result.malformed_entries == 1


@pytest.mark.asyncio
async def test_txt_list_uses_configured_encoding(tmp_path: Path) -> None:
    list_path = tmp_path / "domains.txt"
    list_path.write_bytes("bücher.example\n".encode("latin-1"))
    source = make_local_source(list_path, encoding="latin-1")

    result = await run_local_check(source, "xn--bcher-kva.example")

    assert result.status is CheckStatus.LISTED
    assert result.evidence == ("xn--bcher-kva.example",)


@pytest.mark.asyncio
async def test_empty_txt_list_is_valid_and_not_listed(tmp_path: Path) -> None:
    list_path = tmp_path / "empty.txt"
    list_path.write_text("# comment only\n\n", encoding="utf-8")

    result = await run_local_check(make_local_source(list_path), "example.com")

    assert result.status is CheckStatus.NOT_LISTED
    assert result.entries_read == 0


def test_duplicate_heavy_txt_parse_has_bounded_memory_amplification() -> None:
    source = make_local_source(Path("unused.txt"))

    tracemalloc.start()
    try:
        content = b"a.b\n" * 100_000
        parsed = parse_static_list(content, source)
        _, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert parsed.entries_read == 100_000
    assert parsed.domains == frozenset({"a.b"})
    assert parsed.duplicate_entries == 99_999
    assert peak_bytes < len(content) * 3


@pytest.mark.asyncio
async def test_csv_header_selects_configured_column_and_counts_rows(
    tmp_path: Path,
) -> None:
    list_path = tmp_path / "indicators.csv"
    list_path.write_text(
        """# comment
description,indicator
first,EXAMPLE.COM.
duplicate,example.com
missing-column
invalid,not_an_indicator
address,192.0.2.1
""",
        encoding="utf-8",
    )
    source = make_local_source(
        list_path,
        list_format=ListFormat.CSV,
        csv_options=CsvOptions(has_header=True, column="indicator"),
    )

    result = await run_local_check(source, "example.com")

    assert result.status is CheckStatus.LISTED
    assert result.entries_read == 5
    assert result.malformed_entries == 2
    assert result.duplicate_entries == 1


@pytest.mark.asyncio
async def test_headerless_csv_selects_numeric_column(tmp_path: Path) -> None:
    list_path = tmp_path / "indicators.csv"
    list_path.write_text(
        "note;192.0.2.1\nmissing-column\nnote;\n",
        encoding="utf-8",
    )
    source = make_local_source(
        list_path,
        list_format=ListFormat.CSV,
        csv_options=CsvOptions(has_header=False, column=1, delimiter=";"),
    )

    result = await run_local_check(source, "192.0.2.1")

    assert result.status is CheckStatus.LISTED
    assert result.entries_read == 3
    assert result.malformed_entries == 2


def test_large_duplicate_heavy_csv_is_parsed_incrementally() -> None:
    row_count = 50_000
    content = b"description,indicator\n" + b"note,example.org\n" * row_count
    source = make_local_source(
        Path("unused.csv"),
        list_format=ListFormat.CSV,
        csv_options=CsvOptions(has_header=True, column="indicator"),
    )

    parsed = parse_static_list(content, source)

    assert parsed.entries_read == row_count
    assert parsed.domains == frozenset({"example.org"})
    assert parsed.malformed_entries == 0
    assert parsed.duplicate_entries == row_count - 1


def test_csv_preserves_quoted_multiline_fields() -> None:
    content = (
        b"description,indicator\r\n"
        b'"first line, with delimiter\r\nsecond line",EXAMPLE.ORG.\r\n'
    )
    source = make_local_source(
        Path("unused.csv"),
        list_format=ListFormat.CSV,
        csv_options=CsvOptions(has_header=True, column="indicator"),
    )

    parsed = parse_static_list(content, source)

    assert parsed.domains == frozenset({"example.org"})
    assert parsed.entries_read == 1
    assert parsed.malformed_entries == 0


@pytest.mark.parametrize(
    "continuation_line",
    ["# continuation", ";; continuation", ""],
    ids=["hash", "double-semicolon", "blank"],
)
def test_csv_preserves_comment_like_multiline_continuations(
    continuation_line: str,
) -> None:
    lines = [
        "description,indicator\r\n",
        '"first line\r\n',
        f"{continuation_line}\r\n",
        'last line",example.org\r\n',
    ]
    options = CsvOptions(has_header=True, column="description")

    candidates = list(checkers._iter_csv_candidates(lines, ("#", ";;"), options))

    assert candidates == [f"first line\r\n{continuation_line}\r\nlast line"]


def test_csv_ignores_comments_and_blank_lines_between_records() -> None:
    content = (
        b"# before header\r\n"
        b"description,indicator\r\n"
        b"first,example.org\r\n"
        b"# between records\r\n"
        b";; another comment\r\n"
        b"\r\n"
        b"second,example.net\r\n"
    )
    source = make_local_source(
        Path("unused.csv"),
        list_format=ListFormat.CSV,
        comment_prefixes=("#", ";;"),
        csv_options=CsvOptions(has_header=True, column="indicator"),
    )

    parsed = parse_static_list(content, source)

    assert parsed.domains == frozenset({"example.org", "example.net"})
    assert parsed.entries_read == 2
    assert parsed.malformed_entries == 0


@pytest.mark.asyncio
async def test_malformed_multiline_csv_with_comment_like_lines_is_an_error(
    tmp_path: Path,
) -> None:
    list_path = tmp_path / "indicators.csv"
    list_path.write_text(
        'description,indicator\n"unterminated\n# continuation\n;; continuation\n\n',
        encoding="utf-8",
    )
    source = make_local_source(
        list_path,
        list_format=ListFormat.CSV,
        comment_prefixes=("#", ";;"),
        csv_options=CsvOptions(has_header=True, column="indicator"),
    )

    result = await run_local_check(source, "example.com")

    assert_error(result, ErrorKind.PARSE)
    assert result.failure is not None
    assert "malformed CSV data" in result.failure.message


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("csv_text", "error_message"),
    [
        ("other\nexample.com\n", "does not contain column"),
        ("indicator,indicator\nexample.com,example.net\n", "duplicate column"),
        ("# comments only\n\n", "does not contain a header row"),
        ('indicator\n"unterminated\n', "malformed CSV data"),
    ],
)
async def test_structurally_malformed_csv_returns_parse_error(
    tmp_path: Path,
    csv_text: str,
    error_message: str,
) -> None:
    list_path = tmp_path / "indicators.csv"
    list_path.write_text(csv_text, encoding="utf-8")
    source = make_local_source(
        list_path,
        list_format=ListFormat.CSV,
        csv_options=CsvOptions(has_header=True, column="indicator"),
    )

    result = await run_local_check(source, "example.com")

    assert_error(result, ErrorKind.PARSE)
    assert result.failure is not None
    assert error_message in result.failure.message


@pytest.mark.asyncio
async def test_malformed_encoded_file_returns_decode_error(tmp_path: Path) -> None:
    list_path = tmp_path / "invalid.txt"
    list_path.write_bytes(b"example.com\xff")

    result = await run_local_check(make_local_source(list_path), "example.com")

    assert_error(result, ErrorKind.DECODE)


@pytest.mark.asyncio
async def test_missing_file_returns_structured_error(tmp_path: Path) -> None:
    source = make_local_source(tmp_path / "missing.txt")

    result = await run_local_check(source, "example.com")

    assert_error(result, ErrorKind.FILE_NOT_FOUND)


@pytest.mark.asyncio
async def test_directory_path_returns_unreadable_file_error(tmp_path: Path) -> None:
    result = await run_local_check(make_local_source(tmp_path), "example.com")

    assert_error(result, ErrorKind.FILE_READ)


@pytest.mark.asyncio
async def test_permission_failure_returns_structured_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    list_path = tmp_path / "indicators.txt"
    list_path.write_text("example.com\n", encoding="utf-8")
    source = make_local_source(list_path)

    def deny_read(path: Path, size_limit: int) -> bytes:
        raise PermissionError

    monkeypatch.setattr(checkers, "_read_bounded_local_file", deny_read)

    result = await run_local_check(source, "example.com")

    assert_error(result, ErrorKind.FILE_PERMISSION)


@pytest.mark.asyncio
async def test_source_size_limit_is_enforced(tmp_path: Path) -> None:
    list_path = tmp_path / "indicators.txt"
    list_path.write_bytes(b"example.com\n")
    source = make_local_source(list_path, max_static_bytes=4)

    result = await run_local_check(source, "example.com")

    assert_error(result, ErrorKind.FILE_TOO_LARGE)


@pytest.mark.asyncio
async def test_global_size_limit_is_used_without_source_override(
    tmp_path: Path,
) -> None:
    list_path = tmp_path / "indicators.txt"
    list_path.write_bytes(b"example.com\n")

    result = await run_local_check(
        make_local_source(list_path),
        "example.com",
        default_max_static_bytes=4,
    )

    assert_error(result, ErrorKind.FILE_TOO_LARGE)


@pytest.mark.asyncio
async def test_source_size_override_takes_precedence(tmp_path: Path) -> None:
    list_path = tmp_path / "indicators.txt"
    content = b"example.com\n"
    list_path.write_bytes(content)
    source = make_local_source(list_path, max_static_bytes=len(content))

    result = await run_local_check(
        source,
        "example.com",
        default_max_static_bytes=4,
    )

    assert result.status is CheckStatus.LISTED


@pytest.mark.asyncio
async def test_unsupported_target_is_skipped_without_reading_file(
    tmp_path: Path,
) -> None:
    source = make_local_source(
        tmp_path / "missing.txt",
        supports=frozenset({TargetType.IPV4}),
    )

    result = await run_local_check(source, "example.com")

    assert result.status is CheckStatus.SKIPPED
    assert result.reason == "source does not support domain targets"


@pytest.mark.asyncio
async def test_local_read_is_dispatched_through_asyncio_to_thread(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    list_path = tmp_path / "indicators.txt"
    content = b"example.com\n"
    list_path.write_bytes(content)
    source = make_local_source(list_path)
    calls: list[tuple[Callable[..., object], tuple[object, ...]]] = []

    async def fake_to_thread(
        function: Callable[..., object],
        *args: object,
    ) -> object:
        calls.append((function, args))
        return function(*args)

    monkeypatch.setattr(checkers.asyncio, "to_thread", fake_to_thread)

    result = await run_local_check(source, "example.com")

    assert result.status is CheckStatus.LISTED
    assert calls == [
        (checkers._read_bounded_local_file, (list_path, 10_485_760)),
        (checkers.parse_static_list, (content, source)),
    ]


def test_shared_parser_accepts_remote_static_source_options() -> None:
    source = RemoteStaticSourceConfig(
        name="remote-test",
        category="test",
        supports=frozenset({TargetType.IPV6}),
        url="https://example.org/indicators.txt",
        format=ListFormat.TXT,
    )

    parsed = parse_static_list(b"2001:0db8::1\n2001:db8::1\n", source)

    target: Target = parse_target("2001:db8::1")
    assert parsed.contains(target)
    assert parsed.ipv6 == frozenset({"2001:db8::1"})
    assert parsed.duplicate_entries == 1
