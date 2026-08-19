"""Tests for application model invariants."""

from dataclasses import FrozenInstanceError, asdict
from pathlib import Path

import pytest

from blacklist_checker.models import (
    AppConfig,
    CheckFailure,
    CheckResult,
    CheckStatus,
    CsvOptions,
    DnsblSourceConfig,
    ErrorKind,
    ListFormat,
    LocalStaticSourceConfig,
    RemoteStaticSourceConfig,
    SourceConfig,
    SourceKind,
    Target,
    TargetType,
)


def make_dnsbl_source(
    *,
    name: str = "example-dnsbl",
    category: str = "spam",
    supports: frozenset[TargetType] = frozenset({TargetType.IPV4}),
    host: str = "dnsbl.example.org",
    timeout_seconds: float | None = None,
) -> DnsblSourceConfig:
    return DnsblSourceConfig(
        name=name,
        category=category,
        supports=supports,
        host=host,
        timeout_seconds=timeout_seconds,
    )


def make_remote_source(
    *,
    list_format: ListFormat = ListFormat.TXT,
    csv: CsvOptions | None = None,
    timeout_seconds: float | None = None,
    max_static_bytes: int | None = None,
) -> RemoteStaticSourceConfig:
    return RemoteStaticSourceConfig(
        name="example-remote",
        category="malware",
        supports=frozenset({TargetType.IPV4, TargetType.DOMAIN}),
        url="https://example.org/list.txt",
        format=list_format,
        csv=csv,
        timeout_seconds=timeout_seconds,
        max_static_bytes=max_static_bytes,
    )


def make_local_source(
    *,
    list_format: ListFormat = ListFormat.TXT,
    csv: CsvOptions | None = None,
    max_static_bytes: int | None = None,
) -> LocalStaticSourceConfig:
    return LocalStaticSourceConfig(
        name="example-local",
        category="internal",
        supports=frozenset({TargetType.IPV6, TargetType.DOMAIN}),
        path=Path("lists/internal.txt"),
        format=list_format,
        csv=csv,
        max_static_bytes=max_static_bytes,
    )


@pytest.mark.parametrize(
    ("name", "category", "supports", "error_message"),
    [
        ("", "spam", frozenset({TargetType.IPV4}), "source name"),
        ("example", " ", frozenset({TargetType.IPV4}), "source category"),
        ("example", "spam", frozenset(), "supports"),
    ],
)
def test_source_rejects_empty_shared_fields(
    name: str,
    category: str,
    supports: frozenset[TargetType],
    error_message: str,
) -> None:
    with pytest.raises(ValueError, match=error_message):
        make_dnsbl_source(name=name, category=category, supports=supports)


def test_abstract_source_config_cannot_be_constructed_directly() -> None:
    with pytest.raises(TypeError, match="source subtype"):
        SourceConfig(
            name="example",
            category="spam",
            supports=frozenset({TargetType.IPV4}),
        )


def test_source_kinds_are_frozen_instance_discriminators() -> None:
    csv_options = CsvOptions(has_header=True, column="indicator")
    sources = (
        make_dnsbl_source(),
        make_remote_source(list_format=ListFormat.CSV, csv=csv_options),
        make_local_source(),
    )

    assert [source.kind for source in sources] == [
        SourceKind.DNSBL,
        SourceKind.HTTP_STATIC,
        SourceKind.LOCAL_STATIC,
    ]
    assert [asdict(source)["kind"] for source in sources] == [
        SourceKind.DNSBL,
        SourceKind.HTTP_STATIC,
        SourceKind.LOCAL_STATIC,
    ]


def test_source_kind_cannot_be_passed_to_constructor() -> None:
    with pytest.raises(TypeError, match="unexpected keyword argument 'kind'"):
        DnsblSourceConfig(
            name="example",
            category="spam",
            supports=frozenset({TargetType.IPV4}),
            host="dnsbl.example.org",
            kind=SourceKind.HTTP_STATIC,  # type: ignore[call-arg]
        )


def test_source_kind_cannot_be_reassigned() -> None:
    source = make_dnsbl_source()

    with pytest.raises(FrozenInstanceError):
        source.kind = SourceKind.HTTP_STATIC  # type: ignore[misc]


@pytest.mark.parametrize("host", ["", " "])
def test_dnsbl_rejects_empty_host(host: str) -> None:
    with pytest.raises(ValueError, match="DNSBL host"):
        make_dnsbl_source(host=host)


def test_dnsbl_rejects_domain_support() -> None:
    with pytest.raises(ValueError, match="must not support domain"):
        make_dnsbl_source(supports=frozenset({TargetType.IPV4, TargetType.DOMAIN}))


@pytest.mark.parametrize("timeout_seconds", [0.0, -1.0, float("inf"), float("nan")])
def test_dnsbl_rejects_invalid_timeout_override(timeout_seconds: float) -> None:
    with pytest.raises(ValueError, match="positive finite"):
        make_dnsbl_source(timeout_seconds=timeout_seconds)


@pytest.mark.parametrize("timeout_seconds", [0.0, -1.0, float("inf"), float("nan")])
def test_remote_source_rejects_invalid_timeout_override(
    timeout_seconds: float,
) -> None:
    with pytest.raises(ValueError, match="positive finite"):
        make_remote_source(timeout_seconds=timeout_seconds)


@pytest.mark.parametrize(
    "url",
    ["", "ftp://example.org/list.txt", "https:///list.txt", "https://example.org:0"],
)
def test_remote_source_rejects_invalid_url(url: str) -> None:
    with pytest.raises(ValueError, match="URL"):
        RemoteStaticSourceConfig(
            name="example-remote",
            category="malware",
            supports=frozenset({TargetType.DOMAIN}),
            url=url,
            format=ListFormat.TXT,
        )


@pytest.mark.parametrize("max_static_bytes", [0, -1])
def test_static_sources_reject_invalid_size_overrides(
    max_static_bytes: int,
) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        make_remote_source(max_static_bytes=max_static_bytes)
    with pytest.raises(ValueError, match="positive integer"):
        make_local_source(max_static_bytes=max_static_bytes)


@pytest.mark.parametrize(
    ("has_header", "column", "delimiter", "error_message"),
    [
        (True, 0, ",", "header-based"),
        (True, "", ",", "header-based"),
        (False, "indicator", ",", "headerless"),
        (False, -1, ",", "headerless"),
        (False, 0, "", "delimiter"),
        (False, 0, "::", "delimiter"),
        (False, 0, "\n", "delimiter"),
    ],
)
def test_csv_options_reject_invalid_combinations(
    has_header: bool,
    column: str | int,
    delimiter: str,
    error_message: str,
) -> None:
    with pytest.raises(ValueError, match=error_message):
        CsvOptions(
            has_header=has_header,
            column=column,
            delimiter=delimiter,
        )


def test_csv_options_accept_header_and_index_columns() -> None:
    assert CsvOptions(has_header=True, column="indicator").column == "indicator"
    assert CsvOptions(has_header=False, column=0).column == 0


@pytest.mark.parametrize(
    ("list_format", "csv", "error_message"),
    [
        (ListFormat.CSV, None, "requires CSV options"),
        (
            ListFormat.TXT,
            CsvOptions(has_header=True, column="indicator"),
            "must not include CSV options",
        ),
    ],
)
def test_static_source_rejects_incompatible_format_options(
    list_format: ListFormat,
    csv: CsvOptions | None,
    error_message: str,
) -> None:
    with pytest.raises(ValueError, match=error_message):
        make_remote_source(list_format=list_format, csv=csv)
    with pytest.raises(ValueError, match=error_message):
        make_local_source(list_format=list_format, csv=csv)


def test_static_source_rejects_invalid_text_options() -> None:
    with pytest.raises(ValueError, match="encoding"):
        RemoteStaticSourceConfig(
            name="example-remote",
            category="malware",
            supports=frozenset({TargetType.DOMAIN}),
            url="https://example.org/list.txt",
            format=ListFormat.TXT,
            encoding=" ",
        )
    with pytest.raises(ValueError, match="comment prefixes"):
        LocalStaticSourceConfig(
            name="example-local",
            category="internal",
            supports=frozenset({TargetType.DOMAIN}),
            path=Path("lists/internal.txt"),
            format=ListFormat.TXT,
            comment_prefixes=("",),
        )


def test_app_config_owns_defaults_and_sources_hold_only_overrides() -> None:
    dnsbl = make_dnsbl_source()
    remote = make_remote_source()
    local = make_local_source()
    config = AppConfig(sources=(dnsbl, remote, local))

    assert dnsbl.timeout_seconds is None
    assert remote.timeout_seconds is None
    assert remote.max_static_bytes is None
    assert local.max_static_bytes is None
    assert config.dns_timeout_seconds == 5.0
    assert config.http_timeout_seconds == 15.0
    assert config.max_static_bytes == 10_485_760


def test_app_config_rejects_empty_and_duplicate_sources() -> None:
    with pytest.raises(ValueError, match="at least one source"):
        AppConfig(sources=())

    source = make_dnsbl_source()
    with pytest.raises(ValueError, match="unique"):
        AppConfig(sources=(source, source))


@pytest.mark.parametrize(
    ("field", "value", "error_message"),
    [
        ("dns_timeout_seconds", 0.0, "positive finite"),
        ("http_timeout_seconds", float("inf"), "positive finite"),
        ("max_static_bytes", 0, "positive integer"),
    ],
)
def test_app_config_rejects_invalid_defaults(
    field: str,
    value: float | int,
    error_message: str,
) -> None:
    values: dict[str, object] = {
        "sources": (make_dnsbl_source(),),
        "dns_timeout_seconds": 5.0,
        "http_timeout_seconds": 15.0,
        "max_static_bytes": 10_485_760,
    }
    values[field] = value

    with pytest.raises(ValueError, match=error_message):
        AppConfig(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize("message", ["", " "])
def test_failure_rejects_empty_message(message: str) -> None:
    with pytest.raises(ValueError, match="failure message"):
        CheckFailure(ErrorKind.UNEXPECTED, message)


def test_valid_structured_error_result() -> None:
    target = Target("192.0.2.1", "192.0.2.1", TargetType.IPV4)
    failure = CheckFailure(ErrorKind.DNS_TIMEOUT, "DNS query timed out")

    result = CheckResult(
        source_name="example",
        source_kind=SourceKind.DNSBL,
        category="spam",
        target=target,
        status=CheckStatus.ERROR,
        failure=failure,
    )

    assert result.failure is failure
    assert result.reason is None


def test_error_result_requires_structured_failure() -> None:
    target = Target("192.0.2.1", "192.0.2.1", TargetType.IPV4)

    with pytest.raises(ValueError, match="must include a failure"):
        CheckResult(
            source_name="example",
            source_kind=SourceKind.DNSBL,
            category="spam",
            target=target,
            status=CheckStatus.ERROR,
        )


def test_skipped_result_requires_reason() -> None:
    target = Target("example.com", "example.com", TargetType.DOMAIN)

    with pytest.raises(ValueError, match="skip reason"):
        CheckResult(
            source_name="example",
            source_kind=SourceKind.DNSBL,
            category="spam",
            target=target,
            status=CheckStatus.SKIPPED,
        )

    result = CheckResult(
        source_name="example",
        source_kind=SourceKind.DNSBL,
        category="spam",
        target=target,
        status=CheckStatus.SKIPPED,
        reason="domain targets are unsupported",
    )
    assert result.reason == "domain targets are unsupported"


def test_listed_result_requires_evidence() -> None:
    target = Target("example.com", "example.com", TargetType.DOMAIN)

    with pytest.raises(ValueError, match="must include evidence"):
        CheckResult(
            source_name="example",
            source_kind=SourceKind.LOCAL_STATIC,
            category="malware",
            target=target,
            status=CheckStatus.LISTED,
        )


def test_not_listed_result_rejects_evidence() -> None:
    target = Target("example.com", "example.com", TargetType.DOMAIN)

    with pytest.raises(ValueError, match="must not include evidence"):
        CheckResult(
            source_name="example",
            source_kind=SourceKind.LOCAL_STATIC,
            category="malware",
            target=target,
            status=CheckStatus.NOT_LISTED,
            evidence=("example.com",),
        )


def test_error_result_rejects_skip_reason() -> None:
    target = Target("192.0.2.1", "192.0.2.1", TargetType.IPV4)

    with pytest.raises(ValueError, match="must not include a skip reason"):
        CheckResult(
            source_name="example",
            source_kind=SourceKind.DNSBL,
            category="spam",
            target=target,
            status=CheckStatus.ERROR,
            reason="not applicable",
            failure=CheckFailure(ErrorKind.DNS_TIMEOUT, "DNS query timed out"),
        )


@pytest.mark.parametrize(
    "count_field",
    ["entries_read", "malformed_entries", "duplicate_entries"],
)
def test_result_rejects_negative_entry_counts(count_field: str) -> None:
    target = Target("example.com", "example.com", TargetType.DOMAIN)
    values: dict[str, object] = {
        "source_name": "example",
        "source_kind": SourceKind.LOCAL_STATIC,
        "category": "malware",
        "target": target,
        "status": CheckStatus.NOT_LISTED,
        count_field: -1,
    }

    with pytest.raises(ValueError, match="non-negative integer"):
        CheckResult(**values)  # type: ignore[arg-type]


def test_result_rejects_entry_subcounts_greater_than_entries_read() -> None:
    target = Target("example.com", "example.com", TargetType.DOMAIN)

    with pytest.raises(ValueError, match="must not exceed entries_read"):
        CheckResult(
            source_name="example",
            source_kind=SourceKind.LOCAL_STATIC,
            category="malware",
            target=target,
            status=CheckStatus.NOT_LISTED,
            entries_read=1,
            malformed_entries=1,
            duplicate_entries=1,
        )
