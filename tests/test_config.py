"""Tests for YAML configuration loading and validation."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from blacklist_checker.config import MAX_CONFIG_BYTES, ConfigError, load_config
from blacklist_checker.models import (
    CsvOptions,
    DnsblSourceConfig,
    ListFormat,
    LocalStaticSourceConfig,
    RemoteStaticSourceConfig,
    TargetType,
)


def write_config(tmp_path: Path, content: str, name: str = "blacklists.yaml") -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(content).lstrip(), encoding="utf-8")
    return path


def minimal_dnsbl_source(*, extra: str = "") -> str:
    return f"""
        version: 1
        sources:
          - name: example-dnsbl
            kind: dnsbl
            category: spam
            supports: [ipv4]
            host: dnsbl.example.org
            {extra}
    """


def test_loads_typed_configuration_and_resolves_defaults(tmp_path: Path) -> None:
    config_path = write_config(
        tmp_path,
        """
        version: 1
        defaults:
          dns_timeout_seconds: 7
          http_timeout_seconds: 12.5
          max_static_bytes: 2048
        sources:
          - name: dns-source
            kind: dnsbl
            category: spam
            supports: [ipv4, ipv6]
            host: dnsbl.example.org
            timeout_seconds: 2.5

          - name: remote-source
            kind: http_static
            category: phishing
            supports: [domain]
            url: https://example.org/domains.csv
            format: csv
            encoding: utf-8
            comment_prefixes: ["#"]
            csv:
              has_header: true
              column: indicator
              delimiter: ","
            max_static_bytes: 1024

          - name: local-source
            kind: local_static
            category: internal
            supports: [ipv4, domain]
            path: lists/internal.txt
            format: txt
        """,
    )

    config = load_config(config_path)

    assert config.dns_timeout_seconds == 7.0
    assert config.http_timeout_seconds == 12.5
    assert config.max_static_bytes == 2048
    assert len(config.sources) == 3

    dns_source, remote_source, local_source = config.sources
    assert isinstance(dns_source, DnsblSourceConfig)
    assert dns_source.supports == frozenset({TargetType.IPV4, TargetType.IPV6})
    assert dns_source.timeout_seconds == 2.5

    assert isinstance(remote_source, RemoteStaticSourceConfig)
    assert remote_source.format is ListFormat.CSV
    assert remote_source.csv == CsvOptions(
        has_header=True,
        column="indicator",
        delimiter=",",
    )
    assert remote_source.timeout_seconds is None
    assert remote_source.max_static_bytes == 1024

    assert isinstance(local_source, LocalStaticSourceConfig)
    assert local_source.path == (tmp_path / "lists/internal.txt").resolve()
    assert local_source.max_static_bytes is None


def test_uses_app_config_defaults_when_defaults_are_omitted(tmp_path: Path) -> None:
    config = load_config(write_config(tmp_path, minimal_dnsbl_source()))

    assert config.dns_timeout_seconds == 5.0
    assert config.http_timeout_seconds == 15.0
    assert config.max_static_bytes == 10_485_760


def test_resolves_local_path_relative_to_nested_config_file(tmp_path: Path) -> None:
    config_path = write_config(
        tmp_path,
        """
        version: 1
        sources:
          - name: local-source
            kind: local_static
            category: internal
            supports: [domain]
            path: ../data/domains.txt
            format: txt
        """,
        name="configs/blacklists.yaml",
    )

    config = load_config(config_path)

    source = config.sources[0]
    assert isinstance(source, LocalStaticSourceConfig)
    assert source.path == (tmp_path / "data/domains.txt").resolve()


def test_preserves_absolute_local_path(tmp_path: Path) -> None:
    absolute_list = (tmp_path / "data/domains.txt").resolve()
    config_path = write_config(
        tmp_path,
        f"""
        version: 1
        sources:
          - name: local-source
            kind: local_static
            category: internal
            supports: [domain]
            path: {absolute_list}
            format: txt
        """,
    )

    source = load_config(config_path).sources[0]

    assert isinstance(source, LocalStaticSourceConfig)
    assert source.path == absolute_list


def test_validates_disabled_source_then_omits_it(tmp_path: Path) -> None:
    config_path = write_config(
        tmp_path,
        """
        version: 1
        sources:
          - name: active
            kind: dnsbl
            category: spam
            supports: [ipv4]
            host: active.example.org
          - name: disabled
            kind: http_static
            category: malware
            enabled: false
            supports: [domain]
            url: https://example.org/list.txt
            format: txt
        """,
    )

    config = load_config(config_path)

    assert [source.name for source in config.sources] == ["active"]


def test_rejects_invalid_disabled_source(tmp_path: Path) -> None:
    config_path = write_config(
        tmp_path,
        """
        version: 1
        sources:
          - name: active
            kind: dnsbl
            category: spam
            supports: [ipv4]
            host: active.example.org
          - name: disabled
            kind: dnsbl
            category: spam
            enabled: false
            supports: [domain]
            host: disabled.example.org
        """,
    )

    with pytest.raises(ConfigError, match="must not support domain"):
        load_config(config_path)


def test_rejects_configuration_with_only_disabled_sources(tmp_path: Path) -> None:
    config_path = write_config(
        tmp_path,
        minimal_dnsbl_source(extra="enabled: false"),
    )

    with pytest.raises(ConfigError, match="at least one enabled source"):
        load_config(config_path)


@pytest.mark.parametrize(
    "content",
    [
        """
        version: 1
        version: 1
        sources: []
        """,
        """
        version: 1
        sources:
          - name: first
            name: second
            kind: dnsbl
            category: spam
            supports: [ipv4]
            host: dnsbl.example.org
        """,
        """
        version: 1
        sources:
          - name: source
            kind: http_static
            category: malware
            supports: [domain]
            url: https://example.org/list.csv
            format: csv
            csv:
              has_header: true
              column: first
              column: second
        """,
    ],
)
def test_rejects_duplicate_yaml_keys(tmp_path: Path, content: str) -> None:
    with pytest.raises(ConfigError, match="duplicate key"):
        load_config(write_config(tmp_path, content))


def test_safe_loader_rejects_python_specific_tags(tmp_path: Path) -> None:
    config_path = write_config(
        tmp_path,
        """
        version: !!python/object/new:tuple []
        sources: []
        """,
    )

    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(config_path)


@pytest.mark.parametrize(
    ("content", "error_message"),
    [
        ("", "configuration root must be a mapping"),
        ("- version\n- sources", "configuration root must be a mapping"),
        ("version: [1]\nsources: []", "version must be an integer"),
        ("version: true\nsources: []", "version must be an integer"),
        ("version: 2\nsources: []", "unsupported configuration version"),
        ("sources: []", "configuration root.version is required"),
    ],
)
def test_validates_configuration_version_and_root(
    tmp_path: Path,
    content: str,
    error_message: str,
) -> None:
    with pytest.raises(ConfigError, match=error_message):
        load_config(write_config(tmp_path, content))


@pytest.mark.parametrize(
    ("content", "error_message"),
    [
        (
            """
            version: 1
            unexpected: true
            sources: []
            """,
            "unknown or incompatible fields: 'unexpected'",
        ),
        (
            """
            version: 1
            defaults:
              unexpected: 1
            sources: []
            """,
            "unknown or incompatible fields: 'unexpected'",
        ),
        (
            """
            version: 1
            sources:
              - name: source
                kind: dnsbl
                category: spam
                supports: [ipv4]
                host: dnsbl.example.org
                url: https://example.org/list.txt
            """,
            "unknown or incompatible fields: 'url'",
        ),
        (
            """
            version: 1
            sources:
              - name: source
                kind: http_static
                category: malware
                supports: [domain]
                url: https://example.org/list.txt
                format: txt
                host: dnsbl.example.org
            """,
            "unknown or incompatible fields: 'host'",
        ),
        (
            """
            version: 1
            sources:
              - name: source
                kind: local_static
                category: internal
                supports: [domain]
                path: domains.txt
                format: txt
                timeout_seconds: 5
            """,
            "unknown or incompatible fields: 'timeout_seconds'",
        ),
    ],
)
def test_rejects_unknown_and_kind_incompatible_fields(
    tmp_path: Path,
    content: str,
    error_message: str,
) -> None:
    with pytest.raises(ConfigError, match=error_message):
        load_config(write_config(tmp_path, content))


@pytest.mark.parametrize(
    ("defaults", "error_message"),
    [
        ("[]", "configuration defaults must be a mapping"),
        ("{dns_timeout_seconds: 0}", "positive finite number"),
        ("{dns_timeout_seconds: .nan}", "positive finite number"),
        ("{http_timeout_seconds: true}", "positive finite number"),
        ("{max_static_bytes: 0}", "positive integer"),
        ("{max_static_bytes: 1.5}", "positive integer"),
    ],
)
def test_rejects_invalid_defaults(
    tmp_path: Path,
    defaults: str,
    error_message: str,
) -> None:
    content = f"""
        version: 1
        defaults: {defaults}
        sources:
          - name: source
            kind: dnsbl
            category: spam
            supports: [ipv4]
            host: dnsbl.example.org
    """

    with pytest.raises(ConfigError, match=error_message):
        load_config(write_config(tmp_path, content))


@pytest.mark.parametrize(
    ("sources", "error_message"),
    [
        ("{}", "configuration sources must be a list"),
        ("[]", "configuration sources must not be empty"),
        ("[not-a-mapping]", r"sources\[0\] must be a mapping"),
    ],
)
def test_validates_sources_collection(
    tmp_path: Path,
    sources: str,
    error_message: str,
) -> None:
    content = f"version: 1\nsources: {sources}\n"

    with pytest.raises(ConfigError, match=error_message):
        load_config(write_config(tmp_path, content))


def test_rejects_unknown_source_kind(tmp_path: Path) -> None:
    config_path = write_config(
        tmp_path,
        """
        version: 1
        sources:
          - name: source
            kind: custom
            category: custom
            supports: [domain]
        """,
    )

    with pytest.raises(ConfigError, match="unsupported value 'custom'"):
        load_config(config_path)


@pytest.mark.parametrize(
    ("supports", "error_message"),
    [
        ("ipv4", "supports must be a list"),
        ("[]", "supports must not be empty"),
        ("[ipv4, ipv4]", "must not contain duplicates"),
        ("[ipv4, unknown]", "unsupported value 'unknown'"),
        ("[1]", r"supports\[0\] must be a string"),
        ("[domain]", "DNSBL sources must not support domain"),
    ],
)
def test_rejects_invalid_supports(
    tmp_path: Path,
    supports: str,
    error_message: str,
) -> None:
    content = f"""
        version: 1
        sources:
          - name: source
            kind: dnsbl
            category: spam
            supports: {supports}
            host: dnsbl.example.org
    """

    with pytest.raises(ConfigError, match=error_message):
        load_config(write_config(tmp_path, content))


def test_rejects_duplicate_names_including_disabled_sources(tmp_path: Path) -> None:
    config_path = write_config(
        tmp_path,
        """
        version: 1
        sources:
          - name: duplicate
            kind: dnsbl
            category: spam
            supports: [ipv4]
            host: first.example.org
          - name: duplicate
            kind: local_static
            category: internal
            enabled: false
            supports: [domain]
            path: domains.txt
            format: txt
        """,
    )

    with pytest.raises(ConfigError, match="duplicates source name 'duplicate'"):
        load_config(config_path)


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.org/list.txt",
        "list.txt",
        "https:///list.txt",
        "https://example.org:70000/list.txt",
    ],
)
def test_rejects_invalid_remote_url(tmp_path: Path, url: str) -> None:
    config_path = write_config(
        tmp_path,
        f"""
        version: 1
        sources:
          - name: source
            kind: http_static
            category: malware
            supports: [domain]
            url: {url}
            format: txt
        """,
    )

    with pytest.raises(ConfigError, match="URL"):
        load_config(config_path)


@pytest.mark.parametrize(
    ("kind", "fields", "error_message"),
    [
        (
            "dnsbl",
            "host: dnsbl.example.org\n            timeout_seconds: 0",
            "timeout_seconds must be a positive finite number",
        ),
        (
            "http_static",
            "url: https://example.org/list.txt\n            format: txt\n"
            "            timeout_seconds: false",
            "timeout_seconds must be a positive finite number",
        ),
        (
            "http_static",
            "url: https://example.org/list.txt\n            format: txt\n"
            "            max_static_bytes: -1",
            "max_static_bytes must be a positive integer",
        ),
        (
            "local_static",
            "path: list.txt\n            format: txt\n"
            "            max_static_bytes: 1.5",
            "max_static_bytes must be a positive integer",
        ),
    ],
)
def test_rejects_invalid_source_limits(
    tmp_path: Path,
    kind: str,
    fields: str,
    error_message: str,
) -> None:
    content = f"""
        version: 1
        sources:
          - name: source
            kind: {kind}
            category: test
            supports: [ipv4]
            {fields}
    """

    with pytest.raises(ConfigError, match=error_message):
        load_config(write_config(tmp_path, content))


@pytest.mark.parametrize(
    ("format_and_csv", "error_message"),
    [
        ("format: csv", "csv is required for CSV format"),
        (
            "format: txt\n            csv: {has_header: true, column: indicator}",
            "csv is incompatible with TXT format",
        ),
        (
            "format: csv\n            csv: []",
            "csv must be a mapping",
        ),
        (
            "format: csv\n            csv: {column: indicator}",
            "csv.has_header is required",
        ),
        (
            "format: csv\n            csv: {has_header: true}",
            "csv.column is required",
        ),
        (
            "format: csv\n            csv: {has_header: true, column: 0}",
            "header-based CSV column",
        ),
        (
            "format: csv\n            csv: {has_header: false, column: indicator}",
            "headerless CSV column",
        ),
        (
            "format: csv\n"
            "            csv: {has_header: false, column: 0, delimiter: '::'}",
            "CSV delimiter",
        ),
        (
            "format: csv\n"
            "            csv: {has_header: true, column: indicator, extra: 1}",
            "unknown or incompatible fields: 'extra'",
        ),
    ],
)
def test_rejects_invalid_csv_options(
    tmp_path: Path,
    format_and_csv: str,
    error_message: str,
) -> None:
    content = f"""
        version: 1
        sources:
          - name: source
            kind: http_static
            category: malware
            supports: [domain]
            url: https://example.org/list.csv
            {format_and_csv}
    """

    with pytest.raises(ConfigError, match=error_message):
        load_config(write_config(tmp_path, content))


def test_loads_headerless_csv_options(tmp_path: Path) -> None:
    config_path = write_config(
        tmp_path,
        """
        version: 1
        sources:
          - name: source
            kind: local_static
            category: internal
            supports: [ipv4]
            path: indicators.csv
            format: csv
            csv:
              has_header: false
              column: 2
              delimiter: ";"
        """,
    )

    source = load_config(config_path).sources[0]

    assert isinstance(source, LocalStaticSourceConfig)
    assert source.csv == CsvOptions(has_header=False, column=2, delimiter=";")


@pytest.mark.parametrize(
    ("extra", "error_message"),
    [
        ("enabled: 1", "enabled must be a boolean"),
        ("comment_prefixes: '#'", "comment_prefixes must be a list"),
        ("comment_prefixes: ['', '#']", "must be a non-empty string"),
        ("encoding: not-a-real-codec", "unknown static-list encoding"),
        ("format: json", "format has unsupported value 'json'"),
    ],
)
def test_rejects_miscellaneous_invalid_source_fields(
    tmp_path: Path,
    extra: str,
    error_message: str,
) -> None:
    base_fields = (
        "url: https://example.org/list.txt\n            format: txt"
        if not extra.startswith("format:")
        else "url: https://example.org/list.txt"
    )
    content = f"""
        version: 1
        sources:
          - name: source
            kind: http_static
            category: malware
            supports: [domain]
            {base_fields}
            {extra}
    """

    with pytest.raises(ConfigError, match=error_message):
        load_config(write_config(tmp_path, content))


def test_rejects_missing_configuration_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="configuration file not found"):
        load_config(tmp_path / "missing.yaml")


def test_rejects_malformed_yaml(tmp_path: Path) -> None:
    config_path = write_config(tmp_path, "version: [1\nsources: []")

    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(config_path)


def test_malformed_yaml_error_has_location_without_source_content(
    tmp_path: Path,
) -> None:
    config_path = write_config(
        tmp_path,
        "version: 1\nsources: [TOP_SECRET_VALUE\n",
    )

    with pytest.raises(ConfigError) as raised:
        load_config(config_path)

    message = str(raised.value)
    assert message.startswith("invalid YAML configuration at line ")
    assert ", column " in message
    assert "TOP_SECRET_VALUE" not in message
    assert "sources:" not in message


def test_rejects_oversized_configuration(tmp_path: Path) -> None:
    config_path = tmp_path / "blacklists.yaml"
    config_path.write_bytes(b" " * (MAX_CONFIG_BYTES + 1))

    with pytest.raises(ConfigError, match="size limit"):
        load_config(config_path)
