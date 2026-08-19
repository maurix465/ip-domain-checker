"""YAML configuration loading and validation."""

from __future__ import annotations

import math
from pathlib import Path
from typing import cast

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from blacklist_checker.models import (
    AppConfig,
    BlacklistSourceConfig,
    CsvOptions,
    DnsblSourceConfig,
    ListFormat,
    LocalStaticSourceConfig,
    RemoteStaticSourceConfig,
    SourceKind,
    TargetType,
)

CONFIG_VERSION = 1
MAX_CONFIG_BYTES = 1_048_576

_ROOT_FIELDS = frozenset({"version", "defaults", "sources"})
_DEFAULT_FIELDS = frozenset(
    {"dns_timeout_seconds", "http_timeout_seconds", "max_static_bytes"}
)
_COMMON_SOURCE_FIELDS = frozenset({"name", "kind", "category", "enabled", "supports"})
_DNSBL_FIELDS = _COMMON_SOURCE_FIELDS | {"host", "timeout_seconds"}
_STATIC_FIELDS = {
    "format",
    "encoding",
    "comment_prefixes",
    "csv",
    "max_static_bytes",
}
_HTTP_STATIC_FIELDS = (
    _COMMON_SOURCE_FIELDS
    | _STATIC_FIELDS
    | {
        "url",
        "timeout_seconds",
    }
)
_LOCAL_STATIC_FIELDS = _COMMON_SOURCE_FIELDS | _STATIC_FIELDS | {"path"}
_CSV_FIELDS = frozenset({"has_header", "column", "delimiter"})
_MISSING = object()


class ConfigError(ValueError):
    """Raised when a configuration file cannot be loaded or validated."""


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


class _DuplicateKeyError(ConstructorError):
    """Internal YAML error whose public description contains no key value."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as error:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from error
        if duplicate:
            raise _DuplicateKeyError(
                "while constructing a mapping",
                node.start_mark,
                "found duplicate key",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_config(path: str | Path) -> AppConfig:
    """Load and validate a YAML configuration file into typed models."""
    config_path = Path(path)
    document = _load_yaml_document(config_path)
    root = _require_mapping(document, "configuration root")
    _reject_unknown_fields(root, _ROOT_FIELDS, "configuration root")

    version = _required(root, "version", "configuration root")
    if isinstance(version, bool) or not isinstance(version, int):
        raise ConfigError("configuration version must be an integer")
    if version != CONFIG_VERSION:
        raise ConfigError(
            f"unsupported configuration version {version}; expected {CONFIG_VERSION}"
        )

    default_overrides = _parse_defaults(root.get("defaults", {}))
    sources_value = _required(root, "sources", "configuration root")
    source_items = _require_list(sources_value, "configuration sources")
    if not source_items:
        raise ConfigError("configuration sources must not be empty")

    config_directory = config_path.resolve().parent
    all_sources = tuple(
        _parse_source(item, index, config_directory)
        for index, item in enumerate(source_items)
    )
    _validate_unique_source_names(all_sources)

    enabled_sources = tuple(source for source in all_sources if source.enabled)
    if not enabled_sources:
        raise ConfigError("configuration must contain at least one enabled source")

    base_config = AppConfig(sources=enabled_sources)
    dns_timeout, http_timeout, max_static_bytes = default_overrides
    return AppConfig(
        sources=enabled_sources,
        dns_timeout_seconds=(
            base_config.dns_timeout_seconds if dns_timeout is None else dns_timeout
        ),
        http_timeout_seconds=(
            base_config.http_timeout_seconds if http_timeout is None else http_timeout
        ),
        max_static_bytes=(
            base_config.max_static_bytes
            if max_static_bytes is None
            else max_static_bytes
        ),
    )


def _load_yaml_document(config_path: Path) -> object:
    try:
        with config_path.open("rb") as config_file:
            content = config_file.read(MAX_CONFIG_BYTES + 1)
    except FileNotFoundError as error:
        raise ConfigError(f"configuration file not found: {config_path}") from error
    except (OSError, PermissionError) as error:
        raise ConfigError(
            f"unable to read configuration file: {config_path}"
        ) from error

    if len(content) > MAX_CONFIG_BYTES:
        raise ConfigError(
            f"configuration file exceeds the {MAX_CONFIG_BYTES}-byte size limit"
        )

    try:
        return yaml.load(content, Loader=_UniqueKeySafeLoader)
    except yaml.YAMLError as error:
        raise ConfigError(_yaml_error_message(error)) from error


def _yaml_error_message(error: yaml.YAMLError) -> str:
    message = "invalid YAML configuration"
    if isinstance(error, _DuplicateKeyError):
        message = f"{message}: duplicate key"
    mark = getattr(error, "problem_mark", None)
    line = getattr(mark, "line", None)
    column = getattr(mark, "column", None)
    if type(line) is int and type(column) is int and line >= 0 and column >= 0:
        return f"{message} at line {line + 1}, column {column + 1}"
    return message


def _parse_defaults(value: object) -> tuple[float | None, float | None, int | None]:
    defaults = _require_mapping(value, "configuration defaults")
    _reject_unknown_fields(defaults, _DEFAULT_FIELDS, "configuration defaults")

    dns_timeout = _optional_positive_number(
        defaults,
        "dns_timeout_seconds",
        "configuration defaults",
    )
    http_timeout = _optional_positive_number(
        defaults,
        "http_timeout_seconds",
        "configuration defaults",
    )
    max_static_bytes = _optional_positive_integer(
        defaults,
        "max_static_bytes",
        "configuration defaults",
    )
    return dns_timeout, http_timeout, max_static_bytes


def _parse_source(
    value: object,
    index: int,
    config_directory: Path,
) -> BlacklistSourceConfig:
    location = f"sources[{index}]"
    source = _require_mapping(value, location)
    kind_value = _required_string(source, "kind", location)
    try:
        kind = SourceKind(kind_value)
    except ValueError as error:
        allowed = ", ".join(source_kind.value for source_kind in SourceKind)
        raise ConfigError(
            f"{location}.kind has unsupported value {kind_value!r}; expected {allowed}"
        ) from error

    allowed_fields = {
        SourceKind.DNSBL: _DNSBL_FIELDS,
        SourceKind.HTTP_STATIC: _HTTP_STATIC_FIELDS,
        SourceKind.LOCAL_STATIC: _LOCAL_STATIC_FIELDS,
    }[kind]
    _reject_unknown_fields(source, allowed_fields, f"{location} ({kind.value})")

    name = _required_string(source, "name", location)
    category = _required_string(source, "category", location)
    supports = _parse_supports(_required(source, "supports", location), location)
    enabled = _optional_boolean(source, "enabled", True, location)

    if kind is SourceKind.DNSBL:
        return _parse_dnsbl_source(
            source=source,
            location=location,
            name=name,
            category=category,
            supports=supports,
            enabled=enabled,
        )
    if kind is SourceKind.HTTP_STATIC:
        return _parse_remote_static_source(
            source=source,
            location=location,
            name=name,
            category=category,
            supports=supports,
            enabled=enabled,
        )
    return _parse_local_static_source(
        source=source,
        location=location,
        name=name,
        category=category,
        supports=supports,
        enabled=enabled,
        config_directory=config_directory,
    )


def _parse_dnsbl_source(
    *,
    source: dict[str, object],
    location: str,
    name: str,
    category: str,
    supports: frozenset[TargetType],
    enabled: bool,
) -> DnsblSourceConfig:
    host = _required_string(source, "host", location)
    timeout = _optional_positive_number(source, "timeout_seconds", location)
    try:
        return DnsblSourceConfig(
            name=name,
            category=category,
            supports=supports,
            enabled=enabled,
            host=host,
            timeout_seconds=timeout,
        )
    except (TypeError, ValueError) as error:
        raise ConfigError(f"{location}: {error}") from error


def _parse_remote_static_source(
    *,
    source: dict[str, object],
    location: str,
    name: str,
    category: str,
    supports: frozenset[TargetType],
    enabled: bool,
) -> RemoteStaticSourceConfig:
    url = _required_string(source, "url", location)
    (
        list_format,
        encoding,
        comment_prefixes,
        csv_options,
        max_static_bytes,
    ) = _parse_static_options(source, location)
    timeout = _optional_positive_number(source, "timeout_seconds", location)
    try:
        return RemoteStaticSourceConfig(
            name=name,
            category=category,
            supports=supports,
            enabled=enabled,
            url=url,
            format=list_format,
            encoding=encoding,
            comment_prefixes=comment_prefixes,
            csv=csv_options,
            timeout_seconds=timeout,
            max_static_bytes=max_static_bytes,
        )
    except (TypeError, ValueError) as error:
        raise ConfigError(f"{location}: {error}") from error


def _parse_local_static_source(
    *,
    source: dict[str, object],
    location: str,
    name: str,
    category: str,
    supports: frozenset[TargetType],
    enabled: bool,
    config_directory: Path,
) -> LocalStaticSourceConfig:
    raw_path = _required_string(source, "path", location)
    local_path = Path(raw_path)
    if not local_path.is_absolute():
        local_path = config_directory / local_path
    local_path = local_path.resolve()

    (
        list_format,
        encoding,
        comment_prefixes,
        csv_options,
        max_static_bytes,
    ) = _parse_static_options(source, location)
    try:
        return LocalStaticSourceConfig(
            name=name,
            category=category,
            supports=supports,
            enabled=enabled,
            path=local_path,
            format=list_format,
            encoding=encoding,
            comment_prefixes=comment_prefixes,
            csv=csv_options,
            max_static_bytes=max_static_bytes,
        )
    except (TypeError, ValueError) as error:
        raise ConfigError(f"{location}: {error}") from error


def _parse_static_options(
    source: dict[str, object],
    location: str,
) -> tuple[ListFormat, str, tuple[str, ...], CsvOptions | None, int | None]:
    format_value = _required_string(source, "format", location)
    try:
        list_format = ListFormat(format_value)
    except ValueError as error:
        allowed = ", ".join(list_format.value for list_format in ListFormat)
        raise ConfigError(
            f"{location}.format has unsupported value {format_value!r}; "
            f"expected {allowed}"
        ) from error

    encoding = _optional_string(source, "encoding", "utf-8-sig", location)
    comment_prefixes = _parse_comment_prefixes(source, location)
    max_static_bytes = _optional_positive_integer(
        source,
        "max_static_bytes",
        location,
    )
    csv_options = _parse_csv_options(source, list_format, location)
    return (
        list_format,
        encoding,
        comment_prefixes,
        csv_options,
        max_static_bytes,
    )


def _parse_comment_prefixes(
    source: dict[str, object],
    location: str,
) -> tuple[str, ...]:
    value = source.get("comment_prefixes", _MISSING)
    if value is _MISSING:
        return ("#", ";")
    prefixes = _require_list(value, f"{location}.comment_prefixes")
    parsed: list[str] = []
    for index, prefix in enumerate(prefixes):
        if not isinstance(prefix, str) or not prefix:
            raise ConfigError(
                f"{location}.comment_prefixes[{index}] must be a non-empty string"
            )
        parsed.append(prefix)
    return tuple(parsed)


def _parse_csv_options(
    source: dict[str, object],
    list_format: ListFormat,
    location: str,
) -> CsvOptions | None:
    value = source.get("csv", _MISSING)
    if list_format is ListFormat.TXT:
        if value is not _MISSING:
            raise ConfigError(f"{location}.csv is incompatible with TXT format")
        return None
    if value is _MISSING:
        raise ConfigError(f"{location}.csv is required for CSV format")

    csv_location = f"{location}.csv"
    options = _require_mapping(value, csv_location)
    _reject_unknown_fields(options, _CSV_FIELDS, csv_location)
    has_header = _required_boolean(options, "has_header", csv_location)
    column = _required(options, "column", csv_location)
    delimiter = _optional_string(options, "delimiter", ",", csv_location)

    try:
        return CsvOptions(
            has_header=has_header,
            column=cast(str | int, column),
            delimiter=delimiter,
        )
    except (TypeError, ValueError) as error:
        raise ConfigError(f"{csv_location}: {error}") from error


def _parse_supports(value: object, location: str) -> frozenset[TargetType]:
    raw_supports = _require_list(value, f"{location}.supports")
    if not raw_supports:
        raise ConfigError(f"{location}.supports must not be empty")

    supports: list[TargetType] = []
    for index, raw_target_type in enumerate(raw_supports):
        item_location = f"{location}.supports[{index}]"
        if not isinstance(raw_target_type, str):
            raise ConfigError(f"{item_location} must be a string")
        try:
            supports.append(TargetType(raw_target_type))
        except ValueError as error:
            allowed = ", ".join(target_type.value for target_type in TargetType)
            raise ConfigError(
                f"{item_location} has unsupported value {raw_target_type!r}; "
                f"expected {allowed}"
            ) from error

    if len(supports) != len(set(supports)):
        raise ConfigError(f"{location}.supports must not contain duplicates")
    return frozenset(supports)


def _validate_unique_source_names(
    sources: tuple[BlacklistSourceConfig, ...],
) -> None:
    seen: set[str] = set()
    for index, source in enumerate(sources):
        if source.name in seen:
            raise ConfigError(
                f"sources[{index}].name duplicates source name {source.name!r}"
            )
        seen.add(source.name)


def _required(
    mapping: dict[str, object],
    field: str,
    location: str,
) -> object:
    if field not in mapping:
        raise ConfigError(f"{location}.{field} is required")
    return mapping[field]


def _required_string(
    mapping: dict[str, object],
    field: str,
    location: str,
) -> str:
    value = _required(mapping, field, location)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{location}.{field} must be a non-empty string")
    return value


def _optional_string(
    mapping: dict[str, object],
    field: str,
    default: str,
    location: str,
) -> str:
    if field not in mapping:
        return default
    value = mapping[field]
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{location}.{field} must be a non-empty string")
    return value


def _required_boolean(
    mapping: dict[str, object],
    field: str,
    location: str,
) -> bool:
    value = _required(mapping, field, location)
    if not isinstance(value, bool):
        raise ConfigError(f"{location}.{field} must be a boolean")
    return value


def _optional_boolean(
    mapping: dict[str, object],
    field: str,
    default: bool,
    location: str,
) -> bool:
    if field not in mapping:
        return default
    value = mapping[field]
    if not isinstance(value, bool):
        raise ConfigError(f"{location}.{field} must be a boolean")
    return value


def _optional_positive_number(
    mapping: dict[str, object],
    field: str,
    location: str,
) -> float | None:
    if field not in mapping:
        return None
    value = mapping[field]
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ConfigError(f"{location}.{field} must be a positive finite number")
    return float(value)


def _optional_positive_integer(
    mapping: dict[str, object],
    field: str,
    location: str,
) -> int | None:
    if field not in mapping:
        return None
    value = mapping[field]
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError(f"{location}.{field} must be a positive integer")
    return value


def _require_mapping(value: object, location: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ConfigError(f"{location} must be a mapping")
    for key in value:
        if not isinstance(key, str):
            raise ConfigError(f"{location} field names must be strings")
    return cast(dict[str, object], value)


def _require_list(value: object, location: str) -> list[object]:
    if not isinstance(value, list):
        raise ConfigError(f"{location} must be a list")
    return cast(list[object], value)


def _reject_unknown_fields(
    mapping: dict[str, object],
    allowed: set[str] | frozenset[str],
    location: str,
) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        fields = ", ".join(repr(field) for field in unknown)
        raise ConfigError(
            f"{location} contains unknown or incompatible fields: {fields}"
        )
