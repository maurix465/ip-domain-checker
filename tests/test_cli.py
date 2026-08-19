"""Tests for the command-line interface."""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from types import TracebackType
from typing import cast

import pytest
from rich.console import Console
from rich.table import Table
from rich.text import Text

from blacklist_checker import cli
from blacklist_checker.cli import (
    build_parser,
    exit_code_for_results,
    main,
    render_results,
)
from blacklist_checker.config import ConfigError
from blacklist_checker.models import (
    AppConfig,
    CheckFailure,
    CheckResult,
    CheckStatus,
    ErrorKind,
    ListFormat,
    LocalStaticSourceConfig,
    SourceKind,
    Target,
    TargetType,
)
from blacklist_checker.utils import parse_target


def make_config() -> AppConfig:
    source = LocalStaticSourceConfig(
        name="local-test",
        category="test",
        supports=frozenset({TargetType.DOMAIN}),
        path=Path("indicators.txt"),
        format=ListFormat.TXT,
    )
    return AppConfig(sources=(source,))


def make_result(
    status: CheckStatus,
    *,
    name: str = "source-test",
    target: Target | None = None,
    error_message: str = "source failed safely",
) -> CheckResult:
    checked_target = parse_target("example.com") if target is None else target
    common = {
        "source_name": name,
        "source_kind": SourceKind.LOCAL_STATIC,
        "category": "test",
        "target": checked_target,
        "status": status,
    }
    if status is CheckStatus.LISTED:
        return CheckResult(**common, evidence=(checked_target.normalized,))
    if status is CheckStatus.SKIPPED:
        return CheckResult(**common, reason="target type is unsupported")
    if status is CheckStatus.ERROR:
        return CheckResult(
            **common,
            failure=CheckFailure(ErrorKind.HTTP_CONNECTION, error_message),
        )
    return CheckResult(**common)


class SpyStatus:
    def __init__(self, console: SpyConsole) -> None:
        self.console = console

    def __enter__(self) -> SpyStatus:
        self.console.status_active = True
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        self.console.status_active = False
        return False


class SpyConsole:
    def __init__(self) -> None:
        self.status_active = False
        self.status_messages: list[tuple[object, str]] = []
        self.printed: list[object] = []

    def status(self, message: object, *, spinner: str) -> SpyStatus:
        self.status_messages.append((message, spinner))
        return SpyStatus(self)

    def print(self, renderable: object) -> None:
        self.printed.append(renderable)


def test_parser_accepts_target_and_configuration() -> None:
    arguments = build_parser().parse_args(
        ["example.com", "--config", "blacklists.yaml"]
    )

    assert arguments.target == "example.com"
    assert arguments.config == Path("blacklists.yaml")


def test_parser_help_uses_installed_command_name(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        build_parser().parse_args(["--help"])

    assert raised.value.code == 0
    assert "usage: check-blacklist" in capsys.readouterr().out


def test_main_rejects_missing_target_with_exit_code_2(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        main(["--config", "blacklists.yaml"])

    assert raised.value.code == 2
    assert "the following arguments are required: target" in capsys.readouterr().err


def test_main_rejects_missing_configuration_with_exit_code_2(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        main(["example.com"])

    assert raised.value.code == 2
    assert "the following arguments are required: -c/--config" in (
        capsys.readouterr().err
    )


def test_main_reports_invalid_target_with_exit_code_2(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        main(["localhost", "--config", "blacklists.yaml"])

    assert raised.value.code == 2
    error_output = capsys.readouterr().err
    assert "check-blacklist: error:" in error_output
    assert "domain target must contain at least one dot" in error_output


def test_configuration_error_returns_2_and_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = StringIO()
    console = Console(
        file=output,
        color_system=None,
        force_terminal=False,
        width=160,
    )

    def fail_to_load(path: Path) -> AppConfig:
        assert path == Path("broken.yaml")
        raise ConfigError("invalid [red]configuration[/red]\x1b[31m\nnext line")

    monkeypatch.setattr(cli, "load_config", fail_to_load)

    exit_code = main(
        ["example.com", "--config", "broken.yaml"],
        console=console,
    )

    rendered = output.getvalue()
    assert exit_code == 2
    assert "Configuration error:" in rendered
    assert "[red]configuration[/red]" in rendered
    assert "\x1b" not in rendered
    assert "next line" in rendered


def test_malformed_yaml_cli_error_does_not_disclose_source_content(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "broken.yaml"
    config_path.write_text(
        "version: 1\nsources: [TOP_SECRET_VALUE\n",
        encoding="utf-8",
    )
    output = StringIO()
    console = Console(
        file=output,
        color_system=None,
        force_terminal=False,
        width=160,
    )

    exit_code = main(
        ["example.com", "--config", str(config_path)],
        console=console,
    )

    rendered = output.getvalue()
    assert exit_code == 2
    assert "Configuration error: invalid YAML configuration at line " in rendered
    assert ", column " in rendered
    assert "TOP_SECRET_VALUE" not in rendered
    assert "sources:" not in rendered


def test_main_runs_scan_inside_rich_spinner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = make_config()
    spy = SpyConsole()

    monkeypatch.setattr(cli, "load_config", lambda path: config)

    async def fake_scan(
        target: Target,
        received_config: AppConfig,
    ) -> tuple[CheckResult]:
        assert spy.status_active
        assert target.normalized == "example.com"
        assert received_config is config
        return (make_result(CheckStatus.NOT_LISTED, target=target),)

    monkeypatch.setattr(cli, "scan", fake_scan)

    exit_code = main(
        ["EXAMPLE.COM.", "--config", "blacklists.yaml"],
        console=cast(Console, spy),
    )

    assert exit_code == 0
    assert not spy.status_active
    assert len(spy.status_messages) == 1
    message, spinner = spy.status_messages[0]
    assert isinstance(message, Text)
    assert message.plain == "Checking example.com against configured sources..."
    assert spinner == "dots"
    assert len(spy.printed) == 1
    assert isinstance(spy.printed[0], Table)


def test_result_table_distinguishes_all_statuses_and_sanitizes_details() -> None:
    output = StringIO()
    console = Console(
        file=output,
        color_system=None,
        force_terminal=False,
        width=220,
    )
    target = parse_target("example.com")
    results = (
        make_result(CheckStatus.LISTED, name="listed", target=target),
        make_result(CheckStatus.NOT_LISTED, name="clear", target=target),
        make_result(CheckStatus.SKIPPED, name="skipped", target=target),
        make_result(
            CheckStatus.ERROR,
            name="error [red]literal[/red]",
            target=target,
            error_message="failed [bold]safely[/bold]\x1b[31m\nnext line",
        ),
    )

    render_results(console, target, results)

    rendered = output.getvalue()
    assert "Blacklist results for example.com" in rendered
    assert "LISTED" in rendered
    assert "NOT LISTED" in rendered
    assert "SKIPPED" in rendered
    assert "ERROR" in rendered
    assert "Evidence: example.com" in rendered
    assert "No listing found" in rendered
    assert "target type is unsupported" in rendered
    assert "http_connection: failed [bold]safely[/bold] next line" in rendered
    assert "error [red]literal[/red]" in rendered
    assert "\x1b" not in rendered


@pytest.mark.parametrize(
    ("statuses", "expected_exit_code"),
    [
        ((CheckStatus.NOT_LISTED, CheckStatus.SKIPPED), 0),
        ((CheckStatus.LISTED, CheckStatus.NOT_LISTED), 1),
        ((CheckStatus.ERROR, CheckStatus.NOT_LISTED), 3),
        ((CheckStatus.LISTED, CheckStatus.ERROR), 3),
    ],
)
def test_exit_code_precedence(
    statuses: tuple[CheckStatus, ...],
    expected_exit_code: int,
) -> None:
    results = tuple(
        make_result(status, name=f"source-{index}")
        for index, status in enumerate(statuses)
    )

    assert exit_code_for_results(results) == expected_exit_code


def test_unexpected_scan_failure_returns_3_without_exception_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = StringIO()
    console = Console(
        file=output,
        color_system=None,
        force_terminal=False,
        width=160,
    )
    monkeypatch.setattr(cli, "load_config", lambda path: make_config())

    async def fail_scan(target: Target, config: AppConfig) -> tuple[CheckResult, ...]:
        raise RuntimeError("secret response body")

    monkeypatch.setattr(cli, "scan", fail_scan)

    exit_code = main(
        ["example.com", "--config", "blacklists.yaml"],
        console=console,
    )

    rendered = output.getvalue()
    assert exit_code == 3
    assert "Scan error: the scan could not be completed" in rendered
    assert "secret response body" not in rendered
