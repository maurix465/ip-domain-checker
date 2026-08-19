"""Command-line interface for the blacklist checker."""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Sequence
from pathlib import Path

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from blacklist_checker.config import ConfigError, load_config
from blacklist_checker.core import scan
from blacklist_checker.models import CheckResult, CheckStatus, Target
from blacklist_checker.utils import TargetValidationError, parse_target

_STATUS_STYLES = {
    CheckStatus.LISTED: "bold red",
    CheckStatus.NOT_LISTED: "green",
    CheckStatus.SKIPPED: "yellow",
    CheckStatus.ERROR: "bold magenta",
}


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="check-blacklist",
        description=(
            "Check an IP address or domain against configured blacklist and "
            "threat intelligence sources."
        ),
    )
    parser.add_argument(
        "target",
        help="IPv4 address, IPv6 address, or dotted domain name to check",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        required=True,
        metavar="PATH",
        help="path to the YAML blacklist configuration file",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    console: Console | None = None,
) -> int:
    """Run the command-line application."""
    parser = build_parser()
    arguments = parser.parse_args(argv)

    try:
        target = parse_target(arguments.target)
    except TargetValidationError as error:
        parser.error(str(error))

    output_console = console if console is not None else Console()
    error_console = console if console is not None else Console(stderr=True)

    try:
        config = load_config(arguments.config)
    except ConfigError as error:
        _print_error(error_console, "Configuration error", str(error))
        return 2

    spinner_message = Text.assemble(
        "Checking ",
        (_sanitize_display_text(target.normalized), "bold"),
        " against configured sources...",
    )
    try:
        with output_console.status(spinner_message, spinner="dots"):
            results = asyncio.run(scan(target, config))
    except Exception:
        _print_error(
            error_console,
            "Scan error",
            "the scan could not be completed",
        )
        return 3

    render_results(output_console, target, results)
    return exit_code_for_results(results)


def render_results(
    console: Console,
    target: Target,
    results: Sequence[CheckResult],
) -> None:
    """Render ordered scan results as a Rich table."""
    table = Table(
        title=Text.assemble(
            "Blacklist results for ",
            (_sanitize_display_text(target.normalized), "bold"),
        ),
        box=box.SIMPLE_HEAVY,
        show_lines=False,
    )
    table.add_column("Source", no_wrap=True)
    table.add_column("Kind", no_wrap=True)
    table.add_column("Category", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Details")

    for result in results:
        status_label = result.status.value.replace("_", " ").upper()
        table.add_row(
            Text(_sanitize_display_text(result.source_name)),
            Text(result.source_kind.value.replace("_", " ").upper()),
            Text(_sanitize_display_text(result.category)),
            Text(status_label, style=_STATUS_STYLES[result.status]),
            Text(_result_details(result)),
        )

    console.print(table)


def exit_code_for_results(results: Sequence[CheckResult]) -> int:
    """Return the documented process exit code for completed results."""
    if any(result.status is CheckStatus.ERROR for result in results):
        return 3
    if any(result.status is CheckStatus.LISTED for result in results):
        return 1
    return 0


def _result_details(result: CheckResult) -> str:
    if result.status is CheckStatus.LISTED:
        details = f"Evidence: {', '.join(result.evidence)}"
    elif result.status is CheckStatus.NOT_LISTED:
        details = "No listing found"
    elif result.status is CheckStatus.SKIPPED:
        details = result.reason or "Source was skipped"
    elif result.failure is None:
        details = "unexpected: source check failed"
    else:
        details = f"{result.failure.kind.value}: {result.failure.message}"
    return _sanitize_display_text(details)


def _print_error(console: Console, label: str, message: str) -> None:
    console.print(
        Text.assemble(
            (f"{label}: ", "bold red"),
            _sanitize_display_text(message),
        )
    )


def _sanitize_display_text(value: str) -> str:
    without_ansi = Text.from_ansi(value).plain
    printable = "".join(
        character if character.isprintable() else " " for character in without_ansi
    )
    return " ".join(printable.split())


if __name__ == "__main__":
    raise SystemExit(main())
