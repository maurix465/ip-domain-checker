"""Verify that the release container is clean and runs without root."""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from pathlib import Path

RUNTIME_ROOTS = (
    Path("/opt/venv"),
    Path("/usr/local/lib/python3.12/site-packages"),
)
UNWANTED_PATHS = (
    Path("/app"),
    Path("/build"),
    Path("/usr/local/lib/python3.12/ensurepip"),
    Path("/wheels"),
)
UNWANTED_SUFFIXES = frozenset({".pyc", ".pyd", ".pyo"})
BUILD_MODULES = ("build", "pip", "setuptools", "wheel")


def _generated_paths() -> list[Path]:
    generated: list[Path] = []
    for root in RUNTIME_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if (
                path.name == "__pycache__"
                or path.name.endswith(".egg-info")
                or (path.is_file() and path.suffix in UNWANTED_SUFFIXES)
            ):
                generated.append(path)
    return generated


def _files_containing(tokens: tuple[bytes, ...]) -> list[Path]:
    contaminated: list[Path] = []
    for root in RUNTIME_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            try:
                content = path.read_bytes()
            except OSError:
                continue
            if any(token in content for token in tokens):
                contaminated.append(path)
    return contaminated


def verify_runtime(forbidden_text: tuple[str, ...]) -> list[str]:
    """Return descriptions of runtime-image hygiene failures."""
    errors: list[str] = []
    if os.getuid() == 0:
        errors.append("container process runs as root")
    if Path(sys.prefix) != Path("/opt/venv"):
        errors.append(f"unexpected Python prefix: {sys.prefix}")

    present_unwanted_paths = [str(path) for path in UNWANTED_PATHS if path.exists()]
    if present_unwanted_paths:
        errors.append(f"build/source directories remain: {present_unwanted_paths}")

    generated = _generated_paths()
    if generated:
        errors.append(
            "generated Python or host package metadata remains: "
            f"{[str(path) for path in generated]}"
        )

    build_modules = [
        module for module in BUILD_MODULES if importlib.util.find_spec(module)
    ]
    if build_modules:
        errors.append(f"build-time Python modules remain importable: {build_modules}")

    tokens = tuple(
        value.encode()
        for value in ("HOST_BUILD_CONTEXT_SENTINEL", *forbidden_text)
        if value
    )
    contaminated = _files_containing(tokens)
    if contaminated:
        errors.append(
            "runtime files contain host build-context text: "
            f"{[str(path) for path in contaminated]}"
        )
    return errors


def main() -> int:
    """Run container-runtime verification from the command line."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--forbidden-text",
        action="append",
        default=[],
        help="additional host path or marker that must not occur in runtime files",
    )
    arguments = parser.parse_args()
    errors = verify_runtime(tuple(arguments.forbidden_text))
    if errors:
        for error in errors:
            print(f"container verification failed: {error}", file=sys.stderr)
        return 1
    print(f"Verified clean non-root container runtime (uid={os.getuid()}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
