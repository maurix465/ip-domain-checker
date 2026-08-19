"""Verify the contents promised for release archives."""

from __future__ import annotations

import argparse
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

REQUIRED_SDIST_PATHS = frozenset(
    {
        "LICENSE",
        "MANIFEST.in",
        "README.md",
        "examples/blacklists.yaml",
        "examples/lists/local.txt",
        "examples/public-blacklists.yaml",
        "pyproject.toml",
        "src/blacklist_checker/__init__.py",
        "src/blacklist_checker/checkers.py",
        "src/blacklist_checker/cli.py",
        "src/blacklist_checker/config.py",
        "src/blacklist_checker/core.py",
        "src/blacklist_checker/models.py",
        "src/blacklist_checker/utils.py",
    }
)
REQUIRED_WHEEL_PATHS = frozenset(
    {
        "blacklist_checker/__init__.py",
        "blacklist_checker/checkers.py",
        "blacklist_checker/cli.py",
        "blacklist_checker/config.py",
        "blacklist_checker/core.py",
        "blacklist_checker/models.py",
        "blacklist_checker/utils.py",
    }
)
GENERATED_SUFFIXES = frozenset({".pyc", ".pyd", ".pyo"})


class ArtifactVerificationError(RuntimeError):
    """A release archive does not match the distribution contract."""


def _select_one(dist_dir: Path, pattern: str, artifact_name: str) -> Path:
    matches = sorted(dist_dir.glob(pattern))
    if len(matches) != 1:
        raise ArtifactVerificationError(
            f"expected exactly one {artifact_name} in {dist_dir}, found {len(matches)}"
        )
    return matches[0]


def _validate_archive_names(names: set[str], artifact_name: str) -> None:
    unsafe = {
        name
        for name in names
        if PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts
    }
    if unsafe:
        raise ArtifactVerificationError(
            f"{artifact_name} contains unsafe paths: {sorted(unsafe)}"
        )

    generated = {
        name
        for name in names
        if "__pycache__" in PurePosixPath(name).parts
        or PurePosixPath(name).suffix in GENERATED_SUFFIXES
    }
    if generated:
        raise ArtifactVerificationError(
            f"{artifact_name} contains generated Python files: {sorted(generated)}"
        )


def _sdist_paths(sdist: Path) -> set[str]:
    with tarfile.open(sdist, "r:gz") as archive:
        member_names = {member.name for member in archive.getmembers()}

    _validate_archive_names(member_names, "sdist")
    roots = {
        PurePosixPath(name).parts[0]
        for name in member_names
        if PurePosixPath(name).parts
    }
    if len(roots) != 1:
        raise ArtifactVerificationError(
            f"sdist must have one top-level directory, found {sorted(roots)}"
        )
    root = next(iter(roots))
    return {
        str(PurePosixPath(*PurePosixPath(name).parts[1:]))
        for name in member_names
        if PurePosixPath(name).parts[0] == root and len(PurePosixPath(name).parts) > 1
    }


def _wheel_paths(wheel: Path) -> set[str]:
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
    _validate_archive_names(names, "wheel")
    return names


def _require_paths(
    paths: set[str],
    required: frozenset[str],
    artifact_name: str,
) -> None:
    missing = required - paths
    if missing:
        raise ArtifactVerificationError(
            f"{artifact_name} is missing required paths: {sorted(missing)}"
        )


def _is_source_only_wheel_path(name: str) -> bool:
    parts = PurePosixPath(name).parts
    return (
        "examples" in parts
        or (bool(parts) and parts[0] in {"scripts", "tests"})
        or any(part.endswith(".egg-info") for part in parts)
    )


def verify_artifacts(dist_dir: Path) -> tuple[Path, Path]:
    """Verify one sdist and one wheel in ``dist_dir`` and return their paths."""
    sdist = _select_one(dist_dir, "*.tar.gz", "source distribution")
    wheel = _select_one(dist_dir, "*.whl", "wheel")

    sdist_paths = _sdist_paths(sdist)
    _require_paths(sdist_paths, REQUIRED_SDIST_PATHS, "sdist")

    wheel_paths = _wheel_paths(wheel)
    _require_paths(wheel_paths, REQUIRED_WHEEL_PATHS, "wheel")
    dist_info_roots = {
        PurePosixPath(name).parts[0]
        for name in wheel_paths
        if PurePosixPath(name).parts
        and PurePosixPath(name).parts[0].endswith(".dist-info")
    }
    if len(dist_info_roots) != 1:
        raise ArtifactVerificationError(
            "wheel must contain exactly one .dist-info directory, found "
            f"{sorted(dist_info_roots)}"
        )
    dist_info = next(iter(dist_info_roots))
    _require_paths(
        wheel_paths,
        frozenset(
            {
                f"{dist_info}/METADATA",
                f"{dist_info}/RECORD",
                f"{dist_info}/WHEEL",
                f"{dist_info}/entry_points.txt",
            }
        ),
        "wheel",
    )
    unexpected_wheel_paths = {
        name for name in wheel_paths if _is_source_only_wheel_path(name)
    }
    if unexpected_wheel_paths:
        raise ArtifactVerificationError(
            f"wheel contains source-only files: {sorted(unexpected_wheel_paths)}"
        )

    print(
        f"Verified {sdist.name} ({len(sdist_paths)} paths) and "
        f"{wheel.name} ({len(wheel_paths)} paths)."
    )
    return sdist, wheel


def main() -> int:
    """Run artifact-content verification from the command line."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "dist_dir",
        nargs="?",
        type=Path,
        default=Path("dist"),
        help="directory containing exactly one sdist and one wheel (default: dist)",
    )
    arguments = parser.parse_args()

    try:
        verify_artifacts(arguments.dist_dir)
    except (
        ArtifactVerificationError,
        OSError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as error:
        print(f"artifact verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
