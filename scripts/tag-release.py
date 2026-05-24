#!/usr/bin/env python3
"""Create the next semver release tag for this repository.

Usage:
    python3 scripts/tag-release.py <patch|minor|major>
"""

import re
import subprocess
import sys
from pathlib import Path

SEMVER_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
RELEASE_KINDS = ("patch", "minor", "major")
CHANGELOG_PATH = Path(__file__).resolve().parent.parent / "CHANGELOG.md"


def existing_versions() -> list[tuple[int, int, int]]:
    result = subprocess.run(
        ["git", "tag", "--list"],
        check=True,
        capture_output=True,
        text=True,
    )
    versions = []
    for line in result.stdout.splitlines():
        m = SEMVER_RE.match(line.strip())
        if m:
            versions.append((int(m.group(1)), int(m.group(2)), int(m.group(3))))
    return sorted(versions)


def next_version(kind: str, versions: list[tuple[int, int, int]]) -> tuple[int, int, int]:
    major, minor, patch = versions[-1] if versions else (0, 0, 0)
    if kind == "major":
        return major + 1, 0, 0
    if kind == "minor":
        return major, minor + 1, 0
    return major, minor, patch + 1


def verify_changelog_entry(version: str) -> None:
    """Fail with an actionable error if CHANGELOG.md is missing an entry for `version`.

    Checks both the section heading (`## [X.Y.Z]`) and the link reference
    (`[X.Y.Z]: ...`) — both are required by the Keep a Changelog format
    this project follows.
    """
    if not CHANGELOG_PATH.is_file():
        print(f"error: {CHANGELOG_PATH} not found; cannot verify release entry", file=sys.stderr)
        sys.exit(1)

    text = CHANGELOG_PATH.read_text()
    heading_re = re.compile(rf"^## \[{re.escape(version)}\](?:\s|$)", re.MULTILINE)
    link_re = re.compile(rf"^\[{re.escape(version)}\]:\s+\S+", re.MULTILINE)

    missing = []
    if not heading_re.search(text):
        missing.append(f"`## [{version}]` section heading")
    if not link_re.search(text):
        missing.append(f"`[{version}]: <url>` link reference")

    if missing:
        print(
            f"error: CHANGELOG.md is missing required entries for {version}:",
            file=sys.stderr,
        )
        for item in missing:
            print(f"  - {item}", file=sys.stderr)
        print(
            "\nAdd the entry under [Unreleased] before tagging the release.",
            file=sys.stderr,
        )
        sys.exit(1)


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in RELEASE_KINDS:
        print(f"usage: {sys.argv[0]} <{'|'.join(RELEASE_KINDS)}>", file=sys.stderr)
        sys.exit(1)

    kind = sys.argv[1]
    versions = existing_versions()
    version = "{}.{}.{}".format(*next_version(kind, versions))
    tag = f"v{version}"

    verify_changelog_entry(version)

    subprocess.run(["git", "tag", tag], check=True)
    print(f"Tagged {tag}. To push: git push origin {tag}")


if __name__ == "__main__":
    main()
