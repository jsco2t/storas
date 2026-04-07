#!/usr/bin/env python3
"""Create the next semver release tag for this repository.

Usage:
    python3 scripts/tag-release.py <patch|minor|major>
"""

import re
import subprocess
import sys

SEMVER_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
RELEASE_KINDS = ("patch", "minor", "major")


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


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in RELEASE_KINDS:
        print(f"usage: {sys.argv[0]} <{'|'.join(RELEASE_KINDS)}>", file=sys.stderr)
        sys.exit(1)

    kind = sys.argv[1]
    versions = existing_versions()
    tag = "v{}.{}.{}".format(*next_version(kind, versions))

    subprocess.run(["git", "tag", tag], check=True)
    print(f"Tagged {tag}. To push: git push origin {tag}")


if __name__ == "__main__":
    main()
