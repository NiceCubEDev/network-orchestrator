#!/usr/bin/env python3
"""Release lines of Network Orchestrator (see docs/versioning.md).

versions.toml holds one version per line: core, macos, linux, windows.

  versions.py get <line>              print a line's version
  versions.py set <line> <X.Y.Z>      change it and sync everything
  versions.py sync                    write the versions into the crates and configs
  versions.py check                   exit 1 if any crate or config drifted
  versions.py affected [<git-range>]  lines touched by the changed files
  versions.py prepare LINE=VERSION [LINE=VERSION ...] [--dry-run]
                                     prepare changelogs, versions, lockfile and checks
"""
import argparse
from datetime import date
import json
import pathlib
import re
import shutil
import subprocess
import sys

LINES = ("core", "macos", "linux", "windows")

# Crates that belong to one line carry that line's version in Cargo.toml.
CRATES = {
    "crates/core": "core",
    "crates/engine": "core",
    "crates/macos-bridge": "macos",
    "crates/macos-helper": "macos",
    "crates/daemon": "linux",
}
# Crates shipped by two lines: Cargo.toml says 0.0.0 and the build script
# reads versions.toml for the target operating system.
SHARED_CRATES = {
    "crates/cli": ("macos", "linux"),
    "src-tauri": ("linux", "windows"),
}
SHARED_PLACEHOLDER = "0.0.0"
# Tauri merges tauri.<platform>.conf.json into tauri.conf.json, so each
# platform's bundle gets its own line's version.
TAURI_CONFIGS = {
    "linux": "src-tauri/tauri.linux.conf.json",
    "windows": "src-tauri/tauri.windows.conf.json",
}
# Which lines a changed file belongs to, first match wins.
PATH_LINES = [
    ("crates/core/", ("core",)),
    ("crates/engine/", ("core",)),
    ("crates/macos-bridge/", ("macos",)),
    ("crates/macos-helper/", ("macos",)),
    ("macos/", ("macos",)),
    ("crates/daemon/", ("linux",)),
    ("packaging/", ("linux",)),
    ("e2e/linux/", ("linux",)),
    ("crates/cli/src/linux/", ("linux",)),
    ("crates/cli/", ("macos",)),
    ("src-tauri/", ("linux", "windows")),
    ("src/", ("linux", "windows")),
    ("locales/", ("macos", "linux", "windows")),
    ("design/", ("macos", "linux", "windows")),
]
SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")


def version_key(version):
    base, _, prerelease = version.partition("-")
    numbers = base.split(".")
    prerelease_ids = prerelease.split(".") if prerelease else []
    if any(not re.fullmatch(r"0|[1-9][0-9]*", item) for item in numbers) or any(
        not item or (item.isdigit() and len(item) > 1 and item.startswith("0"))
        for item in prerelease_ids
    ):
        raise SystemExit(f"Invalid release version: {version!r}")
    identifiers = tuple(
        (0, int(item)) if item.isdigit() else (1, item) for item in prerelease_ids
    )
    return tuple(map(int, numbers)), not prerelease, identifiers


class Repo:
    def __init__(self, root):
        self.root = pathlib.Path(root)

    def versions(self):
        # versions.toml is [line] / version = "x" only, so no TOML library
        # (the system Python on macOS is too old to have one).
        data: dict[str, dict[str, str]] = {}
        section = None
        for raw in (self.root / "versions.toml").read_text().splitlines():
            text = raw.split("#", 1)[0].strip()
            header = re.fullmatch(r"\[([a-z]+)\]", text)
            if header:
                section = header.group(1)
                continue
            pair = re.fullmatch(r'version\s*=\s*"([^"]*)"', text)
            if pair and section:
                data.setdefault(section, {})["version"] = pair.group(1)
        out = {}
        for line in LINES:
            version = data.get(line, {}).get("version")
            if not version or not SEMVER.match(version):
                raise SystemExit(f"versions.toml: [{line}] needs a version like 1.2.3")
            out[line] = version
        return out

    def expected(self):
        """Every managed file and the version it must carry."""
        versions = self.versions()
        out = {}
        for crate, line in CRATES.items():
            out[f"{crate}/Cargo.toml"] = versions[line]
        for crate in SHARED_CRATES:
            out[f"{crate}/Cargo.toml"] = SHARED_PLACEHOLDER
        for line, path in TAURI_CONFIGS.items():
            out[path] = versions[line]
        return out

    def _read_version(self, relative):
        text = (self.root / relative).read_text()
        if relative.endswith(".json"):
            return json.loads(text).get("version")
        match = re.search(r'(?ms)^\[package\].*?^version\s*=\s*"([^"]+)"', text)
        return match.group(1) if match else None

    def check(self):
        problems = []
        for relative, want in self.expected().items():
            path = self.root / relative
            if not path.exists():
                problems.append(f"{relative}: missing (run sync)")
                continue
            have = self._read_version(relative)
            if have != want:
                problems.append(f"{relative}: {have!r}, versions.toml says {want!r}")
        return problems

    def sync(self):
        changed = []
        for relative, want in self.expected().items():
            path = self.root / relative
            if relative.endswith(".json"):
                document = {}
                if path.exists():
                    document = json.loads(path.read_text())
                if document.get("version") == want and path.exists():
                    continue
                document = {"version": want, **{k: v for k, v in document.items() if k != "version"}}
                path.write_text(json.dumps(document, indent=2) + "\n")
            else:
                text = path.read_text()
                new = re.sub(
                    r'(?ms)(^\[package\].*?^)(version\.workspace\s*=\s*true|version\s*=\s*"[^"]*")',
                    lambda m: f'{m.group(1)}version = "{want}"',
                    text,
                    count=1,
                )
                if new == text:
                    continue
                path.write_text(new)
            changed.append(relative)
        return changed

    def set_version(self, line, version):
        if line not in LINES:
            raise SystemExit(f"unknown line {line!r}; one of {', '.join(LINES)}")
        if not SEMVER.match(version):
            raise SystemExit(f"{version!r} is not a semantic version like 1.2.3")
        path = self.root / "versions.toml"
        text = path.read_text()
        new, count = re.subn(
            rf'(?ms)(^\[{line}\].*?^version\s*=\s*)"[^"]*"', rf'\g<1>"{version}"', text, count=1
        )
        if count != 1:
            raise SystemExit(f"versions.toml has no [{line}] version")
        path.write_text(new)
        return self.sync()

    def prepare(self, updates, release_date, dry_run=False):
        """Plan every selected line before changing any version or changelog."""
        current = self.versions()
        if not updates:
            raise SystemExit("Select at least one release line")
        proposed = dict(current, **updates)
        changelogs = {}
        for line, version in updates.items():
            if line not in LINES or not SEMVER.fullmatch(version):
                raise SystemExit(f"Invalid release: {line}={version}")
            if version_key(version) <= version_key(current[line]):
                raise SystemExit(f"{line}: release version must be newer than {current[line]}")
            path = self.root / f"changelog/{line}.md"
            text = path.read_text()
            sections = list(re.finditer(r"(?m)^## \[Unreleased\][ \t]*$", text))
            if len(sections) != 1:
                raise SystemExit(f"{path.name}: expected one Unreleased section")
            if re.search(rf"(?m)^## \[{re.escape(version)}\](?:[ \t]|$)", text):
                raise SystemExit(f"{path.name}: version {version} is already documented")
            section = sections[0]
            following = re.search(r"(?m)^## ", text[section.end():])
            end = section.end() + following.start() if following else len(text)
            notes = text[section.end():end].strip()
            if not notes:
                raise SystemExit(f"{path.name}: Unreleased has no notes")
            core = "" if line == "core" else f"Core {proposed['core']}.\n\n"
            changelogs[line] = (
                f"{text[:section.end()]}\n\n## [{version}] - {release_date}\n\n"
                f"{core}{notes}\n\n{text[end:]}"
            )
        if not dry_run:
            for line in LINES:
                if line in updates:
                    self.set_version(line, updates[line])
            for line, text in changelogs.items():
                (self.root / f"changelog/{line}.md").write_text(text)
        return [
            f"{line}: {current[line]} -> {updates[line]} ({release_date})"
            for line in LINES if line in updates
        ]


def lines_for(path):
    for prefix, lines in PATH_LINES:
        if path.startswith(prefix):
            return lines
    return ()


def affected(paths):
    """Lines touched by `paths`; core changes reach every product."""
    found = set()
    for path in paths:
        found.update(lines_for(path))
    return [line for line in LINES if line in found]


def prepare_release(repo, argv):
    parser = argparse.ArgumentParser(prog="versions.py prepare")
    parser.add_argument("releases", nargs="+", metavar="LINE=VERSION")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    updates = {}
    for release in args.releases:
        line, separator, version = release.partition("=")
        if not separator or line in updates:
            parser.error("Use distinct LINE=VERSION arguments")
        updates[line] = version
    release_date = date.today().isoformat()
    for item in repo.prepare(updates, release_date, dry_run=True):
        print("would prepare" if args.dry_run else "prepare", item, flush=True)
    if args.dry_run:
        return 0
    programs: dict[str, str] = {}
    for name in ("git", "cargo", "npm"):
        executable = shutil.which(name)
        if executable is None:
            raise SystemExit(f"Install required tool before preparing: {name}")
        programs[name] = executable
    dirty = subprocess.check_output(
        [programs["git"], "status", "--porcelain"], cwd=repo.root, text=True
    )
    if dirty:
        raise SystemExit("Commit or stash existing changes before preparing a release")
    try:
        repo.prepare(updates, release_date)
        excluded = [] if sys.platform == "darwin" else [
            "--exclude", "net-manager-macos-bridge",
            "--exclude", "network-orchestrator-macos-helper",
        ]
        cargo = programs["cargo"]
        commands = [
            [sys.executable, "scripts/versions.py", "check"],
            [sys.executable, "-m", "unittest", "scripts/test_versions.py"],
            [cargo, "fmt", "--all", "--", "--check"],
            [cargo, "check", "--workspace", "--all-targets", *excluded],
            [cargo, "clippy", "--workspace", "--all-targets", *excluded, "--", "-D", "warnings"],
            [cargo, "test", "--workspace", *excluded],
            [programs["npm"], "run", "build"],
        ]
        for command in commands:
            print("+", *command, flush=True)
            subprocess.run(command, cwd=repo.root, check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"Release preparation failed: {error}", file=sys.stderr)
        print("Review retained edits; no commits, tags or pushes were made.", file=sys.stderr)
        return 1
    print(f"Release preparation passed the {sys.platform} host quality gate.")
    print("Review the edits before committing; other platforms still need native validation.")
    return 0


def main(argv):
    repo = Repo(pathlib.Path(__file__).resolve().parent.parent)
    if not argv:
        print(__doc__)
        return 2
    command, rest = argv[0], argv[1:]
    if command == "get" and len(rest) == 1:
        print(repo.versions()[rest[0]])
    elif command == "set" and len(rest) == 2:
        for path in repo.set_version(*rest):
            print("updated", path)
    elif command == "sync":
        for path in repo.sync():
            print("updated", path)
    elif command == "check":
        problems = repo.check()
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0
    elif command == "affected":
        span = rest[0] if rest else "origin/main...HEAD"
        files = subprocess.check_output(
            ["git", "-C", str(repo.root), "diff", "--name-only", span], text=True
        ).split()
        print(" ".join(affected(files)))
    elif command == "prepare":
        return prepare_release(repo, rest)
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
