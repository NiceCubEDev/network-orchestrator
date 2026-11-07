#!/usr/bin/env python3
"""Wrap built Debian packages into one downloadable .run per client.

No packages are installed by this builder. Run on a build host with dpkg-deb.
The installer itself needs only the normal Debian/Ubuntu system tools.
"""
import argparse
import gzip
import hashlib
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile

from versions import Repo

ROOT = Path(__file__).resolve().parent.parent
DAEMON = "network-orchestrator-daemon"


def fields(path):
    result = subprocess.run(["dpkg-deb", "--field", str(path.resolve())], check=True,
                            stdout=subprocess.PIPE, text=True)
    # Only top-level fields are used; continuation lines belong to descriptions.
    return dict(line.split(": ", 1) for line in result.stdout.splitlines()
                if line and not line[0].isspace() and ": " in line)


def validate(path, package, version, arch=None):
    info = fields(path)
    if info.get("Package") != package or info.get("Version") != version:
        raise ValueError(f"Expected {package} {version}; rebuild the Debian packages first")
    actual_arch = info.get("Architecture", "")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", actual_arch) or actual_arch == "all":
        raise ValueError("A native architecture is required")
    if arch and actual_arch != arch:
        raise ValueError("Client and daemon architectures must match")
    if package != DAEMON:
        dependency = re.search(r"(?:^|,)\s*network-orchestrator-daemon\s*\(>=\s*([^\s)]+)\)",
                               info.get("Depends", ""))
        if not dependency:
            raise ValueError("The client must declare a versioned daemon dependency")
        valid = subprocess.run(["dpkg", "--compare-versions", version, "ge", dependency[1]])
        if valid.returncode:
            raise ValueError("The included daemon does not satisfy the client's dependency")
    return actual_arch


def bundle(client, daemon, package, version, release, arch, out_dir, cli=None):
    template = (ROOT / "packaging/linux/installer.sh.in").read_text()
    # Stream the payload; the pinned backend can be tens of megabytes.
    with tempfile.TemporaryFile() as payload:
        with gzip.GzipFile(fileobj=payload, mode="wb", filename="", mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w|") as archive:
                packages = [(client, "client.deb"), (daemon, "daemon.deb")]
                if cli:
                    packages.append((cli, "netorch.deb"))
                for path, name in packages:
                    entry = tarfile.TarInfo(name)
                    entry.size = path.stat().st_size
                    entry.mode = 0o644
                    with path.open("rb") as source:
                        archive.addfile(entry, source)
        payload.seek(0)
        checksum = hashlib.sha256()
        for chunk in iter(lambda: payload.read(1024 * 1024), b""):
            checksum.update(chunk)
        values = {"CLIENT": package, "VERSION": version, "ARCH": arch,
                  "WITH_CLI": "yes" if cli else "no",
                  "PAYLOAD_SHA256": checksum.hexdigest(),
                  "PAYLOAD_LINE": str(template.count("\n") + 1)}
        for key, value in values.items():
            template = template.replace(f"@{key}@", shlex.quote(value))
        destination = out_dir / f"{package}-{release}-{arch}.run"
        staged = None
        try:
            with tempfile.NamedTemporaryFile(dir=out_dir, delete=False) as output:
                staged = Path(output.name)
                output.write(template.encode())
                payload.seek(0)
                shutil.copyfileobj(payload, output)
            staged.chmod(0o755)
            staged.replace(destination)
        finally:
            if staged and staged.exists():
                staged.unlink()
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", type=Path, required=True)
    parser.add_argument("--cli", type=Path)
    parser.add_argument("--gui", type=Path)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "target/release/installers")
    args = parser.parse_args()
    if not args.cli and not args.gui:
        parser.error("provide --cli and/or --gui")
    if args.gui and not args.cli:
        parser.error("the GUI installer requires --cli for its shared user runtime")
    release = Repo(ROOT).versions()["linux"]
    version = release.replace("-", "~", 1)
    try:
        arch = validate(args.daemon, DAEMON, version)
        clients = [(args.cli, "netorch"), (args.gui, "network-orchestrator")]
        # Validate all inputs before publishing either artifact.
        for path, package in clients:
            if path:
                validate(path, package, version, arch)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for path, package in clients:
            if path:
                print(bundle(path, args.daemon, package, version, release, arch, args.output_dir,
                             args.cli if package == "network-orchestrator" else None))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Cannot build installer: {error}\n")


if __name__ == "__main__":
    main()
