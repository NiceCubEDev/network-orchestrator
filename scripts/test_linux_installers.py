"""Installer contract tests: synthetic .debs and fake package/service commands only."""
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
DAEMON = "network-orchestrator-daemon"


def deb(path, package, version="0.10.1", arch="amd64", minimum="0.10.0"):
    control = f"Package: {package}\nVersion: {version}\nArchitecture: {arch}\n"
    control += "Maintainer: Installer Tests <tests@example.test>\nDescription: Synthetic installer fixture\n"
    if package != DAEMON:
        control += f"Depends: {DAEMON} (>= {minimum})\n"
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        member = tarfile.TarInfo("./control")
        member.size = len(control.encode())
        member.mode = 0o644
        archive.addfile(member, io.BytesIO(control.encode()))
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for name in ["usr", "usr/share", "usr/share/netorch-installer-fixture"]:
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE
            member.mode = 0o755
            archive.addfile(member)
        body = version.encode()
        member = tarfile.TarInfo(f"usr/share/netorch-installer-fixture/{package}.txt")
        member.size = len(body)
        member.mode = 0o644
        archive.addfile(member, io.BytesIO(body))
    with path.open("wb") as output:
        output.write(b"!<arch>\n")
        for name, body in [("debian-binary", b"2.0\n"), ("control.tar.gz", stream.getvalue()), ("data.tar.gz", data.getvalue())]:
            header = f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(body):<10}`\n"
            output.write(header.encode() + body + (b"\n" if len(body) % 2 else b""))


def metadata(path):
    with Path(path).open("rb") as source:
        assert source.read(8) == b"!<arch>\n"
        while header := source.read(60):
            size = int(header[48:58])
            body = source.read(size)
            source.read(size % 2)
            if header[:16].decode().strip().rstrip("/") == "control.tar.gz":
                with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
                    text = archive.extractfile("./control").read().decode()
                return dict(line.split(": ", 1) for line in text.splitlines())
    raise AssertionError("missing control")


def fixture_source(repo, version="0.10.1"):
    """Copy the real builder/template with an isolated release document."""
    (repo / "scripts").mkdir(parents=True, exist_ok=True)
    (repo / "packaging/linux").mkdir(parents=True, exist_ok=True)
    for name in ["package-linux-installers.py", "versions.py"]:
        shutil.copyfile(ROOT / "scripts" / name, repo / "scripts" / name)
    shutil.copyfile(ROOT / "packaging/linux/installer.sh.in", repo / "packaging/linux/installer.sh.in")
    versions = (ROOT / "versions.toml").read_text()
    versions = re.sub(r'(?ms)(^\[linux\].*?^version\s*=\s*)"[^"]*"',
                      lambda m: m[1] + f'"{version}"', versions)
    (repo / "versions.toml").write_text(versions)


def version_key(version):
    # Fixtures only; production delegates Debian version ordering to dpkg.
    base, _, pre = version.partition("~")
    return tuple(int(p) for p in base.split(".")), not bool(pre), pre


def fake_tool(tool, args):
    state_path = Path(os.environ["NETORCH_TEST_STATE"])
    state = json.loads(state_path.read_text())
    with Path(os.environ["NETORCH_TEST_LOG"]).open("a") as log:
        log.write(json.dumps([tool, *args]) + "\n")
    if tool == "uname":
        print(state.get("os", "Linux"))
    elif tool == "id":
        print(state.get("uid", 0))
    elif tool == "dpkg-deb":
        for key, value in metadata(args[-1]).items():
            print(f"{key}: {value}")
    elif tool == "dpkg":
        if args[0] == "--print-architecture":
            print(state.get("arch", "amd64"))
        else:
            assert args[0] == "--compare-versions", args
            left, op, right = version_key(args[1]), args[2], version_key(args[3])
            return 0 if {"gt": left > right, "lt": left < right, "ge": left >= right, "eq": left == right}[op] else 1
    elif tool == "dpkg-query":
        if state.get("query_error"):
            return 2
        installed = state.get("packages", {}).get(args[-1])
        if not installed:
            return 1
        print("\t".join([installed.get("status", "installed"), installed["version"], installed.get("arch", "amd64")]))
    elif tool == "apt-get":
        if state.get("apt_error"):
            return 100
        for path in args:
            if path.endswith(".deb"):
                info = metadata(path)
                state.setdefault("packages", {})[info["Package"]] = {"version": info["Version"], "arch": info["Architecture"]}
        state_path.write_text(json.dumps(state))
    elif tool == "apt-mark":
        if args[0] == "showauto":
            for package in args[1:]:
                if state.get("packages", {}).get(package, {}).get("auto", False):
                    print(package)
        else:
            assert args[0] in {"auto", "manual"}, args
            for package in args[1:]:
                state["packages"][package]["auto"] = args[0] == "auto"
            state_path.write_text(json.dumps(state))
    elif tool == "systemctl":
        if args[0] == "show":
            return state.get("systemd_error", 0)
    else:
        raise AssertionError(tool)
    return 0


class LinuxInstallersTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="netorch installer test ")
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        for tool in ["uname", "id", "dpkg", "dpkg-query", "dpkg-deb", "apt-get", "apt-mark", "systemctl"]:
            path = self.bin / tool
            path.write_text(f"#!{sys.executable}\nimport runpy, sys\nsys.argv = [{str(Path(__file__).resolve())!r}, '--fake-tool', {tool!r}, *sys.argv[1:]]\nrunpy.run_path(sys.argv[0], run_name='__main__')\n")
            path.chmod(0o755)
        self.state = self.dir / "state.json"
        self.log = self.dir / "calls.jsonl"
        self.state.write_text("{}")
        self.env = {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                    "NETORCH_TEST_STATE": str(self.state), "NETORCH_TEST_LOG": str(self.log)}
        self.daemon = self.dir / "daemon.deb"
        self.cli = self.dir / "cli.deb"
        self.gui = self.dir / "gui.deb"
        deb(self.daemon, DAEMON)
        deb(self.cli, "netorch")
        deb(self.gui, "network-orchestrator")
        self.out = self.dir / "out"

    def build(self, **changes):
        # A fixture source-of-truth keeps these upgrade scenarios stable across releases.
        repo = self.dir / "source"
        fixture_source(repo)
        args = {"daemon": self.daemon, "cli": self.cli, "gui": self.gui, "output-dir": self.out, **changes}
        command = [sys.executable, str(repo / "scripts/package-linux-installers.py")]
        for key, value in args.items():
            if value is not None:
                command.extend([f"--{key}", str(value)])
        return subprocess.run(command, env=self.env, text=True, capture_output=True)

    def run_installer(self, client="netorch", *args):
        path = self.out / f"{client}-0.10.1-amd64.run"
        return subprocess.run(["sh", str(path), *args], env=self.env, text=True, capture_output=True)

    def installed(self, packages=None, **extra):
        self.state.write_text(json.dumps({"packages": {name: {"version": version} for name, version in (packages or {}).items()}, **extra}))

    def calls(self, tool):
        return [call[1:] for call in map(json.loads, self.log.read_text().splitlines()) if call[0] == tool] if self.log.exists() else []

    def built(self):
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.log.write_text("")

    def assert_no_mutations(self):
        for tool in ["apt-get", "apt-mark", "systemctl"]:
            self.assertEqual(self.calls(tool), [], tool)

    def test_fresh_cli_then_gui_reuses_one_daemon(self):
        self.built()
        result = self.run_installer("netorch", "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        first = self.calls("apt-get")[0]
        self.assertIn("--no-remove", first)
        self.assertIn("--yes", first)
        self.assertEqual(sorted(Path(p).name for p in first if p.endswith(".deb")), ["client.deb", "daemon.deb"])
        self.assertEqual(self.calls("apt-mark"), [["auto", DAEMON]])
        for path in first:
            if path.endswith(".deb"):
                self.assertFalse(Path(path).exists(), "temporary payload must be removed")
        result = self.run_installer("network-orchestrator")
        self.assertEqual(result.returncode, 0, result.stderr)
        second = self.calls("apt-get")[1]
        self.assertEqual([Path(p).name for p in second if p.endswith(".deb")], ["client.deb"])
        self.assertIn("keep", result.stdout)
        self.assertEqual(set(json.loads(self.state.read_text())["packages"]), {DAEMON, "netorch", "network-orchestrator"})
        self.assertNotIn("restart", " ".join(sum(self.calls("systemctl"), [])))

    def test_gui_then_cli_also_reuses_the_daemon(self):
        self.built()
        self.assertEqual(self.run_installer("network-orchestrator").returncode, 0)
        self.assertEqual(
            set(json.loads(self.state.read_text())["packages"]),
            {DAEMON, "netorch", "network-orchestrator"},
            "the GUI must include its netorch runtime on a fresh machine",
        )
        self.assertEqual(self.run_installer().returncode, 0)
        self.assertEqual(sum(p.endswith("daemon.deb") for call in self.calls("apt-get") for p in call), 1)

    def test_upgrade_updates_both_packages(self):
        self.built()
        self.installed({"netorch": "0.10.0", DAEMON: "0.10.0"})
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("update"), 2)
        packages = json.loads(self.state.read_text())["packages"]
        self.assertTrue(all(p["version"] == "0.10.1" for p in packages.values()))
        self.assertFalse(packages[DAEMON].get("auto", False))

    def test_gui_upgrade_preserves_auto_marks_of_shared_runtime(self):
        self.built()
        self.installed({"netorch": "0.10.0", DAEMON: "0.10.0", "network-orchestrator": "0.10.0"})
        state = json.loads(self.state.read_text())
        state["packages"][DAEMON]["auto"] = True
        state["packages"]["netorch"]["auto"] = True
        self.state.write_text(json.dumps(state))
        result = self.run_installer("network-orchestrator")
        self.assertEqual(result.returncode, 0, result.stderr)
        packages = json.loads(self.state.read_text())["packages"]
        self.assertTrue(packages[DAEMON].get("auto", False))
        self.assertTrue(packages["netorch"].get("auto", False))

    def test_same_version_does_not_reinstall(self):
        self.built()
        self.installed({"netorch": "0.10.1", DAEMON: "0.10.1"})
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls("apt-get"), [])
        self.assertIn(["enable", "--now", "network-orchestrator.service"], self.calls("systemctl"))

    def test_newer_daemon_patch_is_kept_when_client_is_updated(self):
        self.built()
        self.installed({"netorch": "0.10.0", DAEMON: "0.10.10"})
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([Path(p).name for p in self.calls("apt-get")[0] if p.endswith(".deb")], ["client.deb"])

    def test_client_downgrade_and_newer_daemon_line_are_refused(self):
        self.built()
        for packages in [{"netorch": "0.10.2"}, {DAEMON: "0.11.0"}]:
            with self.subTest(packages=packages):
                self.installed(packages)
                result = self.run_installer()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("newer", result.stderr)
                self.assert_no_mutations()

    def test_check_needs_no_root_and_does_not_change_the_system(self):
        self.built()
        self.installed({DAEMON: "0.10.1"}, uid=1000)
        result = self.run_installer("netorch", "--check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("install", result.stdout)
        self.assertIn("keep", result.stdout)
        self.assert_no_mutations()

    def test_non_root_install_and_wrong_architecture_are_refused(self):
        self.built()
        for state in [{"uid": 1000}, {"arch": "arm64"}, {"os": "Darwin"}]:
            self.installed(**state)
            self.assertNotEqual(self.run_installer().returncode, 0)
            self.assert_no_mutations()

    def test_corrupted_payload_is_rejected_before_apt(self):
        self.built()
        path = self.out / "netorch-0.10.1-amd64.run"
        with path.open("ab") as output:
            output.write(b"corruption")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum", result.stderr)
        self.assert_no_mutations()

    def test_apt_failure_does_not_activate_service_or_mark_packages(self):
        self.built()
        self.installed(apt_error=True)
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("APT", result.stderr)
        self.assertEqual(self.calls("systemctl"), [])
        self.assertEqual(self.calls("apt-mark"), [])

    def test_prerelease_upgrade_and_incomplete_install_are_repaired(self):
        self.built()
        for package in [{"version": "0.10.1~beta.2"}, {"version": "0.10.1", "status": "unpacked"}]:
            self.installed(packages=None)
            state = {"packages": {"netorch": package, DAEMON: {"version": "0.10.1"}}}
            self.state.write_text(json.dumps(state))
            self.assertEqual(self.run_installer().returncode, 0)
        self.assertEqual(len(self.calls("apt-get")), 2)

    def test_database_error_is_not_treated_as_absent_package(self):
        self.built()
        self.installed(query_error=True)
        self.assertNotEqual(self.run_installer().returncode, 0)
        self.assert_no_mutations()

    def test_cli_guides_legacy_combined_gui_migration_without_removing_it(self):
        self.built()
        self.installed({"network-orchestrator": "0.10.0"})
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GUI installer first", result.stderr)
        self.assert_no_mutations()

    def test_cli_refuses_an_older_gui_even_when_daemon_is_present(self):
        self.built()
        self.installed({"network-orchestrator": "0.9.9", DAEMON: "0.10.1"})
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_mutations()

    def test_builder_rejects_mixed_releases_architectures_and_wrong_packages(self):
        for changes in [{"version": "0.10.0"}, {"arch": "arm64"}, {"package": "other"}, {"minimum": "0.11.0"}]:
            with self.subTest(changes=changes):
                deb(self.cli, **{"package": "netorch", **changes})
                result = self.build()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(list(self.out.glob("*.run")), [])

    def test_help_and_version_work_without_linux_or_root(self):
        self.built()
        self.installed(os="Darwin", uid=1000)
        self.assertEqual(self.run_installer("netorch", "--help").returncode, 0)
        result = self.run_installer("netorch", "--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("0.10.1", result.stdout)
        self.assert_no_mutations()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--fake-tool":
        sys.exit(fake_tool(sys.argv[2], sys.argv[3:]))
    unittest.main()
