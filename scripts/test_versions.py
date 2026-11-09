"""Run with: python3 -m unittest scripts/test_versions.py"""
import json
import pathlib
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import versions  # noqa: E402

CRATE = '[package]\nname = "x"\nversion.workspace = true\nedition.workspace = true\n\n[dependencies]\nserde = { version = "1" }\n'
TOML = "".join(f'[{line}]\nversion = "0.10.0"\n\n' for line in versions.LINES)


class VersionsTest(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        (self.dir / "versions.toml").write_text(TOML)
        for crate in list(versions.CRATES) + list(versions.SHARED_CRATES):
            (self.dir / crate).mkdir(parents=True)
            (self.dir / crate / "Cargo.toml").write_text(CRATE)
        self.repo = versions.Repo(self.dir)
        (self.dir / "changelog").mkdir()
        for line in versions.LINES:
            (self.dir / f"changelog/{line}.md").write_text(
                f"# {line}\n\n## [Unreleased]\n\n### Fixed\n\n"
                f"- Pending {line} change.\n\n"
                "## [0.10.0] - 2026-11-01\n\n- Released history.\n"
            )

    def test_sync_writes_each_crate_its_lines_version_and_shared_ones_a_placeholder(self):
        self.repo.set_version("linux", "0.11.2")
        def cargo(crate):
            return (self.dir / crate / "Cargo.toml").read_text()
        self.assertIn('version = "0.11.2"', cargo("crates/daemon"))
        self.assertIn('version = "0.10.0"', cargo("crates/core"))
        self.assertIn('version = "0.0.0"', cargo("crates/cli"))
        # Only the package version changes, not a dependency's.
        self.assertIn('serde = { version = "1" }', cargo("crates/daemon"))
        conf = json.loads((self.dir / "src-tauri/tauri.linux.conf.json").read_text())
        self.assertEqual(conf["version"], "0.11.2")
        win = json.loads((self.dir / "src-tauri/tauri.windows.conf.json").read_text())
        self.assertEqual(win["version"], "0.10.0")

    def test_check_reports_drift_and_passes_after_sync(self):
        self.assertTrue(self.repo.check())
        self.repo.sync()
        self.assertEqual(self.repo.check(), [])
        (self.dir / "crates/core/Cargo.toml").write_text(CRATE.replace("version.workspace = true", 'version = "9.9.9"'))
        self.assertEqual(len(self.repo.check()), 1)

    def test_sync_keeps_other_keys_of_a_tauri_config(self):
        path = self.dir / "src-tauri/tauri.linux.conf.json"
        path.write_text(json.dumps({"bundle": {"x": 1}}))
        self.repo.sync()
        data = json.loads(path.read_text())
        self.assertEqual(data["bundle"], {"x": 1})
        self.assertEqual(data["version"], "0.10.0")

    def test_bad_input_is_refused(self):
        with self.assertRaises(SystemExit):
            self.repo.set_version("linux", "1.2")
        with self.assertRaises(SystemExit):
            self.repo.set_version("freebsd", "1.2.3")

    def snapshot(self):
        return {
            path.relative_to(self.dir): path.read_bytes()
            for path in self.dir.rglob("*") if path.is_file()
        }

    def test_prepare_updates_selected_lines_and_preserves_history(self):
        windows = (self.dir / "changelog/windows.md").read_bytes()
        self.repo.prepare({"linux": "0.11.2", "core": "0.11.0"}, "2026-11-09")
        self.assertEqual(self.repo.versions()["linux"], "0.11.2")
        self.assertEqual(self.repo.versions()["core"], "0.11.0")
        self.assertEqual(self.repo.versions()["windows"], "0.10.0")
        self.assertEqual(self.repo.check(), [])
        linux = (self.dir / "changelog/linux.md").read_text()
        self.assertIn("## [Unreleased]\n\n## [0.11.2] - 2026-11-09\n\nCore 0.11.0.", linux)
        self.assertIn("- Pending linux change.", linux)
        self.assertTrue(linux.endswith("## [0.10.0] - 2026-11-01\n\n- Released history.\n"))
        core = (self.dir / "changelog/core.md").read_text()
        self.assertIn("## [0.11.0] - 2026-11-09\n\n### Fixed", core)
        self.assertEqual((self.dir / "changelog/windows.md").read_bytes(), windows)

    def test_prepare_rejects_invalid_batch_before_writing(self):
        before = self.snapshot()
        for invalid in (
            {"linux": "0.11.0", "windows": "0.9.0"},
            {"linux": "0.11.0", "freebsd": "0.11.0"},
            {"linux": "0.11.0", "windows": "invalid"},
        ):
            with self.subTest(updates=invalid):
                with self.assertRaises(SystemExit):
                    self.repo.prepare(invalid, "2026-11-09")
                self.assertEqual(self.snapshot(), before)

    def test_prepare_rejects_noncanonical_semver(self):
        before = self.snapshot()
        for version in ("0.11.0-rc..1", "00.11.0", "0.11.0-01"):
            with self.subTest(version=version):
                with self.assertRaises(SystemExit):
                    self.repo.prepare({"linux": version}, "2026-11-09", dry_run=True)
                self.assertEqual(self.snapshot(), before)

    def test_prepare_requires_notes_in_every_selected_changelog(self):
        (self.dir / "changelog/windows.md").write_text(
            "# Windows\n\n## [Unreleased]\n\n## [0.10.0] - 2026-11-01\n"
        )
        before = self.snapshot()
        with self.assertRaises(SystemExit):
            self.repo.prepare({"linux": "0.11.0", "windows": "0.11.0"}, "2026-11-09")
        self.assertEqual(self.snapshot(), before)

    def test_prepare_dry_run_preserves_all_files(self):
        before = self.snapshot()
        self.repo.prepare({"linux": "0.11.0"}, "2026-11-09", dry_run=True)
        self.assertEqual(self.snapshot(), before)

    def test_prepare_refuses_repeat_without_changing_history(self):
        self.repo.prepare({"linux": "0.11.0"}, "2026-11-09")
        before = self.snapshot()
        with self.assertRaises(SystemExit):
            self.repo.prepare({"linux": "0.11.0"}, "2026-11-09")
        self.assertEqual(self.snapshot(), before)

    def test_prepare_orders_prereleases_semantically(self):
        self.repo.set_version("linux", "0.11.0-rc.2")
        self.repo.prepare({"linux": "0.11.0-rc.10"}, "2026-11-09")
        self.assertEqual(self.repo.versions()["linux"], "0.11.0-rc.10")

    def test_affected_maps_files_to_lines(self):
        self.assertEqual(versions.affected(["crates/core/src/xray.rs"]), ["core"])
        self.assertEqual(versions.affected(["crates/cli/src/linux/hold.rs"]), ["linux"])
        self.assertEqual(versions.affected(["crates/cli/src/connect.rs"]), ["macos"])
        self.assertEqual(
            versions.affected(["src-tauri/src/lib.rs", "macos/README.md"]),
            ["macos", "linux", "windows"],
        )
        self.assertEqual(versions.affected(["docs/testing.md", "README.md"]), [])


if __name__ == "__main__":
    unittest.main()
