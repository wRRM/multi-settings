from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_project_versions_match_debian_version(self) -> None:
        changelog = (ROOT / "debian/changelog").read_text(encoding="utf-8")
        debian_version = re.match(r"multi-settings \(([^)]+)\)", changelog).group(1)
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(project["project"]["version"], debian_version)
        self.assertIn(f"version: '{debian_version}'", (ROOT / "meson.build").read_text(encoding="utf-8"))

    def test_workflow_actions_use_full_commit_shas(self) -> None:
        workflow = (ROOT / ".github/workflows/debian-package.yml").read_text(encoding="utf-8")
        action_references = re.findall(r"^\s*uses:\s*[^@\s]+@([^\s#]+)", workflow, re.MULTILINE)
        self.assertGreaterEqual(len(action_references), 3)
        for reference in action_references:
            self.assertRegex(reference, r"^[0-9a-f]{40}$")

    def test_hardening_checksum_has_expected_shape(self) -> None:
        checksum = (ROOT / "data/ansible/devsec-hardening-10.6.0.sha256").read_text(
            encoding="utf-8"
        )
        self.assertRegex(checksum, r"^[0-9a-f]{64}  devsec-hardening-10\.6\.0\.tar\.gz\n$")

    def test_package_does_not_create_per_user_desktop_shortcuts(self) -> None:
        self.assertFalse((ROOT / "debian/postinst").exists())
        self.assertFalse(
            (ROOT / "src/multi_settings/services/desktop_shortcut.py").exists()
        )
        application = (ROOT / "src/multi_settings/application.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("desktop_shortcut", application)
        self.assertNotIn("DIRECTORY_DESKTOP", application)

    def test_application_metadata_uses_neutral_identifiers(self) -> None:
        app_id = "org.onboarding.settings"
        config = (ROOT / "src/multi_settings/config.py").read_text(encoding="utf-8")
        desktop = (ROOT / f"data/{app_id}.desktop").read_text(encoding="utf-8")
        metainfo = (ROOT / f"data/{app_id}.metainfo.xml").read_text(encoding="utf-8")
        policy = (ROOT / f"data/{app_id}.policy").read_text(encoding="utf-8")
        meson = (ROOT / "meson.build").read_text(encoding="utf-8")

        self.assertIn(f'APP_ID = "{app_id}"', config)
        self.assertIn(f"Icon={app_id}", desktop)
        self.assertIn(f"<id>{app_id}</id>", metainfo)
        self.assertIn(f'<action id="{app_id}.manage">', policy)
        self.assertIn(f"data/{app_id}.desktop", meson)

        for content in (config, desktop, metainfo, policy, meson):
            self.assertNotIn("io.github", content.casefold())
            self.assertNotIn("github.com", content.casefold())


if __name__ == "__main__":
    unittest.main()
