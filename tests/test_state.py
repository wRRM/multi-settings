from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from multi_settings.privileged.state import save_state


class StateTests(unittest.TestCase):
    def test_public_state_omits_credential_material(self) -> None:
        state = {
            "version": 1,
            "enrollments": [
                {
                    "username": "alice",
                    "serial": "12345678",
                    "slot": "primary",
                    "credential": "alice:private-mapping-material",
                }
            ],
            "pam": {"login": True, "sudo": False},
            "hardening_backup": {
                "id": "20260908T120000Z-012345abcdef",
                "status": "available",
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public_path = root / "state.json"
            private_path = root / "private-state.json"
            with (
                patch("multi_settings.privileged.state.STATE_DIR", root),
                patch("multi_settings.privileged.state.STATE_FILE", public_path),
                patch("multi_settings.privileged.state.PRIVATE_STATE_FILE", private_path),
            ):
                save_state(state)

            public = json.loads(public_path.read_text(encoding="utf-8"))
            private = json.loads(private_path.read_text(encoding="utf-8"))
            self.assertNotIn("credential", public["enrollments"][0])
            self.assertIn("credential", private["enrollments"][0])
            self.assertEqual(
                public["hardening_backup"]["id"],
                "20260908T120000Z-012345abcdef",
            )
            self.assertEqual(public_path.stat().st_mode & 0o777, 0o644)
            self.assertEqual(private_path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
