from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from multi_settings.i18n import get_language, load_language, set_language, translate


class TranslationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_language = get_language()

    def tearDown(self) -> None:
        set_language(self.original_language)

    def test_swedish_is_default_when_no_preference_exists(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            preference = Path(directory) / "missing-language"
            self.assertEqual(load_language(preference), "sv")

    def test_language_can_switch_between_swedish_and_english(self) -> None:
        set_language("sv")
        self.assertEqual(translate("Overview"), "Översikt")
        set_language("en")
        self.assertEqual(translate("Overview"), "Overview")

    def test_language_preference_is_private_and_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            preference = Path(directory) / "settings" / "language"
            with patch("multi_settings.i18n.language_file", return_value=preference):
                set_language("en", persist=True)
            self.assertEqual(preference.read_text(encoding="utf-8"), "en\n")
            self.assertEqual(preference.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
