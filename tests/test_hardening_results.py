from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from multi_settings.domain.models import HardeningResult, TaskStatus
from multi_settings.services.hardening_results import HardeningResultsExporter


class HardeningResultsTests(unittest.TestCase):
    def test_results_are_saved_as_private_csv(self) -> None:
        result = HardeningResult(
            task="Configure SSH",
            role="devsec.hardening.ssh_hardening",
            status=TaskStatus.SUCCESS,
            changed=True,
            details="=unsafe spreadsheet formula",
        )
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "results"
            saved = HardeningResultsExporter.save(
                destination,
                [result],
                audit=False,
                os_hardening=False,
                ssh_hardening=True,
            )

            self.assertEqual(saved.name, "results.csv")
            self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
            with saved.open(encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(rows[0]["run_mode"], "apply")
            self.assertEqual(rows[0]["components"], "ssh_hardening")
            self.assertEqual(rows[0]["details"], "'=unsafe spreadsheet formula")


if __name__ == "__main__":
    unittest.main()
