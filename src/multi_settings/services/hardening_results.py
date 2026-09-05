from __future__ import annotations

import csv
import os
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from multi_settings.domain.models import HardeningResult
from multi_settings.i18n import _


class HardeningResultsExporter:
    """Writes the ordinary user's hardening results without elevation."""

    @staticmethod
    def save(
        destination: Path,
        results: Sequence[HardeningResult],
        *,
        audit: bool,
        os_hardening: bool,
        ssh_hardening: bool,
    ) -> Path:
        if not results:
            raise ValueError(_("There are no hardening results to save."))
        if destination.suffix.lower() != ".csv":
            destination = destination.with_name(f"{destination.name}.csv")

        components = ",".join(
            name
            for name, enabled in (
                ("os_hardening", os_hardening),
                ("ssh_hardening", ssh_hardening),
            )
            if enabled
        )
        generated_at = datetime.now(UTC).isoformat()
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=destination.parent, text=True
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(
                    (
                        "generated_at",
                        "run_mode",
                        "components",
                        "task",
                        "role",
                        "status",
                        "changed",
                        "details",
                    )
                )
                for result in results:
                    writer.writerow(
                        (
                            generated_at,
                            "audit" if audit else "apply",
                            components,
                            HardeningResultsExporter._safe_cell(result.task),
                            HardeningResultsExporter._safe_cell(result.role),
                            result.status.value,
                            str(result.changed).lower(),
                            HardeningResultsExporter._safe_cell(result.details),
                        )
                    )
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, destination)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise
        return destination

    @staticmethod
    def _safe_cell(value: str) -> str:
        if value.startswith(("=", "+", "-", "@", "\t", "\r")):
            return f"'{value}"
        return value
