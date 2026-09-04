from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class KeySlot(StrEnum):
    PRIMARY = "primary"
    SECONDARY = "secondary"


class TaskStatus(StrEnum):
    SUCCESS = "success"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class UserAccount:
    username: str
    full_name: str
    uid: int
    is_administrator: bool


@dataclass(frozen=True, slots=True)
class Enrollment:
    username: str
    serial: str
    slot: KeySlot
    credential: str = ""


@dataclass(frozen=True, slots=True)
class ConnectedKey:
    serial: str
    enrollment: Enrollment | None = None

    @property
    def status(self) -> str:
        if self.enrollment is None:
            return "Not enrolled"
        return f"{self.enrollment.slot.value.title()} for {self.enrollment.username}"


@dataclass(frozen=True, slots=True)
class HardeningResult:
    task: str
    role: str
    status: TaskStatus
    changed: bool
    details: str = ""
