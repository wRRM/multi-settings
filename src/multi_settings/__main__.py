from __future__ import annotations

import sys

from .application import MultiSettingsApplication


def main() -> int:
    return MultiSettingsApplication().run(sys.argv)


if __name__ == "__main__":
    raise SystemExit(main())
