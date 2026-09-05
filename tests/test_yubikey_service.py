from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from multi_settings.domain.models import ConnectedKey, KeySlot
from multi_settings.i18n import get_language, set_language
from multi_settings.services.yubikeys import YubiKeyService


class ImmediateThread:
    def __init__(self, *, target, daemon: bool) -> None:
        self.target = target

    def start(self) -> None:
        self.target()


class YubiKeyEnrollmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_language = get_language()
        set_language("en")

    def tearDown(self) -> None:
        set_language(self.original_language)

    @patch("multi_settings.services.yubikeys.threading.Thread", ImmediateThread)
    @patch("multi_settings.services.yubikeys.shutil.which", return_value="/usr/bin/pamu2fcfg")
    @patch("multi_settings.services.yubikeys.subprocess.run")
    def test_pin_is_sent_over_standard_input_only(self, run, _which) -> None:
        run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="Enter PIN for /dev/hidraw2: error:fido_dev_make_cred (-7) FIDO_ERR_INVALID_ARGUMENT",
        )
        service = YubiKeyService()
        service.connected_keys = lambda: [ConnectedKey("1234", None)]
        responses = []

        service.enroll_async("alice", "1234", KeySlot.PRIMARY, "123456", responses.append)

        self.assertEqual(run.call_args.kwargs["input"], "123456\n")
        self.assertNotIn("123456", run.call_args.args[0])
        self.assertTrue(run.call_args.kwargs["start_new_session"])
        self.assertEqual(
            responses[0].message,
            "Enrollment failed. Check the FIDO2 PIN, reconnect the YubiKey, and try again.",
        )

    @patch("multi_settings.services.yubikeys.threading.Thread", ImmediateThread)
    @patch("multi_settings.services.yubikeys.shutil.which", return_value="/usr/bin/pamu2fcfg")
    @patch("multi_settings.services.yubikeys.subprocess.run")
    def test_missing_pin_gets_a_friendly_error(self, run, _which) -> None:
        run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="Enter PIN for /dev/hidraw2: error:fido_dev_make_cred (-7) FIDO_ERR_INVALID_ARGUMENT",
        )
        service = YubiKeyService()
        service.connected_keys = lambda: [ConnectedKey("1234", None)]
        responses = []

        service.enroll_async("alice", "1234", KeySlot.PRIMARY, "", responses.append)

        self.assertIs(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(
            responses[0].message,
            "This YubiKey requires its FIDO2 PIN. Enter the PIN and try again.",
        )


if __name__ == "__main__":
    unittest.main()
