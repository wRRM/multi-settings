from __future__ import annotations

import grp
import pwd

from multi_settings.domain.models import UserAccount


class SystemUserService:
    """Reads public account metadata without crossing the privilege boundary."""

    @staticmethod
    def list_interactive_users() -> list[UserAccount]:
        administrators = SystemUserService._administrator_names()
        users: list[UserAccount] = []
        for record in pwd.getpwall():
            if record.pw_uid < 1_000 or record.pw_uid == 65_534:
                continue
            if record.pw_shell.endswith(("/nologin", "/false")):
                continue
            users.append(
                UserAccount(
                    username=record.pw_name,
                    full_name=record.pw_gecos.split(",", maxsplit=1)[0],
                    uid=record.pw_uid,
                    is_administrator=record.pw_name in administrators,
                )
            )
        return sorted(users, key=lambda user: (not user.is_administrator, user.username))

    @staticmethod
    def _administrator_names() -> set[str]:
        try:
            sudo_group = grp.getgrnam("sudo")
        except KeyError:
            return set()
        members = set(sudo_group.gr_mem)
        for record in pwd.getpwall():
            if record.pw_gid == sudo_group.gr_gid:
                members.add(record.pw_name)
        return members
