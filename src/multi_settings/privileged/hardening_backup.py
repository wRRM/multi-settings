from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from secrets import token_hex
from typing import Any

from multi_settings.config import HARDENING_BACKUP_DIR, HARDENING_COLLECTION_VERSION
from multi_settings.domain.validation import ValidationError
from multi_settings.i18n import _
from multi_settings.privileged.protocol import SAFE_ENVIRONMENT, atomic_write, emit
from multi_settings.privileged.state import load_state, save_state

BACKUP_FORMAT_VERSION = 1
BACKUP_ID_PATTERN = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$")

# The Ubuntu roles primarily change /etc. The extra locations cover the PAM
# profiles and su binary metadata managed by the OS role. SSH-only runs use a
# narrower snapshot so they do not capture unrelated system configuration.
OS_BACKUP_SOURCES = (
    Path("/etc"),
    Path("/usr/share/pam-configs"),
    Path("/bin/su"),
)
SSH_BACKUP_SOURCES = (
    Path("/etc/ssh"),
    Path("/etc/systemd/system/ssh.service.d"),
    Path("/etc/systemd/system/ssh.service.requires"),
    Path("/etc/systemd/system/sockets.target.wants/ssh.socket"),
)


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1_048_576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _entry(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    value: dict[str, Any] = {
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
    }
    if stat.S_ISDIR(metadata.st_mode):
        value["kind"] = "directory"
    elif stat.S_ISREG(metadata.st_mode):
        value.update(kind="file", sha256=_digest(path))
    elif stat.S_ISLNK(metadata.st_mode):
        value.update(kind="symlink", target=os.readlink(path))
    else:
        value["kind"] = "other"
    return value


def snapshot_index(source: Path) -> dict[str, dict[str, Any]]:
    """Return content and ownership metadata without following symlinks."""
    if not source.exists() and not source.is_symlink():
        return {}
    entries = {".": _entry(source)}
    if not source.is_dir() or source.is_symlink():
        return entries
    for root, directory_names, file_names in os.walk(source, followlinks=False):
        root_path = Path(root)
        for name in sorted((*directory_names, *file_names)):
            path = root_path / name
            relative = path.relative_to(source).as_posix()
            try:
                entries[relative] = _entry(path)
            except FileNotFoundError:
                # A volatile system-generated entry may disappear while the
                # snapshot is taken. It was not stable enough to restore.
                continue
    return entries


def _copy_source(source: Path, destination: Path) -> None:
    if not source.exists() and not source.is_symlink():
        return
    if source.is_symlink():
        destination.symlink_to(os.readlink(source))
    elif source.is_dir():
        shutil.copytree(source, destination, symlinks=True)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination, follow_symlinks=False)


def _write_manifest(directory: Path, manifest: dict[str, Any]) -> None:
    atomic_write(
        directory / "manifest.json",
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        0o600,
    )


def _publish_backup(manifest: dict[str, Any], status: str) -> None:
    state = load_state()
    state["hardening_backup"] = {
        "id": manifest["id"],
        "created_at": manifest["created_at"],
        "components": manifest["components"],
        "collection_version": manifest["collection_version"],
        "status": status,
    }
    save_state(state)


def _sources_for(components: tuple[str, ...]) -> tuple[Path, ...]:
    return OS_BACKUP_SOURCES if "os_hardening" in components else SSH_BACKUP_SOURCES


def create_hardening_backup(components: tuple[str, ...]) -> str:
    backup_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + token_hex(6)
    directory = HARDENING_BACKUP_DIR / backup_id
    directory.mkdir(mode=0o700, parents=True)
    os.chmod(HARDENING_BACKUP_DIR, 0o700)
    manifest: dict[str, Any] = {
        "version": BACKUP_FORMAT_VERSION,
        "id": backup_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "collection_version": HARDENING_COLLECTION_VERSION,
        "components": list(components),
        "status": "capturing",
        "sources": [],
    }
    try:
        for index, source in enumerate(_sources_for(components)):
            storage = f"items/{index}"
            before = snapshot_index(source)
            _copy_source(source, directory / storage)
            manifest["sources"].append(
                {"path": str(source), "storage": storage, "before": before}
            )
        _write_manifest(directory, manifest)
        _publish_backup(manifest, "capturing")
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    return backup_id


def _load_manifest(backup_id: str) -> tuple[Path, dict[str, Any]]:
    if not BACKUP_ID_PATTERN.fullmatch(backup_id):
        raise ValidationError(_("The hardening backup identifier is invalid."))
    directory = HARDENING_BACKUP_DIR / backup_id
    try:
        manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValidationError(
            _("The hardening backup could not be read: {error}").format(error=error)
        ) from error
    if (
        not isinstance(manifest, dict)
        or manifest.get("version") != BACKUP_FORMAT_VERSION
        or manifest.get("id") != backup_id
        or not isinstance(manifest.get("sources"), list)
    ):
        raise ValidationError(_("The hardening backup has an invalid format."))
    return directory, manifest


def finalize_hardening_backup(backup_id: str) -> None:
    directory, manifest = _load_manifest(backup_id)
    for item in manifest["sources"]:
        source = Path(item["path"])
        after = snapshot_index(source)
        before = item["before"]
        item["changes"] = sorted(
            key
            for key in set(before) | set(after)
            if before.get(key) != after.get(key)
        )
    manifest["status"] = "available"
    manifest["completed_at"] = datetime.now(timezone.utc).isoformat()
    _write_manifest(directory, manifest)
    _publish_backup(manifest, "available")


def _remove(path: Path) -> None:
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def _stored_path(directory: Path, storage: str, relative: str) -> Path:
    base = directory / storage
    if relative == ".":
        return base
    return base.joinpath(*PurePosixPath(relative).parts)


def _target_path(source: Path, relative: str) -> Path:
    if relative == ".":
        return source
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ValidationError(_("The hardening backup has an invalid format."))
    return source.joinpath(*path.parts)


def _restore_content(source: Path, stored: Path, metadata: dict[str, Any]) -> None:
    kind = metadata["kind"]
    if kind == "directory":
        if source.is_symlink() or (source.exists() and not source.is_dir()):
            _remove(source)
        source.mkdir(mode=metadata["mode"], parents=True, exist_ok=True)
    elif kind == "file":
        if source.is_dir() and not source.is_symlink():
            _remove(source)
        source.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{source.name}.restore.", dir=source.parent
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            os.chmod(temporary, 0o600)
            shutil.copy2(stored, temporary, follow_symlinks=False)
            os.chown(
                temporary,
                metadata["uid"],
                metadata["gid"],
                follow_symlinks=False,
            )
            os.chmod(temporary, metadata["mode"], follow_symlinks=False)
            os.replace(temporary, source)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    elif kind == "symlink":
        if source.exists() or source.is_symlink():
            _remove(source)
        source.parent.mkdir(parents=True, exist_ok=True)
        source.symlink_to(metadata["target"])


def _restore_metadata(path: Path, metadata: dict[str, Any]) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if metadata["kind"] == "symlink":
        os.lchown(path, metadata["uid"], metadata["gid"])
        return
    os.chown(path, metadata["uid"], metadata["gid"], follow_symlinks=False)
    os.chmod(path, metadata["mode"], follow_symlinks=False)


def _validate_manifest_sources(manifest: dict[str, Any]) -> None:
    components = tuple(manifest.get("components", ()))
    if components not in (
        ("os_hardening",),
        ("ssh_hardening",),
        ("os_hardening", "ssh_hardening"),
    ):
        raise ValidationError(_("The hardening backup has an invalid format."))
    expected = _sources_for(components)
    if len(manifest["sources"]) != len(expected):
        raise ValidationError(_("The hardening backup has an invalid format."))
    for index, (item, expected_path) in enumerate(zip(manifest["sources"], expected)):
        if (
            not isinstance(item, dict)
            or item.get("path") != str(expected_path)
            or item.get("storage") != f"items/{index}"
            or not isinstance(item.get("before"), dict)
            or not isinstance(item.get("changes"), list)
            or not all(isinstance(value, str) for value in item["changes"])
        ):
            raise ValidationError(_("The hardening backup has an invalid format."))


def restore_hardening_backup(payload: dict[str, Any]) -> None:
    backup_id = payload.get("backup_id")
    if not isinstance(backup_id, str):
        raise ValidationError(_("The hardening backup identifier is invalid."))
    directory, manifest = _load_manifest(backup_id)
    if manifest.get("status") != "available":
        raise ValidationError(_("This hardening backup is not available for restore."))
    _validate_manifest_sources(manifest)

    for item in manifest["sources"]:
        source = Path(item["path"])
        before = item["before"]
        changes = item.get("changes")
        if not isinstance(before, dict) or not isinstance(changes, list):
            raise ValidationError(_("The hardening backup has an invalid format."))

        # Remove paths created by hardening from the leaves upward.
        for relative in sorted(changes, key=lambda value: len(PurePosixPath(value).parts), reverse=True):
            if relative not in before:
                target = _target_path(source, relative)
                if target.exists() or target.is_symlink():
                    _remove(target)

        # Restore original content from parents to children, then ownership and
        # modes from children to parents so directory metadata is exact.
        original = [relative for relative in changes if relative in before]
        for relative in sorted(original, key=lambda value: len(PurePosixPath(value).parts)):
            target = _target_path(source, relative)
            stored = _stored_path(directory, item["storage"], relative)
            _restore_content(target, stored, before[relative])
        for relative in sorted(original, key=lambda value: len(PurePosixPath(value).parts), reverse=True):
            _restore_metadata(_target_path(source, relative), before[relative])

    components = tuple(manifest["components"])
    if "os_hardening" in components and Path("/usr/sbin/sysctl").is_file():
        subprocess.run(
            ["/usr/sbin/sysctl", "--system"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=SAFE_ENVIRONMENT,
        )
    if Path("/usr/bin/systemctl").is_file():
        subprocess.run(
            ["/usr/bin/systemctl", "daemon-reload"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=SAFE_ENVIRONMENT,
        )
        if "ssh_hardening" in components:
            subprocess.run(
                ["/usr/bin/systemctl", "try-reload-or-restart", "ssh.service"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=SAFE_ENVIRONMENT,
            )

    manifest["status"] = "restored"
    manifest["restored_at"] = datetime.now(timezone.utc).isoformat()
    _write_manifest(directory, manifest)
    _publish_backup(manifest, "restored")
    emit(
        "complete",
        message=_("Hardening configuration was reverted. Installed packages were retained."),
    )
