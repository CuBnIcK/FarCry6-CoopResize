"""Install and restore the co-op DLL inside a game folder.

Every file is written next to its destination, checked by SHA-256 and only then moved
into place, so an interrupted run leaves either the old or the new DLL, never a mix.
"""

import os
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from fc6.build import TARGET_DLL, TARGET_EXE, Build
from fc6.edits import file_sha256, write_verified_copy
from fc6.variants import ORIGINAL, RECOMMENDED, Variant, get_variant, identify_any


BACKUP_SUFFIX = ".bak"
STEAM_APP_ID = "2369390"


@dataclass(frozen=True)
class GameState:
    dll: Path
    # Both None when the DLL is neither an original nor a known variant
    build: Build | None
    variant: Variant | None
    backup_ok: bool

    @property
    def backup(self) -> Path:
        return backup_path(self.dll)


def backup_path(dll: Path) -> Path:
    return dll.with_name(dll.name + BACKUP_SUFFIX)


def find_dll(location: Path) -> Path:
    """Accept the game folder, its bin folder or the DLL itself."""
    location = Path(location)
    for candidate in (location, location / TARGET_DLL, location / "bin" / TARGET_DLL):
        if candidate.name.lower() == TARGET_DLL.lower() and candidate.is_file():
            return candidate.resolve()
    raise FileNotFoundError(f"{TARGET_DLL} not found in {location}, choose the Far Cry 6 folder")


def _is_original(path: Path, build: Build) -> bool:
    return path.is_file() and path.stat().st_size == build.file_size and file_sha256(path) == build.sha256


def inspect(dll: Path) -> GameState:
    known = identify_any(file_sha256(dll))
    if known is None:
        return GameState(dll, None, None, False)
    variant, build = known
    return GameState(dll, build, variant, _is_original(backup_path(dll), build))


def _replace_verified(source: Path, destination: Path, edits, expected_sha256: str):
    staging = destination.with_name(f".{destination.name}.{os.getpid()}.new")
    staging.unlink(missing_ok=True)
    write_verified_copy(source, staging, edits, expected_sha256)
    try:
        os.replace(staging, destination)
    except PermissionError as error:
        raise PermissionError(f"Cannot replace {destination}, close Far Cry 6 and try again") from error
    finally:
        staging.unlink(missing_ok=True)


def install(dll: Path, variant_name: str = RECOMMENDED) -> str:
    variant = get_variant(variant_name)
    state = inspect(dll)
    if state.build is None:
        raise ValueError("Unsupported game version. Verify the game files in Steam or Ubisoft Connect, "
                         "then try again. If it still fails, the game was updated and the patch "
                         "needs an update too")
    if state.variant is variant:
        return "The co-op patch is already installed"
    expected = variant.hash_for(state.build)
    if expected is None:
        raise ValueError(f"The {variant.name} patch is not available for the {state.build.name} version")
    if state.variant is ORIGINAL:
        if not state.backup_ok:
            _replace_verified(dll, state.backup, (), state.build.sha256)
        source = state.backup
    elif state.backup_ok:
        source = state.backup
    else:
        raise ValueError(f"An older patch is installed and {state.backup.name} is missing or damaged. "
                         "Verify the game files in Steam or Ubisoft Connect, then install again")
    _replace_verified(source, dll, variant.edits(source, state.build), expected)
    return f"Installed the co-op patch for the {state.build.name} version. Backup: {state.backup}"


def restore(dll: Path) -> str:
    state = inspect(dll)
    if state.variant is ORIGINAL:
        return "The game DLL is already the original"
    if not state.backup_ok:
        raise ValueError(f"{state.backup.name} is missing or does not match this game version. "
                         "Verify the game files in Steam or Ubisoft Connect to restore the original")
    _replace_verified(state.backup, dll, (), state.build.sha256)
    return "Restored the original game DLL"


def game_running() -> bool:
    if sys.platform != "win32":
        return False
    from fc6.winproc import find_processes
    return bool(find_processes(TARGET_EXE))


def _steam_libraries() -> Iterator[Path]:
    import winreg
    for hive, key, value in ((winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath"),
                             (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam", "InstallPath")):
        try:
            with winreg.OpenKey(hive, key) as handle:
                steam = Path(winreg.QueryValueEx(handle, value)[0])
        except OSError:
            continue
        yield steam
        try:
            text = (steam / "steamapps" / "libraryfolders.vdf").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for path in re.findall(r'"path"\s+"([^"]+)"', text):
            yield Path(path.replace("\\\\", "\\"))


def _steam_candidates() -> Iterator[Path]:
    for library in _steam_libraries():
        apps = library / "steamapps"
        try:
            manifest = (apps / f"appmanifest_{STEAM_APP_ID}.acf").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if match := re.search(r'"installdir"\s+"([^"]+)"', manifest):
            yield apps / "common" / match.group(1)


def _ubisoft_candidates() -> Iterator[Path]:
    import winreg
    for key in (r"SOFTWARE\WOW6432Node\Ubisoft\Launcher\Installs", r"SOFTWARE\Ubisoft\Launcher\Installs"):
        try:
            installs = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key)
        except OSError:
            continue
        with installs:
            index = 0
            while True:
                try:
                    name = winreg.EnumKey(installs, index)
                except OSError:
                    break
                index += 1
                try:
                    with winreg.OpenKey(installs, name) as game:
                        yield Path(winreg.QueryValueEx(game, "InstallDir")[0])
                except OSError:
                    continue


def find_installations() -> list[Path]:
    """Game folders that contain FarCry6.exe and the DLL, from Steam and Ubisoft Connect."""
    if sys.platform != "win32":
        return []
    found = []
    for candidate in (*_steam_candidates(), *_ubisoft_candidates()):
        try:
            folder = candidate.resolve()
            if (folder / "bin" / TARGET_EXE).is_file() and (folder / "bin" / TARGET_DLL).is_file():
                if folder not in found:
                    found.append(folder)
        except OSError:
            continue
    return found
