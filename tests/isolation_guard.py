"""Audit-hook guard that blocks and records writes below the user's real gateway dirs."""

from __future__ import annotations

import os
import pwd
import sys
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field

import pytest

APP_DIR = "privacy-gateway"
HOME_RELATIVE = (".local/state", ".local/share", ".config")
XDG_NAMES = ("XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_CONFIG_HOME")
WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
WRITE_MODE_CHARS = frozenset("wax+")

# event name -> positions of the path arguments that the operation changes
PATH_EVENTS: dict[str, tuple[int, ...]] = {
    "os.mkdir": (0,),
    "os.rmdir": (0,),
    "os.remove": (0,),
    "os.rename": (0, 1),
    "os.chmod": (0,),
    "os.chown": (0,),
    "os.link": (1,),
    "os.symlink": (1,),
    "os.truncate": (0,),
    "os.utime": (0,),
    "shutil.copyfile": (1,),
    "shutil.copymode": (1,),
    "shutil.copystat": (1,),
    "shutil.copytree": (1,),
    "shutil.move": (0, 1),
    "shutil.rmtree": (0,),
    "shutil.chown": (0,),
}


def real_homes(env: Mapping[str, str]) -> tuple[str, ...]:
    """The account's home from the password database plus the original HOME, if different."""
    homes = [pwd.getpwuid(os.getuid()).pw_dir]
    if env.get("HOME"):
        homes.append(env["HOME"])
    return tuple(dict.fromkeys(os.path.realpath(home) for home in homes))


def protected_roots(env: Mapping[str, str]) -> tuple[str, ...]:
    """State, data and config dirs of the gateway under the real home and the original XDG dirs."""
    roots = [os.path.join(home, rel, APP_DIR) for home in real_homes(env) for rel in HOME_RELATIVE]
    roots += [os.path.join(env[name], APP_DIR) for name in XDG_NAMES if env.get(name)]
    return tuple(dict.fromkeys(os.path.realpath(root) for root in roots))


def _as_path(value: object) -> str | None:
    if isinstance(value, (str, bytes, os.PathLike)):
        return os.fsdecode(value)
    return None  # file descriptors and other non-path arguments


def _under(path: str, roots: Iterable[str]) -> bool:
    resolved = os.path.realpath(path)
    return any(resolved == root or resolved.startswith(root + os.sep) for root in roots)


def _is_write_open(mode: object, flags: object) -> bool:
    if isinstance(mode, str) and WRITE_MODE_CHARS & set(mode):
        return True
    return isinstance(flags, int) and bool(flags & WRITE_FLAGS)


def _sqlite_target(database: object) -> str | None:
    path = _as_path(database)
    if path is None or path == ":memory:" or path == "":
        return None
    if path.startswith("file:"):
        location, _, query = path[len("file:") :].partition("?")
        if "mode=ro" in query.split("&") or "mode=memory" in query.split("&"):
            return None
        return location
    return path


def violation(
    event: str, args: tuple[object, ...], roots: Iterable[str], real: Iterable[str] = ()
) -> tuple[str, str] | None:
    """(operation, path) for a change below a root or a subprocess env with a real HOME."""
    if event == "open":
        path = _as_path(args[0])
        if path is not None and _is_write_open(args[1], args[2]) and _under(path, roots):
            return event, path
        return None
    if event == "sqlite3.connect":
        path = _sqlite_target(args[0])
        if path is not None and _under(path, roots):
            return event, path
        return None
    if event == "subprocess.Popen":
        env = args[3]
        if isinstance(env, Mapping):
            home = env.get("HOME")
            if not home or os.path.realpath(os.fsdecode(home)) in tuple(real):
                return event, f"env HOME={home or '<unset>'}"
        return None
    positions = PATH_EVENTS.get(event)
    if positions is None:
        return None
    for position in positions:
        path = _as_path(args[position]) if position < len(args) else None
        if path is not None and _under(path, roots):
            return event, path
    return None


@dataclass
class Guard:
    """Holds the protected roots and every recorded violation as (test id, operation, path)."""

    roots: tuple[str, ...]
    homes: tuple[str, ...] = ()
    current: str | None = None
    violations: list[tuple[str | None, str, str]] = field(default_factory=list)

    def hook(self, event: str, args: tuple[object, ...]) -> None:
        if event != "open" and event not in PATH_EVENTS and event not in (
            "sqlite3.connect",
            "subprocess.Popen",
        ):
            return
        found = violation(event, args, self.roots, self.homes)
        if found is None:
            return
        operation, path = found
        self.violations.append((self.current, operation, path))
        raise PermissionError(f"test isolation guard: {operation} on protected path {path}")

    def take(self, nodeid: str) -> list[tuple[str, str]]:
        """Remove and return the violations recorded for `nodeid`."""
        mine = [(op, path) for owner, op, path in self.violations if owner == nodeid]
        self.violations = [item for item in self.violations if item[0] != nodeid]
        return mine

    def install(self) -> None:
        sys.addaudithook(self.hook)


def report(violations: Iterable[tuple[str, str]]) -> str:
    lines = [f"  {op}: {path}" for op, path in violations]
    return "test isolation guard: write below a protected real directory\n" + "\n".join(lines)


class GuardPlugin:
    """Fails the test whose setup, call or teardown hit the guard, and the session for the rest."""

    def __init__(self, guard: Guard) -> None:
        self.guard = guard

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_protocol(self, item: pytest.Item) -> Iterator[None]:
        self.guard.current = item.nodeid
        yield
        self.guard.current = None

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(self, item: pytest.Item) -> Iterator[None]:
        outcome = yield
        found = self.guard.take(item.nodeid)
        if found:
            result = outcome.get_result()
            result.outcome = "failed"
            result.longrepr = report(found)

    def pytest_sessionfinish(self, session: pytest.Session) -> None:
        if self.guard.violations:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED
            print("\n" + report((op, path) for _, op, path in self.guard.violations))
