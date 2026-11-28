"""The isolation guard blocks writes below protected roots; defaults resolve into the test home."""

from __future__ import annotations

import os
from pathlib import Path

import isolation_guard
import pytest
from isolation_guard import Guard, protected_roots, violation

from privacy_gateway.audit import RequestAuditLog
from privacy_gateway.config import USER_CONFIG_RELATIVE, load_config
from privacy_gateway_proxy import launchd, tool_policy
from privacy_gateway_proxy.settings import ProxySettings, audit_dir_for, load_settings

GUARD_SOURCE = Path(isolation_guard.__file__).read_text(encoding="utf-8")
INNER_CONFTEST = """
import os
import pytest
from isolation_guard import Guard, GuardPlugin

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "protected"))
GUARD = Guard(roots=(ROOT,))
GUARD.install()


def pytest_configure(config):
    config.pluginmanager.register(GuardPlugin(GUARD), "isolation-guard")
"""


@pytest.fixture
def root(tmp_path: Path) -> str:
    directory = tmp_path / "protected"
    directory.mkdir()
    return os.path.realpath(directory)


@pytest.mark.parametrize(
    ("event", "args"),
    [
        ("open", ("{root}/audit.jsonl", "a", 0)),
        ("open", ("{root}/audit.jsonl", None, os.O_WRONLY | os.O_CREAT)),
        ("open", ("{root}/sub/../vault.key", "w", 0)),
        ("os.mkdir", ("{root}/audit", 0o700, None)),
        ("os.rename", ("{root}/a", "/elsewhere/b", None, None)),
        ("os.rename", ("/elsewhere/a", "{root}/b", None, None)),
        ("os.remove", ("{root}/audit-2026-01-01.jsonl", None)),
        ("os.chmod", ("{root}", 0o700, None)),
        ("shutil.copyfile", ("/elsewhere/a", "{root}/a")),
        ("shutil.rmtree", ("{root}", None)),
        ("sqlite3.connect", ("{root}/vault.db",)),
        ("sqlite3.connect", ("file:{root}/vault.db?mode=rwc",)),
    ],
)
def test_changes_below_a_protected_root_are_violations(
    root: str, event: str, args: tuple[object, ...]
) -> None:
    filled = tuple(arg.format(root=root) if isinstance(arg, str) else arg for arg in args)
    assert violation(event, filled, (root,)) is not None


@pytest.mark.parametrize(
    ("event", "args"),
    [
        ("open", ("{root}/audit.jsonl", "r", os.O_RDONLY)),
        ("open", ("{root}/vault.db", None, os.O_RDONLY | os.O_CLOEXEC)),
        ("open", ("{root}-other/audit.jsonl", "w", 0)),
        ("open", (3, "w", 0)),
        ("os.mkdir", ("/elsewhere/audit", 0o700, None)),
        ("sqlite3.connect", ("file:{root}/vault.db?mode=ro",)),
        ("sqlite3.connect", (":memory:",)),
        ("os.listdir", ("{root}",)),
    ],
)
def test_reads_and_other_paths_are_no_violations(
    root: str, event: str, args: tuple[object, ...]
) -> None:
    filled = tuple(arg.format(root=root) if isinstance(arg, str) else arg for arg in args)
    assert violation(event, filled, (root,)) is None


def test_a_symlink_into_a_protected_root_is_resolved(root: str, tmp_path: Path) -> None:
    link = tmp_path / "link"
    link.symlink_to(root)
    assert violation("open", (str(link / "audit.jsonl"), "a", 0), (root,)) is not None


def test_a_subprocess_env_without_the_test_home_is_a_violation(tmp_path: Path) -> None:
    # The guard compares resolved paths; on macOS /home resolves to /System/Volumes/Data/home.
    real = (os.path.realpath("/home/someone"),)
    assert violation("subprocess.Popen", ("x", [], None, {"PATH": "/bin"}), (), real)
    assert violation("subprocess.Popen", ("x", [], None, {"HOME": real[0]}), (), real)
    assert violation("subprocess.Popen", ("x", [], None, {"HOME": str(tmp_path)}), (), real) is None
    assert violation("subprocess.Popen", ("x", [], None, None), (), real) is None


def test_the_hook_raises_and_records_without_a_value(root: str) -> None:
    guard = Guard(roots=(root,), current="test-id")
    with pytest.raises(PermissionError):
        guard.hook("open", (f"{root}/audit.jsonl", "a", 0))
    guard.hook("open", (f"{root}/audit.jsonl", "r", 0))
    assert guard.take("test-id") == [("open", f"{root}/audit.jsonl")]
    assert guard.violations == []


def test_protected_roots_cover_home_and_original_xdg_dirs() -> None:
    env = {"HOME": "/h", "XDG_STATE_HOME": "/xs", "XDG_DATA_HOME": "/xd", "XDG_CONFIG_HOME": "/xc"}
    roots = protected_roots(env)
    for path in (
        "/h/.local/state/privacy-gateway",
        "/h/.local/share/privacy-gateway",
        "/h/.config/privacy-gateway",
        "/xs/privacy-gateway",
        "/xd/privacy-gateway",
        "/xc/privacy-gateway",
    ):
        assert os.path.realpath(path) in roots


def test_the_guard_fails_the_test_and_blocks_the_write(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(isolation_guard=GUARD_SOURCE)
    pytester.makeconftest(INNER_CONFTEST)
    pytester.mkdir("protected")
    pytester.makepyfile(
        test_inner="""
        import os, sqlite3
        HERE = os.path.dirname(__file__)

        def test_writes():
            try:
                open(os.path.join(HERE, "protected", "audit.jsonl"), "a").write("x")
            except PermissionError:
                pass

        def test_sqlite():
            sqlite3.connect(os.path.join(HERE, "protected", "vault.db"))

        def test_reads_only():
            os.listdir(os.path.join(HERE, "protected"))
        """
    )
    result = pytester.runpytest_subprocess("-p", "no:cacheprovider")
    result.assert_outcomes(passed=1, failed=2)
    result.stdout.fnmatch_lines(["*test isolation guard*"])
    assert list((pytester.path / "protected").iterdir()) == []


def test_the_guard_fails_the_session_outside_tests(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(isolation_guard=GUARD_SOURCE)
    pytester.makeconftest(
        INNER_CONFTEST
        + """
try:
    os.mkdir(os.path.join(ROOT, "audit"))
except PermissionError:
    pass
"""
    )
    pytester.mkdir("protected")
    pytester.makepyfile(test_inner="def test_ok():\n    pass\n")
    result = pytester.runpytest_subprocess("-p", "no:cacheprovider")
    result.assert_outcomes(passed=1)
    assert result.ret == pytest.ExitCode.TESTS_FAILED
    assert list((pytester.path / "protected").iterdir()) == []


def test_every_default_path_lands_under_the_test_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("PGW_VAULT_DB", "PGW_VAULT_KEY_FILE", "PGW_AUDIT_LOG", "PGW_AUDIT_LOG_DIR"):
        monkeypatch.delenv(name, raising=False)
    home = (tmp_path / "home").resolve()
    config = load_config(env={})
    proxy = load_settings(env={})
    audit_dir = audit_dir_for(ProxySettings(), env={})
    tool_trail = RequestAuditLog(audit_dir, prefix=tool_policy.AUDIT_PREFIX)
    defaults = {
        "old audit log": config.audit.path,
        "vault": config.vault.db_path,
        "vault key": config.vault.key_file,
        "user config": Path.home() / USER_CONFIG_RELATIVE,
        "v2 audit dir": audit_dir,
        "tool-restore audit dir": tool_trail.directory,
        "launchd plist": launchd.plist_path("pgw-test"),
    }
    real = [Path(root) for root in protected_roots({})]
    for name, path in defaults.items():
        assert path is not None, name
        resolved = path.resolve()
        assert resolved.is_relative_to(home), name
        assert not any(resolved.is_relative_to(root) for root in real), name
    assert proxy.debug_dir is None
    assert proxy.config_path is None
    assert proxy.tool_restore_rules == ()

