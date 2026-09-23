from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parents[2] / "privacy_gateway"
FORBIDDEN = frozenset(
    {
        "socket",
        "socketserver",
        "selectors",
        "http",
        "urllib.request",
        "urllib3",
        "requests",
        "httpx",
        "aiohttp",
        "ssl",
        "ftplib",
        "smtplib",
        "imaplib",
        "poplib",
        "telnetlib",
        "xmlrpc",
        "webbrowser",
        "subprocess",
        "ctypes",
        "asyncio",
        "privacy_gateway_proxy",
    }
)
FORBIDDEN_CALLS = frozenset(
    {
        "__import__",
        "eval",
        "exec",
        "import_module",
        "importlib.import_module",
        "os.system",
        "os.popen",
    }
)


def imported_modules(source: str) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def dotted_name(func: ast.expr) -> str:
    """The dotted name of a call target, or an empty string for anything else."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        prefix = dotted_name(func.value)
        return f"{prefix}.{func.attr}" if prefix else func.attr
    return ""


def called_names(source: str) -> set[str]:
    return {
        dotted_name(node.func)
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
    }


def offending(source: str) -> set[str]:
    """Forbidden imports and forbidden dynamic-import or process calls in one source file."""
    imports = {
        name
        for name in imported_modules(source)
        for forbidden in FORBIDDEN
        if name == forbidden or name.startswith(f"{forbidden}.")
    }
    calls = {
        name
        for name in called_names(source)
        if name in FORBIDDEN_CALLS or name.startswith("os.exec")
    }
    return imports | calls


@pytest.mark.parametrize("path", sorted(PACKAGE_ROOT.rglob("*.py")), ids=str)
def test_module_never_imports_the_network(path: Path) -> None:
    assert offending(path.read_text(encoding="utf-8")) == set()


@pytest.mark.parametrize(
    "source",
    [
        "import socket",
        "import subprocess",
        "import asyncio",
        "import ctypes",
        "import xmlrpc.client",
        "import privacy_gateway_proxy.streaming",
        "from privacy_gateway_proxy import server",
        'importlib.import_module("socket")',
        'import_module("socket")',
        '__import__("socket")',
        'os.system("ls")',
        'os.popen("ls")',
        'os.execv("/bin/ls", [])',
        'eval("1 + 1")',
        'exec("x = 1")',
    ],
)
def test_the_checker_catches_known_evasions(source: str) -> None:
    assert offending(source)


def test_the_checker_accepts_a_harmless_module() -> None:
    source = "import json\nfrom pathlib import Path\n\njson.dumps(str(Path.cwd()))\n"
    assert offending(source) == set()
