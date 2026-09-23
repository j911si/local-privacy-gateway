"""Command line interface behind the `pgw-proxy` entry point."""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import sys
from collections.abc import Mapping
from pathlib import Path

from privacy_gateway.model import PrivacyGatewayError
from privacy_gateway_proxy import launchd
from privacy_gateway_proxy.settings import ProxySettings, is_loopback, load_settings, parse_listen

EXIT_OK = 0
EXIT_ERROR = 1

REPO_ROOT = Path(__file__).resolve().parent.parent


def program_args(repo_root: Path = REPO_ROOT) -> list[str]:
    """The command launchd runs to start the proxy."""
    return [
        shutil.which("uv") or "uv",
        "run",
        "--project",
        str(repo_root),
        "pgw-proxy",
        "serve",
    ]


def launchd_env(environ: Mapping[str, str]) -> dict[str, str]:
    """The `PGW_*` variables of the installing shell, plus `PATH` so `uv` is found."""
    env = {name: value for name, value in environ.items() if name.startswith("PGW_")}
    path = environ.get("PATH")
    if path is not None:
        env["PATH"] = path
    return env


def _settings(args: argparse.Namespace):
    overrides: dict[str, object] = {"config_path": getattr(args, "config", None)}
    listen = getattr(args, "listen", None)
    if listen is not None:
        overrides["listen_host"], overrides["listen_port"] = parse_listen(listen)
    upstream = getattr(args, "upstream", None)
    if upstream is not None:
        overrides["upstream_base_url"] = upstream
    return load_settings(env=os.environ, **overrides)


def log_startup(settings: ProxySettings) -> None:
    """Log the settings the process really runs with, and warn about an open bind."""
    log = logging.getLogger("privacy_gateway_proxy")
    log.info(
        "settings listen=%s:%s upstream=%s transform_system=%s placeholder_notice=%s "
        "debug_dir=%s debug_originals=%s",
        settings.listen_host,
        settings.listen_port,
        settings.upstream_base_url,
        settings.transform_system,
        settings.placeholder_notice,
        settings.debug_dir,
        settings.debug_originals,
    )
    if not is_loopback(settings.listen_host):
        log.warning(
            "listening on the non-loopback address %s: the host header check is off",
            settings.listen_host,
        )


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    from privacy_gateway.api import Gateway
    from privacy_gateway_proxy.server import create_app

    settings = _settings(args)
    gateway = Gateway(settings.config_path)
    app = create_app(settings, gateway)
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    log_startup(settings)
    uvicorn.run(app, host=settings.listen_host, port=settings.listen_port, log_level="info")
    return EXIT_OK


def _install_launchd(args: argparse.Namespace) -> int:
    settings = _settings(args)
    env = launchd_env(os.environ)
    path = launchd.install(args.label, program_args(), args.log_dir, env)
    print(f"installed {path}")
    for name in sorted(name for name in env if name.startswith("PGW_")):
        print(f"  {name}={env[name]}")
    print(f"logs: {args.log_dir}")
    print(f"export ANTHROPIC_BASE_URL=http://{settings.listen_host}:{settings.listen_port}")
    return EXIT_OK


def _uninstall_launchd(args: argparse.Namespace) -> int:
    path = launchd.uninstall(args.label)
    print(f"removed {path}")
    return EXIT_OK


def _status(args: argparse.Namespace) -> int:
    settings = _settings(args)
    result = launchd.status(args.label, settings.listen_host, settings.listen_port)
    print(f"label: {result.label}")
    print(f"plist: {result.plist}")
    print(f"loaded: {'yes' if result.loaded else 'no'}")
    print(f"listening on {settings.listen_host}:{settings.listen_port}: "
          f"{'yes' if result.listening else 'no'}")
    return EXIT_OK if result.listening else EXIT_ERROR


COMMANDS = {
    "serve": _serve,
    "install-launchd": _install_launchd,
    "uninstall-launchd": _uninstall_launchd,
    "status": _status,
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pgw-proxy", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", help="run the proxy in the foreground")
    serve.add_argument("--listen", default=None, help="host:port to bind")
    serve.add_argument("--upstream", default=None, help="upstream base URL")
    serve.add_argument("--config", type=Path, default=None, help="gateway configuration file")

    install = commands.add_parser("install-launchd", help="install the launchd agent")
    install.add_argument("--label", default=launchd.DEFAULT_LABEL)
    install.add_argument("--log-dir", type=Path, default=launchd.DEFAULT_LOG_DIR)

    uninstall = commands.add_parser("uninstall-launchd", help="remove the launchd agent")
    uninstall.add_argument("--label", default=launchd.DEFAULT_LABEL)

    status = commands.add_parser("status", help="show launchd job and port state")
    status.add_argument("--label", default=launchd.DEFAULT_LABEL)
    status.add_argument("--listen", default=None, help="host:port to probe")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one command and return its process exit code."""
    args = _build_parser().parse_args(argv)
    try:
        return COMMANDS[args.command](args)
    except PrivacyGatewayError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
