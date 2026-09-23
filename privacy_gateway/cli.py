"""Command line interface behind the `pgw` entry point."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from privacy_gateway.api import Gateway
from privacy_gateway.model import LeakageError, PrivacyGatewayError, SummaryReport

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FAIL_CLOSED = 2

REPORT_FORMATS = ("json", "text")
RESTORE_MODES = ("strict", "lenient")


def _read_input(source: str) -> str:
    if source == "-":
        return sys.stdin.read()
    return Path(source).read_text(encoding="utf-8")


def _write_private(target: Path, text: str) -> None:
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)


def _write_output(target: Path | None, text: str) -> None:
    if target is None:
        sys.stdout.write(text)
        return
    _write_private(target, text)


def _write_report(report_format: str | None, report: SummaryReport) -> None:
    if report_format is None:
        return
    if report_format == "json":
        payload = {
            "counts": report.counts,
            "tokens": report.tokens,
            "leakage": report.leakage,
            "duration_ms": report.duration_ms,
        }
        print(json.dumps(payload, sort_keys=True), file=sys.stderr)
        return
    for name in sorted(report.counts):
        print(f"{name}: {report.counts[name]}", file=sys.stderr)
    print(f"tokens: {len(report.tokens)}", file=sys.stderr)
    print(f"leakage: {report.leakage}", file=sys.stderr)


def _pseudonymize(args: argparse.Namespace) -> int:
    text = _read_input(args.file)
    with Gateway(args.config) as gateway:
        try:
            if args.session_key is None:
                result = gateway.pseudonymize(text)
                output, session_id, report = result.text, result.session_id, result.report
            else:
                session = gateway.session(args.session_key)
                output, session_id, report = session.pseudonymize(text), session.session_id, None
        except LeakageError as exc:
            classes = sorted({leak.data_class for leak in exc.leaks if leak.data_class})
            print(
                f"fail-closed: {len(exc.leaks)} potential leak(s) detected "
                f"(classes: {', '.join(classes) or 'none'})",
                file=sys.stderr,
            )
            return EXIT_FAIL_CLOSED
        _write_output(args.out, output)
        print(f"session: {session_id}", file=sys.stderr)
        if args.session_file is not None:
            _write_private(args.session_file, session_id)
        if report is not None:
            _write_report(args.report, report)
    return EXIT_OK


def _restore(args: argparse.Namespace) -> int:
    text = _read_input(args.file)
    with Gateway(args.config) as gateway:
        result = gateway.restore(text, args.session, args.mode)
    _write_output(args.out, result.text)
    if result.unknown_tokens:
        print(f"unknown tokens: {', '.join(result.unknown_tokens)}", file=sys.stderr)
    return EXIT_OK


def _validate(args: argparse.Namespace) -> int:
    text = _read_input(args.file)
    with Gateway(args.config) as gateway:
        counts = gateway.scan(text).counts_by_class()
    if not counts:
        print("no sensitive data detected")
        return EXIT_OK
    for name in sorted(counts):
        print(f"{name}: {counts[name]}")
    return EXIT_FAIL_CLOSED


def _classes(args: argparse.Namespace) -> int:
    with Gateway(args.config) as gateway:
        for data_class in gateway.config.registry:
            print(f"{data_class.name}\t{data_class.policy.value}\t{data_class.priority}")
    return EXIT_OK


def _vault(args: argparse.Namespace) -> int:
    with Gateway(args.config) as gateway:
        if args.vault_command == "list":
            for info in gateway.vault.list_sessions():
                print(f"{info.id}\t{info.created_at}\t{info.token_count}")
            return EXIT_OK
        if args.session is not None:
            gateway.vault.purge(args.session)
            purged = 1
        else:
            purged = gateway.vault.purge_older_than(args.older_than)
        gateway.audit.vault_purge(purged)
        print(f"purged {purged} session(s)")
    return EXIT_OK


COMMANDS = {
    "pseudonymize": _pseudonymize,
    "restore": _restore,
    "validate": _validate,
    "classes": _classes,
    "vault": _vault,
}


def _build_parser() -> argparse.ArgumentParser:
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--config", type=Path, default=None, help="extra configuration file")

    parser = argparse.ArgumentParser(prog="pgw", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    pseudonymize = commands.add_parser("pseudonymize", parents=[shared])
    pseudonymize.add_argument("file", nargs="?", default="-")
    pseudonymize.add_argument("--out", type=Path, default=None)
    pseudonymize.add_argument("--session-file", type=Path, default=None)
    pseudonymize.add_argument("--session-key", default=None)
    pseudonymize.add_argument("--report", choices=REPORT_FORMATS, default=None)

    restore = commands.add_parser("restore", parents=[shared])
    restore.add_argument("file", nargs="?", default="-")
    restore.add_argument("--session", required=True)
    restore.add_argument("--mode", choices=RESTORE_MODES, default=None)
    restore.add_argument("--out", type=Path, default=None)

    validate = commands.add_parser("validate", parents=[shared])
    validate.add_argument("file", nargs="?", default="-")

    commands.add_parser("classes", parents=[shared])

    vault = commands.add_parser("vault", parents=[shared])
    vault_commands = vault.add_subparsers(dest="vault_command", required=True)
    vault_commands.add_parser("list")
    purge = vault_commands.add_parser("purge")
    selection = purge.add_mutually_exclusive_group(required=True)
    selection.add_argument("--session", default=None)
    selection.add_argument("--older-than", type=int, default=None)
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
