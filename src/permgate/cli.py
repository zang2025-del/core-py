"""Command-line entry point.

``classify`` is the one that earns its place. It runs the rule layer with no
database, no server and no configuration, which makes it usable in three places
the service is not: a pre-commit hook that checks a command before it is run, a
reviewer asking "why was this allowed", and a shell one-liner while writing a
rule. Everything else here is administration.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict
from typing import Any

from . import __version__


def _print_json(payload: object) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))


def _reconfigure_stdout() -> None:
    """Windows consoles default to a legacy code page; the rule reasons and the
    reports are UTF-8. Reconfiguring is cheaper than asking everyone to set an
    environment variable before they can read their own tooling's output."""
    encoding = (sys.stdout.encoding or "").lower()
    if encoding in ("utf-8", "utf8"):
        return
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is None:
        return
    with contextlib.suppress(ValueError):
        reconfigure(encoding="utf-8", errors="replace")


# --------------------------------------------------------------------- handlers


def cmd_classify(args: argparse.Namespace) -> int:
    """Offline: classify a command, no database or server involved."""
    from .domain import bash_policy

    command = " ".join(args.command)
    risk = bash_policy.classify_bash_command(command)
    blocklist = bash_policy.check_dangerous(command)
    scope = bash_policy.command_scope("bash", {"command": command})
    gate = bash_policy.execution_block(command)

    if args.json:
        _print_json(
            {
                "command": command,
                "vouched": risk is None,
                "allowlist_reason": risk,
                "blocklist_reason": blocklist,
                "execution_block": gate,
                "scope": scope,
            }
        )
        return 0 if risk is None else 1

    print(f"command    {command}")
    print(f"scope      {scope or '-'}")
    if risk is None:
        print("allowlist  ✅ vouched for -- no prompt")
    else:
        print(f"allowlist  ⚠ not vouched for -- {risk}")
    print(f"blocklist  {blocklist or '-'}")
    print(f"gate       {gate or '-'}")
    return 0 if risk is None else 1


def cmd_decide(args: argparse.Namespace) -> int:
    from .api.deps import build_container, create_schema
    from .config import get_settings
    from .domain.decision import RunMode

    settings = get_settings()
    container = build_container(settings)
    try:
        if settings.is_sqlite:
            create_schema(container.engine)
        result = container.decisions.evaluate(
            project_root=args.project,
            tool=args.tool,
            arguments={"command": " ".join(args.command)},
            mode=RunMode(args.mode) if args.mode else None,
            actor=args.actor,
        )
    finally:
        container.close()

    _print_json(
        {
            "decision_id": result.decision_id,
            "verdict": result.verdict.value,
            "rule": result.rule,
            "reason": result.reason,
            "scope": result.scope,
            "latency_us": result.latency_us,
            "project_root": result.project_root,
        }
    )
    return 0 if result.allowed else 3


def cmd_grants(args: argparse.Namespace) -> int:
    from .api.deps import build_container, create_schema
    from .config import get_settings

    settings = get_settings()
    container = build_container(settings)
    try:
        if settings.is_sqlite:
            create_schema(container.engine)
        listing = container.grants.list_for_project(args.project)
    finally:
        container.close()

    # `asdict`, not `__dict__`: these views are frozen slots dataclasses and
    # therefore have no instance dictionary at all.
    if args.json:
        _print_json(
            {
                "project_root": listing.project_root,
                "grants": [asdict(grant) for grant in listing.grants],
            }
        )
        return 0
    if not listing.grants:
        print(f"(no standing grants for {listing.project_root})")
        return 0
    print(listing.project_root)
    for grant in listing.grants:
        print(f"  {grant.key:<40} {grant.strength}")
        if grant.note:
            print(f"      note: {grant.note}")
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    from .api.deps import build_container, create_schema
    from .config import get_settings

    settings = get_settings()
    container = build_container(settings)
    try:
        if settings.is_sqlite:
            create_schema(container.engine)
        if args.all:
            result = container.grants.clear(project_root=args.project)
            print(f"cleared {result.removed} grant(s) in {result.project_root}")
        else:
            for key in args.keys:
                result = container.grants.revoke(project_root=args.project, key=key)
                print(
                    f"{'revoked' if result.removed else 'not found'}: {key}"
                    f"  ({result.project_root})"
                )
    finally:
        container.close()
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    from .api.deps import build_container, create_schema
    from .config import get_settings

    settings = get_settings()
    container = build_container(settings)
    try:
        if settings.is_sqlite:
            create_schema(container.engine)
        entries = container.audit.recent(
            project_root=args.project, limit=args.limit, verdict=args.verdict
        )
    finally:
        container.close()

    if args.json:
        _print_json([asdict(entry) for entry in entries])
        return 0
    for entry in entries:
        stamp = entry.occurred_at.isoformat(timespec="seconds")
        print(f"  {stamp}  {entry.verdict:<5} {entry.rule:<20} {entry.tool}")
        if entry.reason:
            print(f"      reason: {entry.reason}")
        if entry.answer:
            print(f"      answered: {entry.answer} (grant: {entry.granted_key or '-'})")
    return 0


def _client_list(repo: Any, as_json: bool) -> int:
    rows = repo.all()
    if as_json:
        _print_json(
            [
                {
                    "name": row.name,
                    "active": row.active,
                    "created_at": row.created_at,
                    "revoked_at": row.revoked_at,
                    "roots": list(repo.roots_for(row.id)),
                }
                for row in rows
            ]
        )
        return 0
    if not rows:
        print("(no clients)")
        return 0
    for row in rows:
        state = "active" if row.active else "revoked"
        roots = ", ".join(repo.roots_for(row.id)) or "(no roots)"
        print(f"  {row.name:<24} {state:<8} {roots}")
    return 0


def _client_revoke(repo: Any, name: str) -> int:
    if not repo.revoke(name):
        print(f"no active client named {name!r}", file=sys.stderr)
        return 2
    print(f"revoked {name}")
    return 0


def cmd_client(args: argparse.Namespace) -> int:
    """Create, list and revoke the callers allowed to use the service.

    The way in to a fresh deployment. Without it the fail-closed startup check
    is a locked door with the key inside: every endpoint needs a credential, and
    the only thing that mints credentials is this command.

    The token is printed **once**, at creation, and never again -- only its
    digest is stored, so a lost token is replaced rather than recovered. That is
    the same property that makes the table safe to back up, and it is worth
    stating in the one place an operator will read it.
    """
    import secrets

    from .api.deps import build_container, create_schema
    from .api.security import token_digest
    from .config import get_settings
    from .storage.database import session_scope
    from .storage.repositories import ClientRepository

    if args.action == "create" and not args.name:
        print("--name is required to create a client", file=sys.stderr)
        return 2
    if args.action == "create" and not args.root:
        # A client with no roots can authenticate and then be refused every
        # workspace name, which looks like a broken service rather than a
        # misconfigured client. Refuse at the CLI instead.
        print("at least one --root is required to create a client", file=sys.stderr)
        return 2

    settings = get_settings()
    container = build_container(settings)
    token: str | None = None
    stored_roots: tuple[str, ...] = ()
    try:
        if settings.is_sqlite:
            create_schema(container.engine)
        with session_scope(container.session_factory) as session:
            repo = ClientRepository(session)
            if args.action == "list":
                return _client_list(repo, args.json)
            if args.action == "revoke":
                return _client_revoke(repo, args.name)
            token = args.token or secrets.token_urlsafe(32)
            client, _ = repo.upsert(name=args.name, token_hash=token_digest(token), roots=args.root)
            # Read back what was actually stored, not what was typed. The
            # canonical form of a workspace is a fact this project leans on
            # everywhere else (``C:\x`` and ``C:/x`` are one directory), and a
            # creation message that echoes the input would suggest the
            # allowlist holds the string the operator happened to type.
            stored_roots = repo.roots_for(client.id)
    finally:
        container.close()

    print(f"client {args.name} ready, allowed to name:")
    for root in stored_roots:
        print(f"  {root}")
    print()
    print("bearer token (shown once, not recoverable):")
    print(f"  {token}")
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    """Run the offline evaluation. Delegates so there is one implementation."""
    import runpy
    from pathlib import Path

    script = Path(__file__).resolve().parent.parent.parent / "eval" / "run_eval.py"
    if not script.is_file():
        print(f"evaluation harness not found at {script}", file=sys.stderr)
        return 2
    sys.argv = [str(script), *args.passthrough]
    runpy.run_path(str(script), run_name="__main__")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .config import get_settings

    settings = get_settings()
    uvicorn.run(
        "permgate.main:app",
        host=args.host or settings.host,
        port=args.port or settings.port,
        reload=args.reload,
        log_config=None,
    )
    return 0


# ----------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="permgate", description=__doc__)
    parser.add_argument("--version", action="version", version=f"permgate {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    classify = sub.add_parser(
        "classify", help="classify a shell command offline (no database, no server)"
    )
    classify.add_argument("command", nargs="+")
    classify.add_argument("--json", action="store_true")
    classify.set_defaults(func=cmd_classify)

    decide = sub.add_parser("decide", help="evaluate one tool call against the policy engine")
    decide.add_argument("command", nargs="+")
    decide.add_argument("--project", default=".", help="project root")
    decide.add_argument("--tool", default="bash")
    decide.add_argument(
        "--mode",
        choices=["interactive", "unattended", "headless", "bypass"],
        default=None,
    )
    decide.add_argument("--actor", default=None)
    decide.set_defaults(func=cmd_decide)

    grants = sub.add_parser("grants", help="list standing grants for a project")
    grants.add_argument("--project", default=".")
    grants.add_argument("--json", action="store_true")
    grants.set_defaults(func=cmd_grants)

    revoke = sub.add_parser("revoke", help="withdraw one or all grants")
    revoke.add_argument("keys", nargs="*")
    revoke.add_argument("--project", default=".")
    revoke.add_argument("--all", action="store_true")
    revoke.set_defaults(func=cmd_revoke)

    audit = sub.add_parser("audit", help="read the decision audit trail")
    audit.add_argument("--project", default=None)
    audit.add_argument("--limit", type=int, default=20)
    audit.add_argument("--verdict", choices=["allow", "ask", "deny"], default=None)
    audit.add_argument("--json", action="store_true")
    audit.set_defaults(func=cmd_audit)

    clients = sub.add_parser(
        "client", help="create, list and revoke the callers allowed to use the service"
    )
    clients.add_argument("action", choices=["create", "list", "revoke"], nargs="?", default="list")
    clients.add_argument("--name", default=None, help="client label (required to create)")
    clients.add_argument(
        "--root",
        action="append",
        default=[],
        help="a workspace prefix this client may name; repeatable",
    )
    clients.add_argument(
        "--token",
        default=None,
        help="supply a token instead of generating one (testing and automation)",
    )
    clients.add_argument("--json", action="store_true")
    clients.set_defaults(func=cmd_client)

    evaluate = sub.add_parser("eval", help="run the offline quality evaluation")
    evaluate.add_argument("passthrough", nargs=argparse.REMAINDER)
    evaluate.set_defaults(func=cmd_eval)

    serve = sub.add_parser("serve", help="run the HTTP service")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--reload", action="store_true")
    serve.set_defaults(func=cmd_serve)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    _reconfigure_stdout()
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
