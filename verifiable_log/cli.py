"""Command-line service operations."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import audit as audit_module
from . import canonical
from .server import serve


def _base(url: str) -> str:
    return url.rstrip("/")


def _http_json(url: str, method: str = "GET", payload: bytes | None = None):
    import urllib.error
    import urllib.request

    request = urllib.request.Request(
        url,
        data=payload,
        method=method,
        headers={"Content-Type": "application/json; charset=utf-8"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"request failed: {exc}") from exc
    return canonical.loads(body)


def _print(value) -> None:
    print(canonical.dumps_canonical(value).decode("utf-8"))


def _load_records(paths: list[str]) -> list:
    records = []
    for path in paths:
        with open(path, "rb") as handle:
            value = canonical.loads(handle.read())
        records.append(value)
    return records


def command_append(args: argparse.Namespace) -> int:
    values: list = []
    if args.file:
        values.extend(_load_records(args.file))
    if args.json:
        for text in args.json:
            values.append(canonical.loads(text.encode("utf-8")))
    if not values:
        raise SystemExit("provide --file and/or --json")
    body = canonical.dumps_canonical({"records": values})
    result = _http_json(_base(args.url) + "/v1/records", "POST", body)
    _print(result)
    return 0


def command_record(args: argparse.Namespace) -> int:
    _print(_http_json(f"{_base(args.url)}/v1/records/{args.index}"))
    return 0


def command_tree_head(args: argparse.Namespace) -> int:
    _print(_http_json(_base(args.url) + "/v1/tree-head"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verifiable-log",
        description="Serve and inspect a durable verifiable append log",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("serve", help="run the HTTP service")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--data", required=True)
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=lambda args: serve(args.host, args.port, args.data, args.verbose))

    p = sub.add_parser("append", help="atomically append a batch of JSON records")
    p.add_argument("url")
    p.add_argument("--file", action="append", default=[], help="JSON file; repeatable")
    p.add_argument("--json", action="append", default=[], help="inline JSON; repeatable")
    p.set_defaults(func=command_append)

    p = sub.add_parser("record", help="fetch a record by sequence number")
    p.add_argument("url")
    p.add_argument("--index", type=int, required=True)
    p.set_defaults(func=command_record)

    p = sub.add_parser("tree-head", help="fetch the current tree head")
    p.add_argument("url")
    p.set_defaults(func=command_tree_head)

    sub.add_parser(
        "audit",
        help="independently verify roots, inclusion, and consistency",
        add_help=False,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    if argv and argv[0] == "audit":
        return audit_module.main(argv[1:])

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    raise SystemExit(main())
