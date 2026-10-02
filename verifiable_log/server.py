"""Small HTTP front-end for the durable verifiable log."""

from __future__ import annotations

import json
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import canonical, store as storage


class LogError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _json_bytes(value) -> bytes:
    return canonical.dumps_canonical(value)


class LogHandler(BaseHTTPRequestHandler):
    server_version = "VerifiableLog/1"

    @property
    def store(self) -> "storage.Store":
        return self.server.store  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args) -> None:
        if getattr(self.server, "verbose", False):
            super().log_message(fmt, *args)

    def _send_json(self, status: int, value) -> None:
        body = _json_bytes(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: int, message: str) -> None:
        self._send_json(status, {"error": message})

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise LogError(HTTPStatus.BAD_REQUEST, "invalid Content-Length") from exc
        if length <= 0:
            raise LogError(HTTPStatus.BAD_REQUEST, "JSON request body is required")
        if length > 16 * 1024 * 1024:
            raise LogError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request is too large")
        body = self.rfile.read(length)
        if len(body) != length:
            raise LogError(HTTPStatus.BAD_REQUEST, "short request body")
        try:
            return canonical.loads(body)
        except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise LogError(HTTPStatus.BAD_REQUEST, f"invalid canonical JSON: {exc}") from exc

    def _query(self, name: str, required: bool = True, default: int | None = None):
        values = parse_qs(urlsplit(self.path).query).get(name)
        if not values:
            if required:
                raise LogError(HTTPStatus.BAD_REQUEST, f"missing query parameter {name}")
            return default
        if len(values) != 1:
            raise LogError(HTTPStatus.BAD_REQUEST, f"parameter {name} must appear once")
        try:
            value = int(values[0])
        except ValueError as exc:
            raise LogError(HTTPStatus.BAD_REQUEST, f"parameter {name} must be an integer") from exc
        return value

    def do_GET(self) -> None:
        try:
            parts = [part for part in urlsplit(self.path).path.split("/") if part]
            if parts == ["v1", "tree-head"]:
                size, root = self.store.tree_head()
                self._send_json(HTTPStatus.OK, {
                    "tree_size": size,
                    "root_hash": root.hex(),
                })
                return

            if len(parts) == 3 and parts[:2] == ["v1", "records"]:
                try:
                    index = int(parts[2])
                except ValueError as exc:
                    raise LogError(HTTPStatus.BAD_REQUEST, "record index must be an integer") from exc
                payload = self.store.get_entry(index)
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "index": index,
                        "data": canonical.loads(payload),
                        "canonical_json": payload.decode("utf-8"),
                    }
                )
                return

            if parts == ["v1", "inclusion"]:
                index = self._query("index")
                tree_size = self._query("tree_size", required=False)
                payload, size, root, proof = self.store.inclusion(index, tree_size)
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "leaf_index": index,
                        "tree_size": size,
                        "root_hash": root.hex(),
                        "leaf_hash": storage.merkle.leaf_hash(payload).hex(),
                        "proof": [item.hex() for item in proof],
                        "data": canonical.loads(payload),
                        "canonical_json": payload.decode("utf-8"),
                    }
                )
                return

            if parts == ["v1", "consistency"]:
                old_size = self._query("old_size")
                new_size = self._query("new_size", required=False)
                old_root, size, new_root, proof = self.store.consistency(
                    old_size, new_size
                )
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "old_size": old_size,
                        "new_size": size,
                        "old_root_hash": old_root.hex(),
                        "new_root_hash": new_root.hex(),
                        "proof": [item.hex() for item in proof],
                    }
                )
                return

            self._send_error(HTTPStatus.NOT_FOUND, "unknown endpoint")
        except LogError as exc:
            self._send_error(exc.status, exc.message)
        except IndexError as exc:
            self._send_error(HTTPStatus.NOT_FOUND, str(exc))
        except Exception as exc:  # defense for the request-handling thread
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"internal error: {exc}")

    def do_POST(self) -> None:
        try:
            parts = [part for part in urlsplit(self.path).path.split("/") if part]
            if parts != ["v1", "records"]:
                raise LogError(HTTPStatus.NOT_FOUND, "unknown endpoint")
            request = self._read_json()
            if not isinstance(request, dict) or not isinstance(request.get("records"), list):
                raise LogError(HTTPStatus.BAD_REQUEST, "request must be {\"records\": [...]}")
            if not request["records"]:
                raise LogError(HTTPStatus.BAD_REQUEST, "at least one record is required")
            payloads = [canonical.dumps_canonical(item) for item in request["records"]]
            start, _, root = self.store.append_entries(payloads)
            self._send_json(
                HTTPStatus.OK,
                {
                    "start_index": start,
                    "count": len(payloads),
                    "tree_size": start + len(payloads),
                    "root_hash": root.hex(),
                }
            )
        except LogError as exc:
            self._send_error(exc.status, exc.message)
        except (TypeError, UnicodeError, ValueError) as exc:
            self._send_error(HTTPStatus.BAD_REQUEST, f"invalid record: {exc}")
        except Exception as exc:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"internal error: {exc}")


def make_server(host: str, port: int, directory: str, crash_hook=None, verbose: bool = False):
    server = ThreadingHTTPServer((host, port), LogHandler)
    server.store = storage.Store(directory, crash_hook=crash_hook)  # type: ignore[attr-defined]
    server.verbose = verbose  # type: ignore[attr-defined]
    return server


def serve(host: str, port: int, directory: str, verbose: bool = False) -> None:
    server = make_server(host, port, directory, verbose=verbose)
    actual_host, actual_port = server.server_address[:2]
    if verbose:
        print(f"listening on http://{actual_host}:{actual_port}")
    else:
        print(actual_port, flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
