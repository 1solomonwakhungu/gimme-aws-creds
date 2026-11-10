#!/usr/bin/env python3
"""Check that the installed HTTP stack rejects over-long Content-Encoding chains.

GHSA-gm62-xv2j-4w53 (CVE-2025-66418): urllib3 before 2.6.0 applies an unbounded
number of chained decoders to ordinary responses, so a malicious or compromised
configured endpoint can exhaust CPU and memory. gimme-aws-creds reads responses
through Requests sessions, so this check exercises the same path.

Run this with the interpreter of an environment where the built wheel is
installed. It serves small fixtures from a loopback-only HTTP server and
requires that:

* the installed urllib3 is at or above the release floor;
* a chain at the decoder limit (5 gzip layers) still decodes correctly;
* a chain one past the limit (6 gzip layers) is rejected with a decoding error,
  within strict time and allocation budgets.

The fixtures are a few hundred bytes. No external network access is attempted.
"""
import gzip
import json
import re
import sys
import threading
import time
import tracemalloc
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

URLLIB3_FLOOR = (2, 6, 3)
DECODER_LIMIT = 5
TIME_BUDGET_SECONDS = 5.0
ALLOCATION_BUDGET_BYTES = 16 * 1024 * 1024
PAYLOAD = {"status": "fixture", "padding": "x" * 64}


def build_body(layers):
    """Return (body, Content-Encoding header) for the payload wrapped in `layers` gzip layers."""
    body = json.dumps(PAYLOAD).encode("utf-8")
    for _ in range(layers):
        body = gzip.compress(body, mtime=0)
    return body, ", ".join(["gzip"] * layers)


class ChainHandler(BaseHTTPRequestHandler):
    """Serve /chain/<n> with the payload gzip-encoded n times."""

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        try:
            prefix, layers = self.path.rsplit("/", 1)
            layers = int(layers)
            if prefix != "/chain" or not 0 <= layers <= 32:
                raise ValueError(self.path)
        except ValueError:
            self.send_error(404)
            return
        body, encoding = build_body(layers)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if encoding:
            self.send_header("Content-Encoding", encoding)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - BaseHTTPRequestHandler API
        return


def parse_version(text):
    """Return (major, minor, micro) from a version string, ignoring any suffix."""
    parts = []
    for piece in text.split(".")[:3]:
        match = re.match(r"\d+", piece)
        parts.append(int(match.group()) if match else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def below_floor(text):
    """True if the version is older than URLLIB3_FLOOR, counting pre-releases of the floor as older."""
    release = parse_version(text)
    if release != URLLIB3_FLOOR:
        return release < URLLIB3_FLOOR
    return re.search(r"(a|b|rc|dev)\d*", text.split("+", 1)[0].lower()) is not None


def start_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), ChainHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def fetch(session, base_url, layers):
    """Fetch /chain/<layers>; return (outcome, detail, seconds, peak allocation bytes)."""
    import requests

    tracemalloc.start()
    started = time.monotonic()
    try:
        response = session.get(f"{base_url}/chain/{layers}", timeout=TIME_BUDGET_SECONDS)
        outcome, detail = "decoded", response.json()
    except requests.exceptions.ContentDecodingError as exc:
        outcome, detail = "rejected", str(exc)
    except Exception as exc:  # report unexpected failures rather than crash
        outcome, detail = "error", f"{type(exc).__name__}: {exc}"
    elapsed = time.monotonic() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return outcome, detail, elapsed, peak


def run_checks():
    """Run the checks and return (report dict, list of failure strings)."""
    failures = []
    try:
        import requests
        import urllib3
    except ImportError as exc:
        return {}, [f"requests/urllib3 not importable: {exc}"]

    report = {"urllib3": urllib3.__version__, "requests": requests.__version__, "cases": {}}
    if below_floor(urllib3.__version__):
        failures.append(f"installed urllib3 {urllib3.__version__} is below the release floor 2.6.3")

    server = start_server()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    session = requests.Session()
    session.trust_env = False  # never route the loopback fixture through a configured proxy
    try:
        for layers, expected in ((DECODER_LIMIT, "decoded"), (DECODER_LIMIT + 1, "rejected")):
            outcome, detail, elapsed, peak = fetch(session, base_url, layers)
            report["cases"][str(layers)] = {
                "outcome": outcome,
                "seconds": round(elapsed, 4),
                "peak_alloc_bytes": peak,
                "detail": detail if outcome != "decoded" else "payload ok",
            }
            if outcome != expected:
                failures.append(f"{layers}-layer chain: expected {expected}, got {outcome} ({detail})")
            elif expected == "decoded" and detail != PAYLOAD:
                failures.append(f"{layers}-layer chain decoded to unexpected content")
            elif expected == "rejected" and "content encodings" not in detail.lower():
                failures.append(f"{layers}-layer chain rejected for an unexpected reason: {detail}")
            if elapsed > TIME_BUDGET_SECONDS:
                failures.append(f"{layers}-layer chain took {elapsed:.2f}s, budget {TIME_BUDGET_SECONDS}s")
            if peak > ALLOCATION_BUDGET_BYTES:
                failures.append(f"{layers}-layer chain allocated {peak} bytes, budget {ALLOCATION_BUDGET_BYTES}")
    finally:
        session.close()
        server.shutdown()
        server.server_close()
    return report, failures


def main():
    report, failures = run_checks()
    report["ok"] = not failures
    print(json.dumps(report, indent=2, sort_keys=True))
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
