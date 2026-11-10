"""Tests for ci/release/check_encoding_chain.py (loopback-only fixtures)."""
import gzip
import json

import check_encoding_chain


def test_fixture_bodies_are_small_and_layered():
    body, header = check_encoding_chain.build_body(6)
    assert header == ", ".join(["gzip"] * 6)
    assert len(body) < 1024
    for _ in range(6):
        body = gzip.decompress(body)
    assert json.loads(body) == check_encoding_chain.PAYLOAD


def test_installed_stack_rejects_chain_past_limit():
    report, failures = check_encoding_chain.run_checks()
    assert failures == [], failures
    assert report["cases"]["5"]["outcome"] == "decoded"
    assert report["cases"]["6"]["outcome"] == "rejected"
    assert "content encodings" in report["cases"]["6"]["detail"].lower()


def test_old_urllib3_version_is_reported(monkeypatch):
    import urllib3

    monkeypatch.setattr(urllib3, "__version__", "1.26.20")
    _, failures = check_encoding_chain.run_checks()
    assert any("below the release floor" in f for f in failures)


def test_unknown_paths_are_not_served():
    import requests

    server = check_encoding_chain.start_server()
    try:
        session = requests.Session()
        session.trust_env = False
        port = server.server_address[1]
        assert session.get(f"http://127.0.0.1:{port}/other/1", timeout=5).status_code == 404
        assert session.get(f"http://127.0.0.1:{port}/chain/999", timeout=5).status_code == 404
    finally:
        server.shutdown()
        server.server_close()


def test_version_parsing():
    assert check_encoding_chain.parse_version("2.6.3") == (2, 6, 3)
    assert check_encoding_chain.parse_version("2.7") == (2, 7, 0)
    assert check_encoding_chain.parse_version("2.6.3rc1") == (2, 6, 3)


def test_floor_comparison():
    assert check_encoding_chain.below_floor("1.26.20")
    assert check_encoding_chain.below_floor("2.6.2")
    assert check_encoding_chain.below_floor("2.6.3rc1")
    assert not check_encoding_chain.below_floor("2.6.3")
    assert not check_encoding_chain.below_floor("2.8.0")
