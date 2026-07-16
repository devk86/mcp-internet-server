import os
import json
from unittest.mock import patch, MagicMock

from server import _audit_event, fetch_webpage_content


def test_audit_event_writes_json_line(tmp_path, monkeypatch):
    audit_file = tmp_path / "audit.log"
    monkeypatch.setenv("AUDIT_LOG_PATH", str(audit_file))

    _audit_event("test_tool", {"ok": True, "value": 123})

    content = audit_file.read_text(encoding="utf-8").strip()
    assert content
    record = json.loads(content)
    assert record["tool"] == "test_tool"
    assert record["ok"] is True
    assert record["value"] == 123


def test_audit_event_serializes_magicmock(tmp_path, monkeypatch):
    audit_file = tmp_path / "audit.log"
    monkeypatch.setenv("AUDIT_LOG_PATH", str(audit_file))

    mock_value = MagicMock()
    _audit_event("test_tool", {"ok": True, "value": mock_value})

    record = json.loads(audit_file.read_text(encoding="utf-8").strip())
    assert record["tool"] == "test_tool"
    assert record["ok"] is True
    assert isinstance(record["value"], str)


def test_fetch_webpage_content_logs_on_error(tmp_path, monkeypatch):
    audit_file = tmp_path / "audit.log"
    monkeypatch.setenv("AUDIT_LOG_PATH", str(audit_file))

    mock_resp = MagicMock()
    mock_resp.text = "not html"
    mock_resp.headers = {"Content-Type": "text/plain"}
    mock_resp.status_code = 200
    mock_client = MagicMock()
    mock_client.get.return_value = mock_resp

    class DummyClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return mock_client

        def __exit__(self, exc_type, exc, tb):
            return False

    with patch.dict("os.environ", {"ALLOWED_DOMAINS": "example.com"}):
        with patch("server.httpx.Client", new=DummyClient):
            with patch("server.socket.getaddrinfo") as mock_getaddr:
                mock_getaddr.return_value = [(2, 1, 6, '', ('93.184.216.34', 0))]
                res = fetch_webpage_content("https://example.com")
                assert res["ok"] is False

    lines = [l.strip() for l in open(audit_file, encoding="utf-8").read().splitlines() if l.strip()]
    assert lines
    last = json.loads(lines[-1])
    assert last["tool"] == "fetch_webpage_content"
    assert last["ok"] is False
