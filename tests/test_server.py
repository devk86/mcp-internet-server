import pytest
import json
from unittest.mock import patch, MagicMock

from server import search_internet, fetch_webpage_content


def test_search_internet_no_results():
    mock_result = []

    class MockDDGS:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def text(self, query, max_results=5):
            return iter(mock_result)

    with patch("server.DDGS", new=MockDDGS):
        res = search_internet("nothing", max_results=1)
        assert isinstance(res, dict)
        assert res["ok"] is True
        assert res["results"] == []


def test_search_internet_results():
    mock_result = [{"title": "T", "body": "B", "href": "http://example/"}]

    class MockDDGS:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def text(self, query, max_results=5):
            return iter(mock_result)

    with patch("server.DDGS", new=MockDDGS):
        res = search_internet("something", max_results=1)
        assert res["ok"] is True
        assert len(res["results"]) == 1
        item = res["results"][0]
        assert item["title"] == "T"
        assert item["snippet"] == "B"
        assert item["url"] == "http://example/"


def make_mock_response(text, content_type="text/html; charset=utf-8", status_code=200):
    mock = MagicMock()
    mock.text = text
    mock.headers = {"Content-Type": content_type}
    mock.status_code = status_code

    def raise_for_status():
        if status_code >= 400:
            raise Exception(f"HTTP {status_code}")

    mock.raise_for_status = raise_for_status
    return mock


def test_fetch_webpage_content_html():
    html = "<html><body><h1>Hello</h1><script>bad()</script></body></html>"
    mock_resp = make_mock_response(html)

    mock_client = MagicMock()
    mock_client.get.return_value = mock_resp

    class DummyClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return mock_client

        def __exit__(self, exc_type, exc, tb):
            return False

    with patch("server.httpx.Client", new=DummyClient):
        res = fetch_webpage_content("https://example.com")
        assert res["ok"] is True
        assert "Hello" in res["text"]
        assert res["truncated"] in (True, False)


def test_fetch_webpage_content_non_html():
    mock_resp = make_mock_response("{}", content_type="application/json")
    mock_client = MagicMock()
    mock_client.get.return_value = mock_resp

    class DummyClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return mock_client

        def __exit__(self, exc_type, exc, tb):
            return False

    with patch("server.httpx.Client", new=DummyClient):
        res = fetch_webpage_content("https://example.com")
        assert res["ok"] is False
        assert "content_type" in res or "error" in res


def test_fetch_webpage_content_block_private_ip():
    # Simulate DNS resolving to a private IP
    html = "<html><body>Private</body></html>"
    mock_resp = make_mock_response(html)

    mock_client = MagicMock()
    mock_client.get.return_value = mock_resp

    class DummyClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return mock_client

        def __exit__(self, exc_type, exc, tb):
            return False

    with patch("server.httpx.Client", new=DummyClient):
        with patch("server.socket.getaddrinfo") as mock_getaddr:
            # Return an address that resolves to 127.0.0.1
            mock_getaddr.return_value = [(2, 1, 6, '', ('127.0.0.1', 0))]
            res = fetch_webpage_content("https://example.com")
            assert res["ok"] is False
            assert "restricted" in res.get("error", "").lower()


def test_fetch_webpage_content_allowlist():
    html = "<html><body>Allowed</body></html>"
    mock_resp = make_mock_response(html)
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
                res = fetch_webpage_content("https://sub.example.com/path")
                assert res["ok"] is True


def test_audit_log_written_for_search(tmp_path, monkeypatch):
    audit_file = tmp_path / "audit.log"
    monkeypatch.setenv("AUDIT_LOG_PATH", str(audit_file))

    mock_result = [{"title": "T", "body": "B", "href": "http://example/"}]

    class MockDDGS:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def text(self, query, max_results=5):
            return iter(mock_result)

    with patch("server.DDGS", new=MockDDGS):
        res = search_internet("audit test", max_results=1)
        assert res["ok"] is True

    # Read the last line of the audit file
    text = audit_file.read_text(encoding="utf-8")
    lines = [l for l in text.splitlines() if l.strip()]
    assert lines
    last = json.loads(lines[-1])
    assert last["tool"] == "search_internet"
    assert last["ok"] is True


def test_audit_log_written_for_fetch(tmp_path, monkeypatch):
    audit_file = tmp_path / "audit.log"
    monkeypatch.setenv("AUDIT_LOG_PATH", str(audit_file))

    html = "<html><body><h1>Hello</h1></body></html>"
    mock_resp = make_mock_response(html)

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
                assert res["ok"] is True

    text = audit_file.read_text(encoding="utf-8")
    lines = [l for l in text.splitlines() if l.strip()]
    assert lines
    last = json.loads(lines[-1])
    assert last["tool"] == "fetch_webpage_content"
    assert last["ok"] is True
