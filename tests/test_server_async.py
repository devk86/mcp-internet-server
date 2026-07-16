import json
import asyncio
from unittest.mock import patch, MagicMock

from server import search_internet_async, fetch_webpage_content_async


def test_search_internet_async():
    mock_result = [{"title": "T", "body": "B", "href": "http://example/"}]

    class MockDDGS:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def text(self, query, max_results=5):
            return iter(mock_result)

    with patch("server.DDGS", new=MockDDGS):
        res = asyncio.run(search_internet_async("something", max_results=1))
        assert res["ok"] is True
        assert len(res["results"]) == 1


def test_fetch_webpage_content_async_html():
    html = "<html><body><h1>Hello</h1><script>bad()</script></body></html>"
    mock_resp = MagicMock()
    mock_resp.text = html
    mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
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

    with patch("server.httpx.Client", new=DummyClient):
        res = asyncio.run(fetch_webpage_content_async("https://example.com"))
        assert res["ok"] is True
        assert "Hello" in res["text"]


def test_fetch_webpage_content_async_allowlist():
    html = "<html><body>Allowed</body></html>"
    mock_resp = MagicMock()
    mock_resp.text = html
    mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
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
                res = asyncio.run(fetch_webpage_content_async("https://sub.example.com/path"))
                assert res["ok"] is True
