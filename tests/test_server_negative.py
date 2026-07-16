import os
from unittest.mock import patch, MagicMock

import httpx

from server import search_internet, fetch_webpage_content


def test_search_internet_invalid_max_results():
    res = search_internet("query", max_results=0)
    assert res["ok"] is False
    assert "max_results" in res["error"]


def test_search_internet_exception_path():
    class MockDDGS:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def text(self, query, max_results=5):
            raise RuntimeError("search failed")

    with patch("server.DDGS", new=MockDDGS):
        res = search_internet("query", max_results=1)
        assert res["ok"] is False
        assert "search failed" in res["error"]


def test_fetch_webpage_content_invalid_scheme():
    res = fetch_webpage_content("ftp://example.com")
    assert res["ok"] is False
    assert "Invalid URL scheme" in res["error"]


def test_fetch_webpage_content_final_hostname_mismatch_allowlist():
    mock_resp = MagicMock()
    mock_resp.text = "<html><body>Redirected</body></html>"
    mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
    mock_resp.status_code = 200
    mock_resp.url = MagicMock(hostname="malicious.example", __str__=MagicMock(return_value="https://malicious.example"))
    mock_resp.content = mock_resp.text.encode("utf-8")
    mock_resp.encoding = "utf-8"

    def raise_for_status():
        return None

    mock_resp.raise_for_status = raise_for_status

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
                assert "Final hostname not in allowed domains" in res["error"]


def test_fetch_webpage_content_http_client_error():
    mock_resp = MagicMock()
    mock_resp.text = "<html><body>Not found</body></html>"
    mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
    mock_resp.status_code = 404
    mock_resp.url = MagicMock(hostname="example.com", __str__=MagicMock(return_value="https://example.com"))
    mock_resp.content = mock_resp.text.encode("utf-8")
    mock_resp.encoding = "utf-8"

    def raise_for_status():
        raise httpx.HTTPStatusError("404 Client Error", request=MagicMock(), response=mock_resp)

    mock_resp.raise_for_status = raise_for_status

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
            mock_getaddr.return_value = [(2, 1, 6, '', ('93.184.216.34', 0))]
            res = fetch_webpage_content("https://example.com")
            assert res["ok"] is False
            assert "HTTP error" in res["error"]
