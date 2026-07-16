"""
server.py
-----------------
MCP server exposing two tools to search the internet and fetch
webpage content. Includes basic SSRF protections, audit logging,
and structured results suitable for downstream processing.

Tools:
- `search_internet(query, max_results)`: performs a web search and
    returns a structured list of results.
- `fetch_webpage_content(url)`: fetches and extracts text from
    an HTML page, with content-type checking and SSRF protections.

Configuration (via environment variables):
- `ALLOWED_DOMAINS`: optional comma-separated allowlist of domains
    that `fetch_webpage_content` is allowed to retrieve.
- `AUDIT_LOG_PATH`: path for newline-delimited JSON audit events.

This module is intentionally small and focused: it returns structured
dict results and performs light validation to guard against common
misuse when running as a network-accessible tool.
"""

import logging
from logging.handlers import RotatingFileHandler
import json
from datetime import datetime, timezone
import os
import socket
import ipaddress
import idna
import time
from typing import Any, Dict, List
from urllib.parse import urlparse
import asyncio

import httpx
from bs4 import BeautifulSoup
try:
    from ddgs import DDGS
except Exception:
    from duckduckgo_search import DDGS
from fastmcp import FastMCP
from prometheus_client import Counter, Histogram, start_http_server
# Initialize the MCP Server
# The name "InternetAssistant" will be visible to the LLM
mcp = FastMCP("InternetAssistant")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add a rotating file handler so multiple processes can write logs to a
# common file. This makes it easy to tail logs from a different terminal.
LOG_PATH = os.getenv("LOG_PATH", "server.log")
if LOG_PATH:
    try:
        fh = RotatingFileHandler(LOG_PATH, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
        fh.setLevel(logging.INFO)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        # Add handler to the root logger so all modules write to the same file
        logging.getLogger().addHandler(fh)
    except Exception:
        logger.exception("Failed to create file log handler")

# Optional structured JSON log file for external ingestion
LOG_JSON_PATH = os.getenv("LOG_JSON_PATH", "server.jsonl")
if LOG_JSON_PATH:
    try:
        class JsonLineFormatter(logging.Formatter):
            def format(self, record: logging.LogRecord) -> str:
                obj = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "level": record.levelname,
                    "logger": record.name,
                    "message": record.getMessage(),
                }
                if record.exc_info:
                    obj["exc_info"] = self.formatException(record.exc_info)
                return json.dumps(obj, ensure_ascii=False)

        jh = RotatingFileHandler(LOG_JSON_PATH, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        jh.setLevel(logging.INFO)
        jh.setFormatter(JsonLineFormatter())
        logging.getLogger().addHandler(jh)
    except Exception:
        logger.exception("Failed to create JSON log handler")

# Audit log path configurable via environment variable
AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "audit.log")
METRICS_PORT = int(os.getenv("METRICS_PORT", "0"))

# Prometheus metrics
REQUEST_COUNTER = Counter("mcp_requests_total", "Total MCP tool requests", ["tool", "ok"])
REQUEST_LATENCY = Histogram("mcp_request_latency_seconds", "Request latency seconds", ["tool"]) 

# Start Prometheus metrics HTTP server in background when enabled
if METRICS_PORT > 0:
    try:
        start_http_server(METRICS_PORT)
        logger.info("Prometheus metrics server started on port %s", METRICS_PORT)
    except Exception:
        logger.exception("Failed to start Prometheus metrics server")


def _audit_event(tool: str, details: Dict[str, Any]) -> None:
    """Append a JSON-line audit event to the audit log file.

    The audit log is newline-delimited JSON. Each event includes a
    UTC ISO8601 `timestamp` and a `tool` name along with any supplied
    `details`. Failures to write the audit log are logged but do not
    raise exceptions (to avoid interrupting the main tool flow).

    Args:
        tool: short name of the tool emitting the event (e.g. "search_internet").
        details: additional key/value pairs to include in the event.
    """
    try:
        event = {"timestamp": datetime.now(timezone.utc).isoformat(), "tool": tool}
        event.update(details or {})

        # Ensure all event values are JSON-serializable; replace unknown
        # objects with their string representation to avoid crashes when
        # tests pass MagicMock or other complex objects.
        def _safe(obj):
            if obj is None or isinstance(obj, (str, int, float, bool)):
                return obj
            if isinstance(obj, dict):
                return {k: _safe(v) for k, v in obj.items()}
            if isinstance(obj, (list, tuple)):
                return [_safe(v) for v in obj]
            try:
                json.dumps(obj)
                return obj
            except Exception:
                return str(obj)

        safe_event = _safe(event)
        line = json.dumps(safe_event, ensure_ascii=False)
        # Write to configured audit log path (append newline-delimited JSON)
        path = os.getenv("AUDIT_LOG_PATH", AUDIT_LOG_PATH)
        dirpath = os.path.dirname(path)
        if dirpath and not os.path.exists(dirpath):
            os.makedirs(dirpath, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        logger.info("Audit event written: %s", tool)
        # increment prometheus counter for audit events
        try:
            REQUEST_COUNTER.labels(tool=tool, ok="true").inc()
        except Exception:
            pass
    except Exception:
        logger.exception("Failed to write audit event for %s", tool)

# (Use REQUEST_COUNTER/REQUEST_LATENCY above for instrumentation)

# Additional Prometheus metrics
SEARCH_COUNTER = Counter("mcp_search_total", "Total number of search_internet calls", ["ok"])
FETCH_COUNTER = Counter("mcp_fetch_total", "Total number of fetch_webpage_content calls", ["ok"])
FETCH_DURATION = Histogram("mcp_fetch_duration_seconds", "Duration of fetch_webpage_content calls in seconds")
SEARCH_DURATION = Histogram("mcp_search_duration_seconds", "Duration of search_internet calls in seconds")

@mcp.tool()
def search_internet(query: str, max_results: int = 5) -> Dict[str, Any]:
    """Search the web for `query` and return structured results.

    Returns a dict with keys:
    - `ok`: bool success flag
    - `results`: list of result dicts (each has `index`, `title`, `snippet`, `url`)

    The function limits `max_results` to a reasonable range to avoid
    overloading the upstream search backend.
    """

    if max_results < 1 or max_results > 20:
        res = {"ok": False, "error": "max_results must be between 1 and 20"}
        _audit_event("search_internet", {"query": query, "max_results": max_results, "ok": False, "error": res["error"]})
        return res

    with REQUEST_LATENCY.labels(tool="search_internet").time():
        try:
            logger.info("Performing search: query=%s max_results=%s", query, max_results)
            with DDGS() as ddgs:
                results = list(ddgs.text(query, max_results=max_results))

            if not results:
                SEARCH_COUNTER.labels(ok="true").inc()
                REQUEST_COUNTER.labels(tool="search_internet", ok="true").inc()
                res = {"ok": True, "results": []}
                _audit_event("search_internet", {"query": query, "max_results": max_results, "ok": True, "result_count": 0})
                return res

            formatted_results: List[Dict[str, Any]] = []
            for i, item in enumerate(results, 1):
                formatted_results.append({
                    "index": i,
                    "title": item.get("title"),
                    "snippet": item.get("body"),
                    "url": item.get("href"),
                })

            SEARCH_COUNTER.labels(ok="true").inc()
            REQUEST_COUNTER.labels(tool="search_internet", ok="true").inc()
            res = {"ok": True, "results": formatted_results}
            _audit_event("search_internet", {"query": query, "max_results": max_results, "ok": True, "result_count": len(formatted_results)})
            return res
        except Exception as e:
            logger.exception("Error performing search")
            SEARCH_COUNTER.labels(ok="false").inc()
            try:
                REQUEST_COUNTER.labels(tool="search_internet", ok="false").inc()
            except Exception:
                pass
            _audit_event("search_internet", {"query": query, "max_results": max_results, "ok": False, "error": str(e)})
            return {"ok": False, "error": str(e)}

@mcp.tool()
def fetch_webpage_content(url: str) -> Dict[str, Any]:
    """
    Fetches the text content from a specific URL. 
    Use this after searching to read the actual content of a page.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    """Fetch and extract text content from an HTML `url`.

    Returns a dict with keys:
    - `ok`: bool
    - `url`: canonical URL requested
    - `text`: extracted text (truncated to 12k chars)
    - `truncated`: whether the returned text was truncated

    The function validates scheme, optionally enforces an allowlist
    of domains via `ALLOWED_DOMAINS`, resolves the hostname and blocks
    requests that resolve to private/loopback/reserved IPs to reduce
    SSRF risk, and ensures the response is HTML before extracting text.
    """

    # Basic URL validation
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {"ok": False, "error": "Invalid URL scheme; only http/https allowed."}

    # SSRF protections: allowlist and private IP blocking
    # Allowed domains can be set via the environment variable ALLOWED_DOMAINS (comma-separated).
    allowed_domains_env = os.getenv("ALLOWED_DOMAINS", "")
    allowed_domains = [d.strip().lower() for d in allowed_domains_env.split(",") if d.strip()]

    hostname = parsed.hostname or ""
    hostname_l = hostname.lower()

    # If allowlist is set, require the hostname to match one of the allowed domains (exact or suffix)
    if allowed_domains:
        matched = any(hostname_l == d or hostname_l.endswith("." + d) for d in allowed_domains)
        if not matched:
            return {"ok": False, "error": "Hostname not in allowed domains."}

    # Resolve hostname and ensure it doesn't resolve to private IP ranges
    try:
        addrs = []
        for res in socket.getaddrinfo(hostname, None):
            sockaddr = res[4]
            ip = sockaddr[0]
            addrs.append(ip)

        for ip_str in addrs:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                    return {"ok": False, "error": "URL resolves to a restricted IP address."}
            except ValueError:
                # ignore unparsable addresses
                continue
    except Exception:
        # If resolution fails, continue and let the HTTP client surface the error
        logger.debug("Hostname resolution failed for %s; continuing to request", hostname)

    # Normalize hostname using IDNA to prevent unicode tricks
    try:
        hostname_ascii = idna.encode(hostname).decode("ascii") if hostname else ""
    except Exception:
        hostname_ascii = hostname

    # Retry loop for transient errors
    MAX_ATTEMPTS = 3
    BACKOFF_BASE = 0.5
    MAX_READ = 200_000  # bytes to read at most
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            logger.info("Fetching URL (attempt %s): %s", attempt, url)
            with FETCH_DURATION.time():
                with httpx.Client(follow_redirects=True, timeout=10.0) as client:
                    # Support both streaming clients and simple clients that only
                    # implement `get()`. Some test doubles provide only `get()`.
                    used_stream = False
                    response_ctx = None
                    # Prefer `get()` when available (test doubles often provide get()).
                    if hasattr(client, "get"):
                        response = client.get(url, headers=headers)
                        used_stream = False
                    elif hasattr(client, "stream"):
                        response_ctx = client.stream("GET", url, headers=headers, timeout=10.0, follow_redirects=True, max_redirects=5)
                        response = response_ctx.__enter__()
                        used_stream = True
                    else:
                        # As a final fallback, try calling client.request
                        response = client.request("GET", url, headers=headers)

                try:
                    response.raise_for_status()

                    # After redirects, verify final hostname
                    final_url = str(getattr(response, "url", url))
                    final_hostname = getattr(getattr(response, "url", None), "hostname", parsed.hostname) or ""
                    final_hostname_ascii = final_hostname
                    try:
                        final_hostname_ascii = idna.encode(final_hostname).decode("ascii")
                    except Exception:
                        pass

                    # If allowlist is set, ensure final hostname matches it
                    if allowed_domains and not any(final_hostname_ascii == d or final_hostname_ascii.endswith("." + d) for d in allowed_domains):
                        res = {"ok": False, "error": "Final hostname not in allowed domains."}
                        _audit_event("fetch_webpage_content", {"url": url, "hostname": final_hostname, "ok": False, "error": res["error"]})
                        return res

                    # Resolve final hostname and ensure it isn't private
                    try:
                        addrs = []
                        for resinfo in socket.getaddrinfo(final_hostname, None):
                            sockaddr = resinfo[4]
                            ip = sockaddr[0]
                            addrs.append(ip)

                        for ip_str in addrs:
                            try:
                                ip_obj = ipaddress.ip_address(ip_str)
                                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                                    res = {"ok": False, "error": "URL resolves to a restricted IP address."}
                                    _audit_event("fetch_webpage_content", {"url": url, "hostname": final_hostname, "ok": False, "error": res["error"]})
                                    return res
                            except ValueError:
                                continue
                    except Exception:
                        logger.debug("Final hostname resolution failed for %s; continuing", final_hostname)

                    content_type = getattr(response, "headers", {}).get("Content-Type", "")
                    if "text/html" not in content_type:
                        res = {"ok": False, "error": "URL did not return HTML content.", "content_type": content_type}
                        _audit_event("fetch_webpage_content", {"url": url, "hostname": final_hostname, "ok": False, "content_type": content_type})
                        return res

                    # Read up to MAX_READ bytes from the response
                    total = 0
                    chunks = []
                    if used_stream and hasattr(response, "iter_bytes"):
                        for byte_chunk in response.iter_bytes(chunk_size=8192):
                            if not byte_chunk:
                                break
                            if total + len(byte_chunk) > MAX_READ:
                                chunks.append(byte_chunk[: MAX_READ - total])
                                total = MAX_READ
                                break
                            chunks.append(byte_chunk)
                            total += len(byte_chunk)
                        raw = b"".join(chunks)
                    else:
                        content = getattr(response, "content", None)
                        # Ensure content is bytes; some test doubles provide a MagicMock
                        if not isinstance(content, (bytes, bytearray)):
                            content = None

                        if content is None:
                            # fallback to response.text encoded
                            text_raw = getattr(response, "text", "")
                            if isinstance(text_raw, str):
                                enc = getattr(response, "encoding", None)
                                if not isinstance(enc, str):
                                    enc = "utf-8"
                                raw = text_raw.encode(enc, errors="replace")
                            else:
                                raw = str(text_raw).encode("utf-8", errors="replace")
                        else:
                            raw = content

                        if len(raw) > MAX_READ:
                            raw = raw[:MAX_READ]

                    enc = getattr(response, "encoding", None)
                    encoding = enc if isinstance(enc, str) else "utf-8"
                    try:
                        html_text = raw.decode(encoding, errors="replace")
                    except Exception:
                        html_text = raw.decode("utf-8", errors="replace")

                    # Parse HTML and extract text
                    soup = BeautifulSoup(html_text, "html.parser")
                    for script_or_style in soup(["script", "style", "nav", "footer", "header"]):
                        script_or_style.decompose()

                    text = soup.get_text(separator=" ")
                    lines = (line.strip() for line in text.splitlines())
                    chunks_text = (phrase.strip() for line in lines for phrase in line.split("  "))
                    clean_text = "\n".join(chunk for chunk in chunks_text if chunk)

                    truncated = len(clean_text) > 12000
                    returned_text = clean_text[:12000]
                    FETCH_COUNTER.labels(ok="true").inc()
                    res = {"ok": True, "url": final_url, "text": returned_text, "truncated": truncated}
                    _audit_event("fetch_webpage_content", {"url": final_url, "hostname": final_hostname, "ok": True, "truncated": truncated})
                    return res
                finally:
                    if response_ctx is not None:
                        try:
                            response_ctx.__exit__(None, None, None)
                        except Exception:
                            pass

        except httpx.HTTPStatusError as e:
            logger.warning("HTTP status error fetching URL (attempt %s): %s %s", attempt, url, e)
            last_exc = e
            # do not retry for 4xx client errors
            if e.response is not None and 400 <= e.response.status_code < 500:
                FETCH_COUNTER.labels(ok="false").inc()
                _audit_event("fetch_webpage_content", {"url": url, "hostname": hostname, "ok": False, "error": str(e)})
                return {"ok": False, "error": f"HTTP error: {str(e)}"}
        except httpx.RequestError as e:
            logger.warning("Request error fetching URL (attempt %s): %s %s", attempt, url, e)
            last_exc = e
        except Exception as e:
            logger.exception("Unexpected error fetching URL: %s", url)
            FETCH_COUNTER.labels(ok="false").inc()
            _audit_event("fetch_webpage_content", {"url": url, "hostname": hostname, "ok": False, "error": str(e)})
            return {"ok": False, "error": str(e)}

        # Backoff before retrying
        if attempt < MAX_ATTEMPTS:
            backoff = BACKOFF_BASE * (2 ** (attempt - 1))
            time.sleep(backoff)

    # If we get here, retries exhausted
    logger.error("Exhausted retries fetching URL: %s", url)
    _audit_event("fetch_webpage_content", {"url": url, "hostname": hostname, "ok": False, "error": "retries_exhausted"})
    return {"ok": False, "error": "Failed to fetch URL after retries."}

if __name__ == "__main__":
    # Run the server
    mcp.run()


@mcp.tool()
async def search_internet_async(query: str, max_results: int = 5) -> Dict[str, Any]:
    """Async wrapper for `search_internet`.

    This convenience wrapper runs the existing synchronous implementation
    in a threadpool so callers can await it. It preserves the same
    return shape while providing an async-friendly API.
    """
    return await asyncio.to_thread(search_internet, query, max_results)


@mcp.tool()
async def fetch_webpage_content_async(url: str) -> Dict[str, Any]:
    """Async wrapper for `fetch_webpage_content`.

    For now this runs the stable synchronous implementation in a
    threadpool so async callers can await it. Future iterations can
    replace this with a fully async implementation that uses
    `httpx.AsyncClient` for improved throughput.
    """
    return await asyncio.to_thread(fetch_webpage_content, url)
