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
from typing import Any, Dict, List
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup
try:
    from ddgs import DDGS
except Exception:
    from duckduckgo_search import DDGS
from fastmcp import FastMCP

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

# Audit log path configurable via environment variable
AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "audit.log")


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
        line = json.dumps(event, ensure_ascii=False)
        # Write to configured audit log path (append newline-delimited JSON)
        path = os.getenv("AUDIT_LOG_PATH", AUDIT_LOG_PATH)
        dirpath = os.path.dirname(path)
        if dirpath and not os.path.exists(dirpath):
            os.makedirs(dirpath, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        logger.info("Audit event written: %s", tool)
    except Exception:
        logger.exception("Failed to write audit event for %s", tool)

@mcp.tool()
def search_internet(query: str, max_results: int = 5) -> Dict[str, Any]:
    """
    Searches the internet for a given query and returns a list of 
    titles, snippets, and URLs. Use this to find information.
    """
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

    try:
        logger.info("Performing search: query=%s max_results=%s", query, max_results)
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))

        if not results:
            res = {"ok": True, "results": []}
            _audit_event("search_internet", {"query": query, "max_results": max_results, "ok": True, "result_count": 0})
            return res

        formatted_results: List[Dict[str, Any]] = []
        for i, res in enumerate(results, 1):
            formatted_results.append({
                "index": i,
                "title": res.get("title"),
                "snippet": res.get("body"),
                "url": res.get("href"),
            })

        res = {"ok": True, "results": formatted_results}
        _audit_event("search_internet", {"query": query, "max_results": max_results, "ok": True, "result_count": len(formatted_results)})
        return res
    except Exception as e:
        logger.exception("Error performing search")
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

    try:
        logger.info("Fetching URL: %s", url)
        with httpx.Client(follow_redirects=True, timeout=15.0) as client:
            response = client.get(url, headers=headers)
            response.raise_for_status()

        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            res = {"ok": False, "error": "URL did not return HTML content.", "content_type": content_type}
            _audit_event("fetch_webpage_content", {"url": url, "hostname": hostname, "ok": False, "content_type": content_type})
            return res

        # Parse HTML and extract text
        soup = BeautifulSoup(response.text, "html.parser")

        # Remove script and style elements from the text
        for script_or_style in soup(["script", "style", "nav", "footer", "header"]):
            script_or_style.decompose()

        # Get text and clean up whitespace
        text = soup.get_text(separator=" ")
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        clean_text = "\n".join(chunk for chunk in chunks if chunk)

        truncated = len(clean_text) > 12000
        returned_text = clean_text[:12000]

        res = {"ok": True, "url": url, "text": returned_text, "truncated": truncated}
        _audit_event("fetch_webpage_content", {"url": url, "hostname": hostname, "ok": True, "truncated": truncated})
        return res

    except httpx.HTTPStatusError as e:
        logger.exception("HTTP error fetching URL: %s", url)
        _audit_event("fetch_webpage_content", {"url": url, "hostname": hostname, "ok": False, "error": str(e)})
        return {"ok": False, "error": f"HTTP error: {str(e)}"}
    except httpx.RequestError as e:
        logger.exception("Request error fetching URL: %s", url)
        _audit_event("fetch_webpage_content", {"url": url, "hostname": hostname, "ok": False, "error": str(e)})
        return {"ok": False, "error": f"Request error: {str(e)}"}
    except Exception as e:
        logger.exception("Unexpected error fetching URL: %s", url)
        _audit_event("fetch_webpage_content", {"url": url, "hostname": hostname, "ok": False, "error": str(e)})
        return {"ok": False, "error": str(e)}

if __name__ == "__main__":
    # Run the server
    mcp.run()
