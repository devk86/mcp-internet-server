# MCP Internet Server

Small MCP server exposing two tools for internet access:

- `search_internet(query, max_results=5)` — perform a web search and return structured results.
- `fetch_webpage_content(url)` — fetch and extract text from an HTML page with SSRF protections.

Features
- Structured (dict) responses for easier downstream processing.
- SSRF protections: optional `ALLOWED_DOMAINS` allowlist and private IP blocking.
- JSON-line audit logging (path configurable via `AUDIT_LOG_PATH`).
- Unit tests using `pytest`.

Quick start

1. Create and activate a virtualenv (recommended):

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Unix/macOS
source .venv/bin/activate
```

2. Install dependencies:

```bash
python -m pip install -r requirements.txt
```

3. Run a quick smoke test:

```bash
python run_test.py
```

4. Run unit tests:

```bash
python -m pytest -q
```

5. Run test coverage:

```bash
python -m pytest --cov=server --cov-report=term-missing
```

6. MCP json to use in inference engine
```json
{
  "mcpServers": {
    "internet_assistant": {
      "command": "PATH TO YOUR PYTHON EXECUTABLE",
      "args": [
        "PATH TO YOUR server.py"
      ]
    }
  }
}
```
Configuration

- `ALLOWED_DOMAINS`: optional comma-separated list of domains that `fetch_webpage_content` is allowed to access. If unset, fetching is allowed for any public hostname (subject to IP checks).
- `AUDIT_LOG_PATH`: path to write newline-delimited JSON audit events (default: `audit.log`).
- `METRICS_PORT`: port to expose Prometheus metrics via HTTP. Set to `0` or unset to disable metrics export.

Notes

- The project prefers the `ddgs` package for search; `duckduckgo_search` fallback is supported.
- Audit log rotation, remote logging, or more advanced rate-limiting are not included but recommended for production deployments.

Files of interest
- `server.py` — main MCP tools implementation
- `run_test.py` — smoke tests
- `tests/test_server.py` — pytest unit tests
- `requirements.txt` — dependencies

License: MIT
