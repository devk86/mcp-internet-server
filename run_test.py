"""
run_test.py
-----------
Small, self-contained smoke tests for the `server` tools. This script
imports `search_internet` and `fetch_webpage_content` from `server.py`
and runs a couple of example calls, printing the results. It is
intended for quick local verification and is tolerant of network
errors and missing dependencies.

Usage:
    python run_test.py
"""

from typing import Any

try:
    from server import search_internet, fetch_webpage_content
except Exception as e:
    print("Failed to import server module:", e)
    raise


def safe_call(func, *args, **kwargs) -> Any:
    """Call `func` safely, returning a dict with an `_error` key on exception.

    This helper is used to keep the smoke-test output readable even when
    network calls fail or unexpected exceptions occur.
    """
    try:
        return func(*args, **kwargs)
    except Exception as e:
        return {"_error": str(e)}


def main():
    print("Running basic tests for server tools...")

    print("\n1) Test search_internet()")
    res = safe_call(search_internet, "python programming", max_results=1)
    print("Result type:", type(res))
    print("Result content:", res)

    print("\n2) Test fetch_webpage_content()")
    res2 = safe_call(fetch_webpage_content, "https://example.com")
    print("Result type:", type(res2))
    print("Result keys/summary:", list(res2.keys()) if isinstance(res2, dict) else str(res2))
    if isinstance(res2, dict) and res2.get("ok"):
        text = res2.get("text", "")
        print("Fetched text length:", len(text))
        print("Truncated:", res2.get("truncated"))

    print("\nTests complete.")


if __name__ == "__main__":
    main()
