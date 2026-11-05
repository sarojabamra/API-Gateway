from typing import Optional

import httpx

_client: Optional[httpx.AsyncClient] = None


def get_http_client() -> httpx.AsyncClient:
    """Reuse one connection-pooled HTTP client for all upstream proxy calls.

    Redirects are NOT followed automatically so API7/API10 can pin-check each hop
    against private/metadata destinations before continuing.
    """
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            timeout=httpx.Timeout(10.0, connect=3.0),
            follow_redirects=False,
            limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
        )
    return _client


async def close_http_client() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
