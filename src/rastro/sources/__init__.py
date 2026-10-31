"""Public data sources Rastro reads from. None of them is the investigated domain itself."""

import http.client
import urllib.error

from rastro import __version__

# What a flaky connection can raise: refused, reset or timed-out sockets (OSError, URLError included) and broken
# HTTP answers. Every client retries on these instead of stopping a long run.
NETWORK_ERRORS = (OSError, http.client.HTTPException)
# HTTP answers worth asking again: the server is busy, rate-limiting or briefly down. Any other error answer (a 404,
# a 400) will not change by retrying, so the clients give up on it at once.
RETRY_STATUS = {408, 425, 429, 500, 502, 503, 504}
MAX_WAIT = 300.0    # longest Retry-After a client honours, in seconds

# Said to every service Rastro asks, so their operators can see what is calling and where to read about it.
USER_AGENT = f"rastro-osint/{__version__} (+https://github.com/Ruby570bocadito/rastro)"


def retryable(err: BaseException) -> bool:
    """Whether asking again may help: any network failure, or an HTTP error answer from RETRY_STATUS."""
    return not isinstance(err, urllib.error.HTTPError) or err.code in RETRY_STATUS


def wait(err: BaseException, delay: float) -> float:
    """Seconds to wait before the next try: the server's Retry-After when it gives one in seconds, else `delay`."""
    if isinstance(err, urllib.error.HTTPError) and err.headers:
        after = err.headers.get("Retry-After", "")
        if after.strip().isdigit():
            return min(max(float(after), delay), MAX_WAIT)
    return delay
