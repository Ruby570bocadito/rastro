"""Public data sources Rastro reads from. None of them is the investigated domain itself."""

import http.client

from rastro import __version__

# What a flaky connection can raise: refused, reset or timed-out sockets (OSError, URLError included) and broken
# HTTP answers. Every client retries on these instead of stopping a long run.
NETWORK_ERRORS = (OSError, http.client.HTTPException)

# Said to every service Rastro asks, so their operators can see what is calling and where to read about it.
USER_AGENT = f"rastro-osint/{__version__} (+https://github.com/Ruby570bocadito/rastro)"
