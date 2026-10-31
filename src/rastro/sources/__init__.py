"""Public data sources Rastro reads from. None of them is the investigated domain itself."""

from rastro import __version__

# Said to every service Rastro asks, so their operators can see what is calling and where to read about it.
USER_AGENT = f"rastro-osint/{__version__} (+https://github.com/Ruby570bocadito/rastro)"
