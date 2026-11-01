"""The public list of phishing domains that `rastro investigate` looks for siblings in.

Phishing.Database (MIT licence) publishes the domains its contributors and feeds found still
active, one per line, about 10 MB. Rastro downloads it from GitHub only when asked
(`rastro list update`), keeps the server's ETag next to it, and the next time asks for it again
only if it changed. A download that is not a list of domains, such as an error page, never
replaces a good list.
"""

from __future__ import annotations

import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from rastro.sources import NETWORK_ERRORS, USER_AGENT, retryable, wait

URL = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt"
HOSTNAME = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)+$")
MIN_DOMAINS = 1000     # fewer than this is not the list, whatever the server says
MIN_SHARE = 0.9        # and at least this share of its lines must be domain names


@dataclass(frozen=True)
class Update:
    path: Path
    changed: bool          # False when the server said the copy on disk is current
    domains: int
    size: int              # bytes on disk


def count(text: str) -> tuple[int, int]:
    """(domain lines, lines that are neither empty nor comments) of a list."""
    lines = [s.strip().lower() for s in text.splitlines()]
    lines = [s for s in lines if s and not s.startswith("#")]
    return sum(bool(HOSTNAME.match(s)) for s in lines), len(lines)


def check(text: str) -> int:
    """The number of domains in a downloaded list, or ValueError when it is not one."""
    domains, lines = count(text)
    if domains < MIN_DOMAINS or domains < MIN_SHARE * lines:
        raise ValueError(f"the download is not a list of domains ({domains} of {lines} lines are domain names)")
    return domains


def update(path: Path | str, url: str = URL, timeout: float = 120, retries: int = 4) -> Update:
    """Download the list to `path` unless the copy there is current; RuntimeError when the server never gave it."""
    path = Path(path)
    etag_path = path.with_name(path.name + ".etag")
    headers = {"User-Agent": USER_AGENT}
    if path.exists() and etag_path.exists():
        headers["If-None-Match"] = etag_path.read_text(encoding="utf-8").strip()
    req = urllib.request.Request(url, headers=headers)
    body, etag, last_error, delay = None, None, None, 5.0
    for _ in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body, etag = resp.read(), resp.headers.get("ETag")
            break
        except urllib.error.HTTPError as err:
            if err.code == 304:                  # not modified: the copy on disk is current
                text = path.read_text(encoding="utf-8", errors="replace")
                return Update(path, False, count(text)[0], path.stat().st_size)
            last_error = err
            if not retryable(err):
                break
            time.sleep(wait(err, delay))
        except NETWORK_ERRORS as err:
            last_error = err
            time.sleep(delay)
        delay = min(delay * 2, 60)
    if body is None:
        raise RuntimeError(f"{url} did not give the list: {last_error}")
    domains = check(body.decode("utf-8", errors="replace"))
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_name(path.name + ".part")
    partial.write_bytes(body)
    os.replace(partial, path)                 # a reader never sees half a list
    if etag:
        etag_path.write_text(etag, encoding="utf-8")
    elif etag_path.exists():
        etag_path.unlink()
    return Update(path, True, domains, len(body))
