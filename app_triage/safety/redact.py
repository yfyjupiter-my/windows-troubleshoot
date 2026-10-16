"""Redaction of the local user name before any text leaves the machine."""
import re

# Characters that may legitimately follow a user-profile folder name in a path
# or command line. Anything else means the folder name is longer (tester2).
_END = r"""(?=[\\/]|$|[\s"'<>|:;,)\]])"""


def redact(text: str, username: str) -> str:
    """Replace ``\\Users\\<username>`` (either slash style, any case) with ``\\Users\\%USER%``."""
    if not username:
        return text
    pattern = re.compile(r"[\\/]+Users[\\/]+" + re.escape(username) + _END, re.IGNORECASE)
    return pattern.sub(lambda _m: r"\Users\%USER%", text)
