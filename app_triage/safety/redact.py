"""Redaction of the local user name before any text leaves the machine."""
import re


def redact(text: str, username: str) -> str:
    """Replace the user-profile folder name in ``\\Users\\<username>`` with ``%USER%``.

    Matching is case-insensitive and accepts either slash style. Only the name itself
    is replaced; the surrounding separators are kept exactly as written, so
    JSON-escaped paths (``C:\\\\Users\\\\name``) stay valid JSON. A longer name that merely
    starts with the username (``tester2``) is left alone, but ``tester.PC`` or
    ``tester-PC`` are still redacted.
    """
    if not username:
        return text
    pattern = re.compile(
        r"([\\/]Users[\\/]+)" + re.escape(username) + r"(?!\w)", re.IGNORECASE
    )
    return pattern.sub(lambda m: m.group(1) + "%USER%", text)
