"""Make console output unable to crash a scan, whatever the terminal or pipe can display.

Reports use symbols (check marks, boxes, emoji). When output is piped or redirected, the stream's
encoding is whatever the platform chose (on Windows usually a legacy code page such as cp1252), and
printing a character it cannot encode used to abort the scan with UnicodeEncodeError.

Instead of forcing UTF-8 (which Windows PowerShell 5.1 then misreads as garbage), we keep each
stream's own encoding and install an error handler that replaces ONLY the characters that stream
cannot encode with readable ASCII (check mark -> "OK"). UTF-8 streams are untouched, except that
lone surrogates (file names containing invalid bytes) are replaced instead of raising.
"""
from __future__ import annotations

import codecs
import sys

HANDLER_NAME = "aysal-ascii"

_REPLACEMENTS: dict[str, str] = {
    "\u2713": "OK", "\u2714": "OK", "\u2705": "[OK]",
    "\u2717": "X", "\u2718": "X", "\u274c": "[X]",
    "\u26a0": "!", "\ufe0f": "",
    "\u2192": "->", "\u2022": "*", "\u2026": "...", "\u2014": "-", "\u2013": "-", "\u00b7": "*",
    "\U0001f534": "", "\U0001f7e0": "", "\U0001f7e1": "", "\U0001f535": "", "\u26aa": "",
}


def to_ascii(text: str) -> str:
    """Readable ASCII for any text (known symbols mapped, everything else '?')."""
    return "".join(_REPLACEMENTS.get(ch, ch if ord(ch) < 128 else "?") for ch in text)


def _handler(exc: UnicodeError):
    if isinstance(exc, UnicodeEncodeError):
        return to_ascii(exc.object[exc.start:exc.end]), exc.end
    raise exc


def install() -> None:
    """Register the handler and apply it to stdout and stderr. Safe to call repeatedly."""
    try:
        codecs.lookup_error(HANDLER_NAME)
    except LookupError:
        codecs.register_error(HANDLER_NAME, _handler)
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors=HANDLER_NAME)
        except (ValueError, OSError):
            pass
