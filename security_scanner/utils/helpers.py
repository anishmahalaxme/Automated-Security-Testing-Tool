"""
Utility helpers for the Automated Security Testing Software.

Includes:
- URL normalization
- host extraction
- colored CLI output helpers using colorama
"""

from __future__ import annotations

from typing import Tuple
from urllib.parse import urlparse

from colorama import Fore, Style, init as colorama_init

# Initialize colorama for Windows terminals
colorama_init(autoreset=True)

_COLOR_ENABLED: bool = True


def set_color_enabled(enabled: bool) -> None:
    """Globally enable or disable colored output."""
    global _COLOR_ENABLED
    _COLOR_ENABLED = enabled


def normalize_url(url: str) -> str:
    """
    Normalize the target URL.

    - Ensure a scheme is present (default to http).
    - Strip trailing whitespace.
    """
    url = url.strip()
    if not url:
        return url

    parsed = urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
        parsed = urlparse(url)
    # Rebuild minimal normalized form
    normalized = f"{parsed.scheme}://{parsed.netloc}"
    if parsed.path and parsed.path != "/":
        normalized += parsed.path
    return normalized


def extract_host(url: str) -> str:
    """
    Extract host (hostname) from a URL.
    """
    parsed = urlparse(normalize_url(url))
    return parsed.hostname or parsed.netloc


def _wrap_color(color: str, text: str) -> str:
    if not _COLOR_ENABLED:
        return text
    return f"{color}{text}{Style.RESET_ALL}"


def color_info(text: str) -> str:
    return _wrap_color(Fore.CYAN, text)


def color_success(text: str) -> str:
    return _wrap_color(Fore.GREEN, text)


def color_warning(text: str) -> str:
    return _wrap_color(Fore.YELLOW, text)


def color_error(text: str) -> str:
    return _wrap_color(Fore.RED, text)
