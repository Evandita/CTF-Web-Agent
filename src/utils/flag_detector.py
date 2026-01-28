"""Flag detection utilities for CTF challenges."""

import re
from typing import Any

from ..config import get_settings


def detect_flag(content: str) -> str | None:
    """
    Search a string for CTF flag patterns.

    Args:
        content: The string to search for flags.

    Returns:
        The first flag found, or None if no flag is found.
    """
    if not content:
        return None

    settings = get_settings()

    for pattern in settings.flag_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return match.group(0)

    return None


def detect_flag_in_page(
    html: str = "",
    cookies: list[dict[str, Any]] | None = None,
    local_storage: dict[str, Any] | None = None,
    console_logs: list[str] | None = None,
    network_responses: list[dict[str, Any]] | None = None,
) -> str | None:
    """
    Comprehensive search for flags across all data sources.

    Args:
        html: The HTML source of the page.
        cookies: List of cookie dictionaries.
        local_storage: Dictionary of localStorage key-value pairs.
        console_logs: List of console log messages.
        network_responses: List of network response data.

    Returns:
        The first flag found, or None if no flag is found.
    """
    # Search in HTML
    if html:
        flag = detect_flag(html)
        if flag:
            return flag

    # Search in cookies
    if cookies:
        for cookie in cookies:
            # Check cookie name
            flag = detect_flag(cookie.get("name", ""))
            if flag:
                return flag
            # Check cookie value
            flag = detect_flag(str(cookie.get("value", "")))
            if flag:
                return flag

    # Search in localStorage
    if local_storage:
        for key, value in local_storage.items():
            flag = detect_flag(key)
            if flag:
                return flag
            flag = detect_flag(str(value))
            if flag:
                return flag

    # Search in console logs
    if console_logs:
        for log in console_logs:
            flag = detect_flag(log)
            if flag:
                return flag

    # Search in network responses
    if network_responses:
        for response in network_responses:
            # Check URL
            flag = detect_flag(response.get("url", ""))
            if flag:
                return flag
            # Check response body
            flag = detect_flag(str(response.get("body", "")))
            if flag:
                return flag
            # Check headers
            headers = response.get("headers", {})
            for key, value in headers.items():
                flag = detect_flag(f"{key}: {value}")
                if flag:
                    return flag

    return None


def search_flag_in_text(text: str) -> list[str]:
    """
    Find all flags in a text string.

    Args:
        text: The text to search.

    Returns:
        List of all flags found.
    """
    if not text:
        return []

    settings = get_settings()
    flags = []

    for pattern in settings.flag_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        flags.extend(matches)

    return list(set(flags))  # Remove duplicates
