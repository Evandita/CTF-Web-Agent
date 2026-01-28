"""Browser module containing Playwright controller and tools."""

from .controller import BrowserController
from .extractors import (
    extract_interactive_elements,
    extract_html_hints,
    extract_forms,
    extract_links,
)
from .payloads import get_payloads, get_all_payload_types, PAYLOADS

__all__ = [
    "BrowserController",
    "extract_interactive_elements",
    "extract_html_hints",
    "extract_forms",
    "extract_links",
    "get_payloads",
    "get_all_payload_types",
    "PAYLOADS",
]
