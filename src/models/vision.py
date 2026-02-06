"""Vision model analysis utilities for CTF pages."""

import json
from typing import Any

from .ollama_client import analyze_screenshot


CTF_ANALYSIS_PROMPT = """You are analyzing a screenshot of a CTF (Capture The Flag) web challenge.

Your task is to:
1. Identify what type of web challenge this appears to be
2. Describe all interactive elements you can see (forms, buttons, links, inputs)
3. Note any hints, clues, or unusual elements visible on the page
4. Identify potential attack vectors based on what you observe

Common CTF web challenge types:
- SQL Injection (login forms, search fields)
- XSS (Cross-Site Scripting) (input fields that reflect user input)
- Authentication Bypass (login pages, admin panels)
- Command Injection (forms that might execute system commands)
- Path Traversal (file viewers, image loaders)
- File Upload (upload forms with potential bypasses)
- SSRF (forms with URL inputs)
- SSTI (Server-Side Template Injection)
- IDOR (Insecure Direct Object Reference)
- Cookie/Session manipulation

Please provide a structured analysis."""


def build_page_state_json(
    url: str,
    interactive_elements: list[dict[str, Any]] | None = None,
    cookies: list[dict[str, Any]] | None = None,
    html_hints: list[str] | None = None,
) -> str:
    """
    Build full page state as JSON for LLM context.

    Args:
        url: The current URL of the page.
        interactive_elements: List of interactive DOM elements.
        cookies: List of page cookies.
        html_hints: List of hints found in HTML source.

    Returns:
        JSON string with full page state.
    """
    elements = interactive_elements or []
    visible_elements = [e for e in elements if e.get("visible", True)]
    hidden_elements = [e for e in elements if not e.get("visible", True)]

    page_state = {
        "url": url,
        "elements": {
            "total": len(elements),
            "visible_count": len(visible_elements),
            "hidden_count": len(hidden_elements),
            "visible": [
                {
                    "selector": e.get("selector"),
                    "tag": e.get("tag"),
                    "type": e.get("type"),
                    "name": e.get("name"),
                    "text": (e.get("text") or "")[:50],
                    "placeholder": e.get("placeholder"),
                    "value": e.get("value"),
                    "role": e.get("role"),
                    "ariaLabel": e.get("ariaLabel"),
                }
                for e in visible_elements[:25]
            ],
            "hidden": [
                {
                    "selector": e.get("selector"),
                    "tag": e.get("tag"),
                    "type": e.get("type"),
                    "name": e.get("name"),
                    "text": (e.get("text") or "")[:50],
                    "value": e.get("value"),
                }
                for e in hidden_elements[:10]
            ],
        },
        "hints": (html_hints or [])[:20],
        "cookies": [
            {"name": c.get("name"), "value": c.get("value", "")}
            for c in (cookies or [])
        ] if cookies else [],
    }

    return json.dumps(page_state, indent=2)


async def analyze_ctf_page(
    screenshot_b64: str,
    url: str,
    interactive_elements: list[dict[str, Any]] | None = None,
    cookies: list[dict[str, Any]] | None = None,
    html_hints: list[str] | None = None,
) -> str:
    """
    Analyze a CTF challenge page using the vision model.

    Args:
        screenshot_b64: Base64 encoded screenshot of the page.
        url: The current URL of the page.
        interactive_elements: List of interactive DOM elements.
        cookies: List of page cookies.
        html_hints: List of hints found in HTML source.

    Returns:
        Analysis string from the vision model.
    """
    # Build context as full JSON
    context = build_page_state_json(
        url=url,
        interactive_elements=interactive_elements,
        cookies=cookies,
        html_hints=html_hints,
    )

    # Analyze with vision model
    analysis = await analyze_screenshot(
        screenshot_b64=screenshot_b64,
        prompt=CTF_ANALYSIS_PROMPT,
        context=f"Page State:\n```json\n{context}\n```",
    )

    return analysis
