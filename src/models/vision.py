"""Vision model analysis utilities for CTF pages."""

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


def format_elements(elements: list[dict[str, Any]]) -> str:
    """
    Format DOM elements for inclusion in the prompt.

    Args:
        elements: List of element dictionaries from DOM extraction.

    Returns:
        Formatted string describing the elements.
    """
    if not elements:
        return "No interactive elements found."

    visible = [e for e in elements if e.get("is_visible", True)]
    hidden = [e for e in elements if not e.get("is_visible", True)]

    lines = []

    # Format visible elements
    if visible:
        lines.append(f"Visible interactive elements ({len(visible)}):")
        for i, elem in enumerate(visible, 1):
            tag = elem.get("tag", "unknown")
            elem_type = elem.get("type", "")
            elem_id = elem.get("id", "")
            elem_class = elem.get("class", "")
            text = elem.get("text", "")[:50]
            selector = elem.get("selector", "")

            desc = f"{i}. <{tag}>"
            if elem_type:
                desc += f" type='{elem_type}'"
            if elem_id:
                desc += f" id='{elem_id}'"
            if elem_class:
                desc += f" class='{elem_class}'"
            if text:
                desc += f" text='{text}'"
            if selector:
                desc += f"\n   Selector: {selector}"

            lines.append(desc)

    # Format hidden elements (important for CTF)
    if hidden:
        lines.append(f"\nHidden elements ({len(hidden)}) - may contain flags or hints:")
        for i, elem in enumerate(hidden, 1):
            tag = elem.get("tag", "unknown")
            elem_type = elem.get("type", "")
            elem_id = elem.get("id", "")
            text = elem.get("text", "")[:50]
            value = elem.get("value", "")[:50]
            selector = elem.get("selector", "")

            desc = f"{i}. <{tag}>"
            if elem_type:
                desc += f" type='{elem_type}'"
            if elem_id:
                desc += f" id='{elem_id}'"
            if text:
                desc += f" text='{text}'"
            if value:
                desc += f" value='{value}'"
            if selector:
                desc += f"\n   Selector: {selector}"

            lines.append(desc)

    return "\n".join(lines)


def format_cookies(cookies: list[dict[str, Any]]) -> str:
    """
    Format cookies for inclusion in the prompt.

    Args:
        cookies: List of cookie dictionaries.

    Returns:
        Formatted string describing the cookies.
    """
    if not cookies:
        return "No cookies found."

    lines = ["Cookies:"]
    for cookie in cookies:
        name = cookie.get("name", "unknown")
        value = cookie.get("value", "")
        domain = cookie.get("domain", "")
        # Truncate long values
        if len(value) > 50:
            value = value[:50] + "..."
        lines.append(f"  - {name}={value} (domain: {domain})")

    return "\n".join(lines)


def format_html_hints(hints: list[str]) -> str:
    """
    Format HTML hints for inclusion in the prompt.

    Args:
        hints: List of hint strings found in HTML.

    Returns:
        Formatted string describing the hints.
    """
    if not hints:
        return "No HTML hints found."

    lines = ["HTML hints/comments found:"]
    for hint in hints:
        # Truncate long hints
        if len(hint) > 200:
            hint = hint[:200] + "..."
        lines.append(f"  - {hint}")

    return "\n".join(lines)


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
    # Build context from available information
    context_parts = [
        f"Current URL: {url}",
        "",
    ]

    if interactive_elements:
        context_parts.append(format_elements(interactive_elements))
        context_parts.append("")

    if cookies:
        context_parts.append(format_cookies(cookies))
        context_parts.append("")

    if html_hints:
        context_parts.append(format_html_hints(html_hints))
        context_parts.append("")

    context = "\n".join(context_parts)

    # Analyze with vision model
    analysis = await analyze_screenshot(
        screenshot_b64=screenshot_b64,
        prompt=CTF_ANALYSIS_PROMPT,
        context=context,
    )

    return analysis


def build_analysis_summary(
    visual_analysis: str,
    elements: list[dict[str, Any]],
    cookies: list[dict[str, Any]],
    hints: list[str],
) -> str:
    """
    Build a comprehensive analysis summary.

    Args:
        visual_analysis: Analysis from the vision model.
        elements: Interactive elements from DOM.
        cookies: Page cookies.
        hints: HTML hints.

    Returns:
        Combined analysis summary.
    """
    sections = []

    sections.append("## Visual Analysis")
    sections.append(visual_analysis)

    sections.append("\n## DOM Elements")
    sections.append(format_elements(elements))

    sections.append("\n## Cookies")
    sections.append(format_cookies(cookies))

    sections.append("\n## HTML Hints")
    sections.append(format_html_hints(hints))

    return "\n".join(sections)
