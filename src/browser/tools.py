"""LangChain tools for browser automation in CTF challenges - ReAct format."""

import re
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from langchain_core.tools import tool

from .extractors import (
    extract_interactive_elements,
    extract_html_hints,
    extract_forms,
    find_elements_by_text,
)
from .payloads import get_payloads
from ..config import get_settings
from ..utils.flag_detector import detect_flag_in_page, detect_flag
from ..utils.logger import log_action, log_observation
from ..utils.hitl import request_human_input
from ..models.vision import analyze_ctf_page

if TYPE_CHECKING:
    from .controller import BrowserController

# Global browser controller reference (set by orchestrator)
_browser: "BrowserController | None" = None


def set_browser_controller(browser: "BrowserController") -> None:
    """Set the global browser controller for tools."""
    global _browser
    _browser = browser


def get_browser() -> "BrowserController":
    """Get the global browser controller."""
    if _browser is None:
        raise RuntimeError("Browser controller not initialized")
    return _browser


# =============================================================================
# NAVIGATION TOOLS
# =============================================================================

@tool
async def navigate_to_url(url: str) -> str:
    """Navigate the browser to a specific URL.

    Args:
        url: The URL to navigate to.

    Returns:
        Status message about navigation result.
    """
    browser = get_browser()
    result = await browser.navigate(url)
    return result


@tool
async def go_back() -> str:
    """Navigate back in browser history.

    Returns:
        Status message with new URL.
    """
    browser = get_browser()
    result = await browser.go_back()
    return result


@tool
async def scroll_page(direction: str) -> str:
    """Scroll the page up or down.

    Args:
        direction: 'up' or 'down'

    Returns:
        Status message.
    """
    browser = get_browser()
    result = await browser.scroll(direction)
    return result


# =============================================================================
# PAGE INTERACTION TOOLS
# =============================================================================

@tool
async def fill_input(selector: str, value: str) -> str:
    """Fill an input field with a value and submit by pressing Enter.

    This is your MAIN exploitation tool. Use payloads from get_payload_suggestions().

    IMPORTANT:
    - The form is automatically submitted after filling
    - The OUTPUT is returned - READ IT CAREFULLY, the flag might be there!
    - If the page changes and has no inputs, it automatically navigates back

    Args:
        selector: CSS selector for the input element (from page state)
        value: The value/payload to fill (get payloads from get_payload_suggestions)

    Returns:
        The page output after submission. Check this for command results or flags!
    """
    browser = get_browser()
    original_url = browser.get_current_url()

    # Clear and fill the input
    try:
        await browser.page.fill(selector, "")
    except Exception:
        pass  # Input might not be clearable

    result = await browser.fill(selector, value)

    # Press Enter to submit
    await browser.press_key("Enter")

    # Wait for response
    await browser.page.wait_for_timeout(1500)
    try:
        await browser.page.wait_for_load_state("networkidle", timeout=5000)
    except Exception:
        pass  # Continue even if timeout

    # Get the response
    html = await browser.get_page_content()
    url = browser.get_current_url()

    # Check for flag in response
    flag = detect_flag(html)
    if flag:
        return f"FLAG FOUND: {flag}"

    # Strip HTML tags for cleaner output
    body_text = re.sub(r'<[^>]+>', ' ', html)
    body_text = ' '.join(body_text.split())

    # Check if page changed and has no input elements
    page_changed = url != original_url
    has_inputs = False
    try:
        elements = await extract_interactive_elements(browser.page)
        input_elements = [e for e in elements if e.get('tag') in ['input', 'textarea']]
        has_inputs = len(input_elements) > 0
    except Exception:
        pass

    # If page changed and has no inputs, navigate back automatically
    navigated_back = False
    if page_changed and not has_inputs:
        try:
            await browser.go_back()
            await browser.page.wait_for_timeout(500)
            navigated_back = True
        except Exception:
            pass

    # Build response with clear output indication
    if body_text.strip():
        output = f"Output: {body_text[:2000]}"  # Truncate very long outputs
    else:
        # Show raw HTML when body text is empty
        output = f"Output: (empty - raw HTML: {html[:500]})"

    if navigated_back:
        return f"{output}\n(navigated back to input page)"
    return output


@tool
async def click_element(selector: str) -> str:
    """Click an element using CSS selector.

    Args:
        selector: CSS selector for the element.
            Examples: '#submit-btn', '.login-button', 'button:has-text("Login")'

    Returns:
        Status message about click result.
    """
    browser = get_browser()
    result = await browser.click(selector)
    return result


@tool
async def execute_javascript(code: str) -> str:
    """Execute JavaScript code in the page context.

    Useful for XSS testing, extracting data, or manipulating the page.

    Args:
        code: JavaScript code to execute.

    Returns:
        String result of the JavaScript execution.
    """
    browser = get_browser()
    result = await browser.execute_js(code)
    return result


@tool
async def submit_form(form_selector: str) -> str:
    """Submit a form by clicking its submit button or pressing Enter.

    Args:
        form_selector: CSS selector for the form.

    Returns:
        Status message about form submission.
    """
    browser = get_browser()

    if not browser.page:
        return "Error: Browser not initialized"

    try:
        # Try to find and click submit button
        submit_selectors = [
            f"{form_selector} input[type='submit']",
            f"{form_selector} button[type='submit']",
            f"{form_selector} button:has-text('Submit')",
            f"{form_selector} button:has-text('Login')",
            f"{form_selector} button",
        ]

        for sel in submit_selectors:
            try:
                element = await browser.page.query_selector(sel)
                if element:
                    await element.click()
                    await browser.page.wait_for_load_state("domcontentloaded", timeout=5000)
                    log_action("Form submitted", f"Using selector: {sel}")
                    return f"Submitted. URL: {browser.get_current_url()}"
            except Exception:
                continue

        # Fallback: press Enter
        await browser.press_key("Enter")
        return f"Submitted (Enter). URL: {browser.get_current_url()}"

    except Exception as e:
        return f"Error submitting form: {e}"


# =============================================================================
# INFORMATION GATHERING TOOLS
# =============================================================================

@tool
async def get_page_state() -> str:
    """Get comprehensive page state as JSON including elements, forms, hints, cookies.

    Use this to understand the page structure and find selectors for inputs.

    Returns:
        JSON string with complete page state.
    """
    import json

    browser = get_browser()

    if not browser.page:
        return json.dumps({"error": "Browser not initialized"})

    title = await browser.page.title()
    elements = await extract_interactive_elements(browser.page)
    forms = await extract_forms(browser.page)
    hints = await extract_html_hints(browser.page)
    cookies = await browser.get_cookies()

    # Build structured response
    state = {
        "url": browser.page.url,
        "title": title,
        "elements": {
            "total": len(elements),
            "items": [
                {
                    "selector": e.get('selector'),
                    "tag": e.get('tag'),
                    "type": e.get('type'),
                    "name": e.get('name'),
                    "text": (e.get('text') or '')[:50],
                    "value": e.get('value'),
                }
                for e in elements[:20]
            ]
        },
        "forms": [
            {
                "selector": f.get('selector'),
                "method": f.get('method', 'GET'),
                "action": f.get('action'),
                "fields": f.get('fields', []),
            }
            for f in forms
        ],
        "hints": hints[:15],
        "cookies": [
            {"name": c.get('name'), "value": c.get('value', '')}
            for c in cookies
        ] if cookies else []
    }

    return json.dumps(state, indent=2)


@tool
async def check_for_flag() -> str:
    """Search the current page for CTF flag patterns.

    Searches in HTML, cookies, localStorage, console logs, and network responses.

    Returns:
        The flag if found, or a message indicating no flag was found.
    """
    browser = get_browser()

    if not browser.page:
        return "Error: Browser not initialized"

    html = await browser.get_page_content()
    cookies = await browser.get_cookies()
    local_storage = await browser.get_local_storage()
    console_logs = browser.get_console_logs()
    network = browser.get_network_traffic()

    flag = detect_flag_in_page(
        html=html,
        cookies=cookies,
        local_storage=local_storage,
        console_logs=console_logs,
        network_responses=network.get("responses", []),
    )

    if flag:
        log_observation(f"FLAG FOUND: {flag}")
        return f"FLAG FOUND: {flag}"

    return "No flag found in page content, cookies, localStorage, or network traffic."


@tool
async def get_page_source() -> str:
    """Get the full HTML source of the current page.

    Useful for finding hidden comments, scripts, or data attributes.

    Returns:
        The HTML source code (truncated if very long).
    """
    browser = get_browser()
    html = await browser.get_page_content()

    if len(html) > 10000:
        return html[:10000] + "\n... (truncated)"
    return html


@tool
async def get_cookies() -> str:
    """Get all cookies for the current page.

    Returns:
        Formatted list of cookies.
    """
    browser = get_browser()
    cookies = await browser.get_cookies()

    if not cookies:
        return "No cookies."

    return "\n".join(f"{c.get('name')}={c.get('value', '')}" for c in cookies)


@tool
async def get_local_storage() -> str:
    """Get localStorage data from the current page.

    Returns:
        Formatted localStorage key-value pairs.
    """
    browser = get_browser()
    storage = await browser.get_local_storage()

    if not storage:
        return "localStorage is empty."

    return "\n".join(f"{k}={str(v)}" for k, v in storage.items())


@tool
async def find_element_by_text(text: str) -> str:
    """Find elements containing specific text and return their selectors.

    Args:
        text: The text to search for in elements.

    Returns:
        List of elements containing the text with their selectors.
    """
    browser = get_browser()

    if not browser.page:
        return "Error: Browser not initialized"

    elements = await find_elements_by_text(browser.page, text)

    if not elements:
        return f"No elements containing '{text}'"

    return "\n".join(f"<{e.get('tag')}> {e.get('selector')}" for e in elements)


@tool
async def analyze_page_visually() -> str:
    """Take a screenshot and analyze it with the vision model.

    Use this to understand the page layout and identify challenge type.

    Returns:
        Visual analysis of the page from the VLM.
    """
    settings = get_settings()

    if not settings.vision_enabled:
        return "Vision model is disabled. Use get_page_state instead."

    browser = get_browser()

    if not browser.page:
        return "Error: Browser not initialized"

    screenshot_b64 = await browser.screenshot()
    if not screenshot_b64:
        return "Error: Could not take screenshot"

    url = browser.get_current_url()
    elements = await extract_interactive_elements(browser.page)
    cookies = await browser.get_cookies()
    hints = await extract_html_hints(browser.page)

    analysis = await analyze_ctf_page(
        screenshot_b64=screenshot_b64,
        url=url,
        interactive_elements=elements,
        cookies=cookies,
        html_hints=hints,
    )

    log_observation("Visual analysis complete")
    return analysis


# =============================================================================
# UTILITY TOOLS
# =============================================================================

@tool
async def try_sensitive_paths() -> str:
    """Try accessing common sensitive paths like robots.txt, .git, .env, etc.

    Returns:
        Results of trying to access sensitive paths.
    """
    browser = get_browser()

    if not browser.page:
        return "Error: Browser not initialized"

    base_url = browser.get_current_url()
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    paths = get_payloads("sensitive_paths")
    results = []

    for path in paths:
        if isinstance(path, tuple):
            path = path[0]

        full_url = urljoin(base, str(path))
        try:
            await browser.navigate(full_url)
            html = await browser.get_page_content()

            is_404 = "404" in html or "not found" in html.lower()
            if is_404:
                results.append(f"{path}: 404")
            else:
                flag = detect_flag(html)
                if flag:
                    return f"FLAG FOUND: {flag} at {path}"
                results.append(f"{path}: {len(html)}b")
        except Exception:
            pass

    await browser.navigate(base_url)
    return "\n".join(results) if results else "No sensitive paths found."


@tool
async def request_human_help(reason: str) -> str:
    """Request assistance from a human operator when stuck.

    Use this when you've tried multiple approaches and are unable to progress.

    Args:
        reason: Explanation of why help is needed and what has been tried.

    Returns:
        Human's guidance or suggestion.
    """
    browser = get_browser()
    url = browser.get_current_url() if browser.page else "unknown"

    context = f"Current URL: {url}\n\nProblem: {reason}"
    response = request_human_input(reason, context)
    return f"Human guidance: {response}"


# =============================================================================
# RAG TOOL - Payload Knowledge Retrieval
# =============================================================================

@tool
def get_payload_suggestions(vuln_type: str) -> str:
    """Retrieve payload suggestions for a specific vulnerability type.

    Call this tool FIRST when you identify a vulnerability type to get
    relevant detection and exploitation payloads.

    Args:
        vuln_type: The vulnerability type. Options:
            - 'ssti': Server-Side Template Injection (Jinja2/Flask)
            - 'sqli': SQL Injection
            - 'cmdi': Command Injection
            - 'lfi': Local File Inclusion
            - 'xss': Cross-Site Scripting
            - 'path_traversal': Directory Traversal

    Returns:
        Formatted payload suggestions with detection and exploitation payloads.
    """
    vuln_type = vuln_type.lower().strip()

    # Map common aliases
    type_aliases = {
        "sql": "sqli",
        "sql_injection": "sqli",
        "command": "cmdi",
        "cmd": "cmdi",
        "command_injection": "cmdi",
        "template": "ssti",
        "template_injection": "ssti",
        "traversal": "path_traversal",
        "directory_traversal": "path_traversal",
        "file_inclusion": "lfi",
    }
    vuln_type = type_aliases.get(vuln_type, vuln_type)

    # Get payloads from the knowledge base
    payloads = get_payloads(vuln_type)

    if not payloads:
        available = ["ssti", "sqli", "cmdi", "lfi", "xss", "path_traversal"]
        return f"Unknown vulnerability type: '{vuln_type}'. Available types: {', '.join(available)}"

    # Format payloads by category
    result_lines = [f"## Payloads for {vuln_type.upper()}\n"]

    if vuln_type == "ssti":
        # SSTI has detection and exploitation phases
        result_lines.append("### Detection Payloads (test these first)")
        detection = [p for p in payloads if "7*7" in str(p) or "config" in str(p).lower()][:5]
        for p in detection:
            result_lines.append(f"  - {p}")

        result_lines.append("\n### Exploitation Payloads (after confirming SSTI)")
        # Get exploration payloads
        explore_payloads = get_payloads("ssti_explore")
        for p in explore_payloads[:4]:
            result_lines.append(f"  - {p}")

        result_lines.append("\n### Usage Tips")
        result_lines.append("  1. Test with {{7*7}} - if output shows 49, SSTI confirmed")
        result_lines.append("  2. Use ls payload to list directories")
        result_lines.append("  3. Replace 'ls -la /' with 'cat /path/to/flag' to read files")
        result_lines.append("  4. Common flag paths: /flag.txt, /flag, /home/*/flag.txt")

    elif vuln_type == "sqli":
        result_lines.append("### Auth Bypass Payloads")
        bypass_payloads = get_payloads("sqli_auth_bypass")
        for p in bypass_payloads[:5]:
            if isinstance(p, tuple):
                result_lines.append(f"  - Username: {p[0]}, Password: {p[1]}")
            else:
                result_lines.append(f"  - {p}")

        result_lines.append("\n### Detection Payloads")
        for p in payloads[:8]:
            result_lines.append(f"  - {p}")

        result_lines.append("\n### Usage Tips")
        result_lines.append("  1. Try auth bypass payloads on login forms")
        result_lines.append("  2. Use UNION SELECT to extract data")
        result_lines.append("  3. Check for error messages revealing DB structure")

    elif vuln_type == "cmdi":
        result_lines.append("### Command Injection Payloads")
        for p in payloads[:12]:
            result_lines.append(f"  - {p}")

        result_lines.append("\n### Usage Tips")
        result_lines.append("  1. Try ; | & operators to chain commands")
        result_lines.append("  2. Use 'ls -la /' to list directories")
        result_lines.append("  3. Use 'cat /flag.txt' to read flag")

    elif vuln_type == "lfi":
        result_lines.append("### LFI Payloads")
        for p in payloads[:10]:
            result_lines.append(f"  - {p}")

        result_lines.append("\n### Usage Tips")
        result_lines.append("  1. Try php:// wrappers for PHP apps")
        result_lines.append("  2. Use base64 encoding to read PHP files")
        result_lines.append("  3. Check /etc/passwd to confirm LFI works")

    elif vuln_type == "path_traversal":
        result_lines.append("### Path Traversal Payloads")
        for p in payloads[:10]:
            result_lines.append(f"  - {p}")

        result_lines.append("\n### Usage Tips")
        result_lines.append("  1. Try different encoding bypasses")
        result_lines.append("  2. Check /etc/passwd first to confirm")
        result_lines.append("  3. Common flag paths: /flag.txt, /home/user/flag.txt")

    elif vuln_type == "xss":
        result_lines.append("### XSS Payloads")
        for p in payloads[:10]:
            result_lines.append(f"  - {p}")

        result_lines.append("\n### Usage Tips")
        result_lines.append("  1. Check if input is reflected in response")
        result_lines.append("  2. Try different event handlers")
        result_lines.append("  3. Look for cookie stealing opportunities")

    else:
        # Generic format for other types
        result_lines.append("### Payloads")
        for p in payloads[:15]:
            if isinstance(p, tuple):
                result_lines.append(f"  - {p[0]} / {p[1]}")
            else:
                result_lines.append(f"  - {p}")

    return "\n".join(result_lines)


# =============================================================================
# TOOL COLLECTIONS
# =============================================================================

# ReAct tools - streamlined set for the ReAct pattern
# The agent retrieves payloads via RAG and calls fill_input
REACT_TOOLS = [
    # Navigation
    navigate_to_url,
    go_back,
    scroll_page,
    # Page interaction (main tools)
    fill_input,
    click_element,
    execute_javascript,
    submit_form,
    # Information gathering
    get_page_state,
    check_for_flag,
    get_page_source,
    get_cookies,
    get_local_storage,
    find_element_by_text,
    # RAG - Payload knowledge retrieval
    get_payload_suggestions,
    # Utility
    try_sensitive_paths,
    request_human_help,
    # Visual (optional)
    analyze_page_visually,
]

# Legacy exports for backwards compatibility
ALL_TOOLS = REACT_TOOLS
NAVIGATION_TOOLS = [navigate_to_url, go_back]
