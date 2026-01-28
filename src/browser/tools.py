"""LangChain tools for browser automation in CTF challenges."""

from typing import TYPE_CHECKING

from langchain_core.tools import tool

from .extractors import (
    extract_interactive_elements,
    extract_html_hints,
    extract_forms,
    extract_links,
    find_elements_by_text,
)
from .payloads import get_payloads
from ..utils.flag_detector import detect_flag_in_page
from ..utils.logger import log_action, log_observation, log_error
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
async def click_element(selector: str) -> str:
    """Click an element using CSS selector or text content.

    Args:
        selector: CSS selector or Playwright text selector.
            Examples: '#submit-btn', '.login-button', 'button:has-text("Login")'

    Returns:
        Status message about click result.
    """
    browser = get_browser()
    result = await browser.click(selector)
    return result


@tool
async def fill_input(selector: str, value: str) -> str:
    """Fill an input field with a value.

    Use for text inputs, textareas, password fields, and other form fields.

    Args:
        selector: CSS selector for the input element.
        value: The value to fill into the input.

    Returns:
        Status message about fill result.
    """
    browser = get_browser()
    result = await browser.fill(selector, value)
    return result


@tool
async def get_page_state() -> str:
    """Get comprehensive page state including URL, title, forms, and elements.

    Returns:
        Formatted string with page state information.
    """
    browser = get_browser()

    if not browser.page:
        return "Error: Browser not initialized"

    url = browser.get_current_url()
    title = await browser.page.title()
    elements = await extract_interactive_elements(browser.page)
    forms = await extract_forms(browser.page)
    hints = await extract_html_hints(browser.page)
    cookies = await browser.get_cookies()

    # Format output
    lines = [
        f"URL: {url}",
        f"Title: {title}",
        f"\nForms ({len(forms)}):",
    ]

    for form in forms:
        lines.append(f"  - {form.get('selector')}: {form.get('method')} to {form.get('action')}")
        for field in form.get('fields', []):
            lines.append(f"    - {field.get('tag')} [{field.get('type')}]: name={field.get('name')}")

    lines.append(f"\nInteractive Elements ({len(elements)}):")
    for elem in elements[:15]:  # Limit output
        tag = elem.get('tag')
        selector = elem.get('selector')
        text = elem.get('text', '')[:30]
        lines.append(f"  - <{tag}> {selector} : {text}")

    if len(elements) > 15:
        lines.append(f"  ... and {len(elements) - 15} more elements")

    lines.append(f"\nHints ({len(hints)}):")
    for hint in hints[:10]:
        lines.append(f"  - {hint[:100]}")

    lines.append(f"\nCookies ({len(cookies)}):")
    for cookie in cookies:
        lines.append(f"  - {cookie.get('name')}={cookie.get('value', '')[:30]}")

    return "\n".join(lines)


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
async def check_for_flag() -> str:
    """Search the current page for CTF flag patterns.

    Searches in HTML, cookies, localStorage, console logs, and network responses.

    Returns:
        The flag if found, or a message indicating no flag was found.
    """
    browser = get_browser()

    if not browser.page:
        return "Error: Browser not initialized"

    # Gather all data sources
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

    return "No flag found in current page state."


@tool
async def analyze_page_visually() -> str:
    """Take a screenshot and analyze it with the vision model.

    Use this to understand the page layout and identify challenge type.

    Returns:
        Visual analysis of the page from the VLM.
    """
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

    log_observation(f"Visual analysis complete")
    return analysis


@tool
async def list_interactive_elements() -> str:
    """List all interactive elements on the page with their selectors.

    Returns:
        Formatted list of interactive elements.
    """
    browser = get_browser()

    if not browser.page:
        return "Error: Browser not initialized"

    elements = await extract_interactive_elements(browser.page)

    lines = [f"Found {len(elements)} interactive elements:\n"]
    for i, elem in enumerate(elements, 1):
        tag = elem.get("tag")
        selector = elem.get("selector")
        elem_type = elem.get("type", "")
        text = elem.get("text", "")[:40]
        name = elem.get("name", "")

        line = f"{i}. <{tag}>"
        if elem_type:
            line += f" type='{elem_type}'"
        if name:
            line += f" name='{name}'"
        line += f"\n   Selector: {selector}"
        if text:
            line += f"\n   Text: '{text}'"
        lines.append(line)

    return "\n".join(lines)


@tool
async def get_network_traffic() -> str:
    """Get captured network requests and responses since last navigation.

    Useful for finding flags or hints in API responses.

    Returns:
        Formatted network traffic information.
    """
    browser = get_browser()
    traffic = browser.get_network_traffic()

    lines = [
        f"Network Requests ({len(traffic['requests'])}):",
    ]

    for req in traffic["requests"][-20:]:  # Last 20
        lines.append(f"  {req.get('method')} {req.get('url')[:80]}")

    lines.append(f"\nNetwork Responses ({len(traffic['responses'])}):")
    for resp in traffic["responses"][-20:]:
        body_preview = resp.get("body", "")[:100]
        lines.append(f"  [{resp.get('status')}] {resp.get('url')[:60]}")
        if body_preview:
            lines.append(f"       Body: {body_preview}...")

    return "\n".join(lines)


@tool
async def get_page_source() -> str:
    """Get the full HTML source of the current page.

    Returns:
        The HTML source code, truncated if very long.
    """
    browser = get_browser()
    html = await browser.get_page_content()

    # Truncate if too long
    if len(html) > 10000:
        return html[:10000] + "\n\n... [truncated, total length: " + str(len(html)) + "]"

    return html


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
        return f"No elements found containing text: '{text}'"

    lines = [f"Elements containing '{text}':\n"]
    for elem in elements:
        lines.append(f"  <{elem.get('tag')}> {elem.get('selector')}")
        lines.append(f"    Text: {elem.get('text', '')[:60]}")

    return "\n".join(lines)


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
            f"{form_selector} button:has-text('Sign in')",
            f"{form_selector} button",
        ]

        for sel in submit_selectors:
            try:
                element = await browser.page.query_selector(sel)
                if element:
                    await element.click()
                    await browser.page.wait_for_load_state("domcontentloaded", timeout=5000)
                    log_action("Form submitted", f"Using selector: {sel}")
                    return f"Form submitted using {sel}. Current URL: {browser.get_current_url()}"
            except Exception:
                continue

        # Fallback: press Enter on the last input
        result = await browser.press_key("Enter")
        return f"Pressed Enter to submit form. {result}"

    except Exception as e:
        return f"Error submitting form: {e}"


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


@tool
async def try_common_payloads(input_selector: str, payload_type: str) -> str:
    """Try common CTF payloads on an input field.

    Args:
        input_selector: CSS selector for the input field to test.
        payload_type: Type of payload: 'sqli', 'xss', 'cmdi', 'path_traversal', 'ssti'

    Returns:
        Results of testing each payload.
    """
    browser = get_browser()

    if not browser.page:
        return "Error: Browser not initialized"

    payloads = get_payloads(payload_type)
    if not payloads:
        return f"Unknown payload type: {payload_type}. Available: sqli, xss, cmdi, path_traversal, ssti"

    results = [f"Testing {payload_type} payloads on {input_selector}:\n"]

    # Test first 5 payloads
    for payload in payloads[:5]:
        if isinstance(payload, tuple):
            payload = payload[0]  # Use first value if tuple

        try:
            # Clear and fill input
            await browser.page.fill(input_selector, "")
            await browser.fill(input_selector, str(payload))

            # Try to submit (press Enter)
            await browser.press_key("Enter")
            await browser.page.wait_for_timeout(1000)

            # Check for flag
            html = await browser.get_page_content()
            from ..utils.flag_detector import detect_flag
            flag = detect_flag(html)

            url = browser.get_current_url()
            result = f"  Payload: {str(payload)[:50]}"
            result += f"\n  URL after: {url}"

            if flag:
                result += f"\n  FLAG FOUND: {flag}"
                results.append(result)
                return "\n".join(results) + f"\n\n*** FLAG FOUND: {flag} ***"

            results.append(result)

            # Go back for next payload
            await browser.go_back()
            await browser.page.wait_for_timeout(500)

        except Exception as e:
            results.append(f"  Payload {str(payload)[:30]}... Error: {e}")

    return "\n".join(results)


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
async def wait_for_element(selector: str, timeout: int = 5) -> str:
    """Wait for an element to appear on the page.

    Args:
        selector: CSS selector for the element.
        timeout: Maximum time to wait in seconds.

    Returns:
        Status message about whether element was found.
    """
    browser = get_browser()
    result = await browser.wait_for_selector(selector, timeout)
    return result


@tool
async def get_cookies() -> str:
    """Get all cookies for the current page.

    Returns:
        Formatted list of cookies.
    """
    browser = get_browser()
    cookies = await browser.get_cookies()

    lines = [f"Cookies ({len(cookies)}):\n"]
    for cookie in cookies:
        lines.append(f"  {cookie.get('name')}:")
        lines.append(f"    Value: {cookie.get('value', '')}")
        lines.append(f"    Domain: {cookie.get('domain', '')}")
        lines.append(f"    Path: {cookie.get('path', '/')}")
        lines.append(f"    HttpOnly: {cookie.get('httpOnly', False)}")
        lines.append(f"    Secure: {cookie.get('secure', False)}")

    return "\n".join(lines)


@tool
async def get_local_storage() -> str:
    """Get localStorage data from the current page.

    Returns:
        Formatted localStorage key-value pairs.
    """
    browser = get_browser()
    storage = await browser.get_local_storage()

    if not storage:
        return "localStorage is empty"

    lines = [f"localStorage ({len(storage)} items):\n"]
    for key, value in storage.items():
        value_str = str(value)[:100]
        lines.append(f"  {key}: {value_str}")

    return "\n".join(lines)


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
    # Get base domain
    from urllib.parse import urljoin, urlparse
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    paths = get_payloads("sensitive_paths")
    results = ["Checking sensitive paths:\n"]

    for path in paths[:10]:  # Check first 10
        if isinstance(path, tuple):
            path = path[0]

        full_url = urljoin(base, str(path))
        try:
            await browser.navigate(full_url)
            html = await browser.get_page_content()

            # Check for 404 indicators
            is_404 = "404" in html[:500] or "not found" in html.lower()[:500]

            result = f"  {path}: "
            if is_404:
                result += "404 Not Found"
            else:
                # Check for flag
                from ..utils.flag_detector import detect_flag
                flag = detect_flag(html)
                if flag:
                    result += f"FLAG FOUND: {flag}"
                    results.append(result)
                    return "\n".join(results) + f"\n\n*** FLAG: {flag} ***"
                else:
                    result += f"Found content ({len(html)} bytes)"

            results.append(result)

        except Exception as e:
            results.append(f"  {path}: Error - {e}")

    # Navigate back to original
    await browser.navigate(base_url)

    return "\n".join(results)


@tool
async def type_slowly(selector: str, text: str) -> str:
    """Type text character by character into an input field.

    Useful when fill() doesn't trigger expected events.

    Args:
        selector: CSS selector for the input.
        text: Text to type.

    Returns:
        Status message.
    """
    browser = get_browser()
    result = await browser.type_text(selector, text)
    return result


# Collect all tools
ALL_TOOLS = [
    navigate_to_url,
    click_element,
    fill_input,
    get_page_state,
    execute_javascript,
    check_for_flag,
    analyze_page_visually,
    list_interactive_elements,
    get_network_traffic,
    get_page_source,
    find_element_by_text,
    submit_form,
    request_human_help,
    try_common_payloads,
    scroll_page,
    go_back,
    wait_for_element,
    get_cookies,
    get_local_storage,
    try_sensitive_paths,
    type_slowly,
]
