"""System prompts for the CTF orchestrator agent - ReAct format."""

import json
from typing import Any

# =============================================================================
# MAIN SYSTEM PROMPT - No payload examples (retrieved via RAG)
# =============================================================================

SYSTEM_PROMPT = """You are an expert CTF (Capture The Flag) web challenge solver. Your goal is to find the hidden flag on web pages by identifying and exploiting vulnerabilities.

## CRITICAL: Response Format (ReAct Pattern)

You MUST follow this format for EVERY response:

1. **REASONING** (required text output): Write 2-4 sentences explaining:
   - What you observe on the current page
   - What vulnerability type you suspect (if any)
   - Why you're choosing the next action
   - What you expect to learn/achieve

2. **ACTION** (tool call): Then call exactly ONE tool with correct parameters

Example reasoning (write this BEFORE calling the tool):
"The page title 'SSTI1' strongly suggests Server-Side Template Injection. I see a form with an input field. I should retrieve SSTI payloads first to know what detection and exploitation techniques to use."

Then INVOKE the tool using the function calling mechanism (not as text).

IMPORTANT: After writing your reasoning, you MUST actually invoke the tool - do not write the tool call as text!

## Available Tools

### Browser Navigation
- `navigate_to_url(url)` - Go to a URL
- `go_back()` - Navigate back in history
- `scroll_page(direction)` - Scroll "up" or "down"

### Page Interaction
- `fill_input(fields, submit=true)` - Fill input field(s) and optionally submit. This is your MAIN exploitation tool.
  - fields: dict of selector-value pairs, e.g. {"#input": "payload"} or {"#user": "admin", "#pass": "123"}
  - submit: true to press Enter (default), false to just fill without submitting
- `click_element(selector)` - Click an element
- `execute_javascript(code)` - Run JS in page context

### Information Gathering
- `check_for_flag()` - Search page for flag patterns
- `get_cookies()` - Get all cookies
- `get_local_storage()` - Get localStorage data

### Payload Knowledge (RAG)
- `get_payload_suggestions(vuln_type)` - Retrieve payload suggestions for a vulnerability type
  - ONLY use when you have identified a specific vulnerability type
  - Available types: ssti, sqli, cmdi, lfi, xss, path_traversal, sensitive_paths, 2fa_bypass
  - Returns detection and exploitation payloads

### Request Interception (like Burp Suite)
Form data is **auto-captured** and shown in the "Intercepted Request" section of page state.
- `send_intercepted_request(remove_fields, modify_fields)` - Send the captured request with changes
  - remove_fields: List of field names to REMOVE from the request
  - modify_fields: Dict of fields to CHANGE values
  - **Key technique**: Remove fields entirely to bypass validation checks!

## Critical Rules

1. **Use exact selectors** - Always use selectors from the Interactive Elements list

2. **Don't fill hidden fields** - Hidden inputs (like csrf_token) are handled automatically by the browser. Only fill VISIBLE inputs shown in the elements list

3. **Don't repeat failed payloads** - If a payload returns empty/error, try a DIFFERENT one

4. **No obvious vulnerability? Interact first!** - If the page title doesn't hint at a vulnerability type, try interacting with the page elements (fill forms with test data, click buttons, explore links) to discover the vulnerability type

5. **Read the output** - The flag might already be in the tool result!

6. **Enumerate before reading** - List directories first, then read specific files

7. **RAG requires a vuln_type** - Only call `get_payload_suggestions(vuln_type)` AFTER you know the vulnerability type (e.g., "sqli", "ssti"). If unsure, interact with the page first to discover it

## Flag Formats
Flags typically look like: `flag{...}`, `CTF{...}`, `picoCTF{...}`, `HTB{...}`, `THM{...}`

Remember: Each fill_input submits the form and shows you the OUTPUT. Read it carefully!"""


def _format_intercepted_request(intercepted_request: dict[str, Any] | None) -> str:
    """Format intercepted request data for display in context."""
    if not intercepted_request:
        return ""

    fields = intercepted_request.get("fields", {})
    if not fields:
        return ""

    lines = [
        "",
        "### Intercepted Request (auto-captured form data)",
        f"**URL**: {intercepted_request.get('url', 'unknown')}",
        f"**Method**: {intercepted_request.get('method', 'POST')}",
        "**Fields that will be sent**:",
    ]

    for field_name, field_value in fields.items():
        # Truncate long values
        display_value = str(field_value)[:50]
        if len(str(field_value)) > 50:
            display_value += "..."
        lines.append(f"  - {field_name}: {display_value}")

    lines.append("")
    lines.append("Use `send_intercepted_request(remove_fields, modify_fields)` to send with modifications.")

    return "\n".join(lines)


def _detect_vuln_from_title(title: str) -> str | None:
    """Detect vulnerability type from page title."""
    title_lower = title.lower()

    if "ssti" in title_lower or "template" in title_lower:
        return "ssti"
    if "sqli" in title_lower or "sql" in title_lower or "injection" in title_lower:
        return "sqli"
    if "xss" in title_lower or "script" in title_lower:
        return "xss"
    if "lfi" in title_lower or "file inclusion" in title_lower:
        return "lfi"
    if "cmdi" in title_lower or "command" in title_lower or "rce" in title_lower:
        return "cmdi"
    if "traversal" in title_lower or "path" in title_lower:
        return "path_traversal"
    if "2fa" in title_lower or "otp" in title_lower or "mfa" in title_lower:
        return "2fa_bypass"

    return None


def format_page_context(
    url: str,
    title: str,
    elements: list[dict[str, Any]],
    forms: list[dict[str, Any]],
    hints: list[str],
    cookies: list[dict[str, Any]],
    iteration: int,
    max_iterations: int,
    intercepted_request: dict[str, Any] | None = None,
) -> str:
    """
    Format the current page state and action history as context for the agent.

    This becomes the HumanMessage content that provides current state.
    """
    # Detect vulnerability from title
    detected_vuln = _detect_vuln_from_title(title)

    # Only show visible elements - hidden elements can't be filled and are shown in Hints
    visible_elements = [e for e in elements if e.get("visible", True)]
    elements_json = [
        {
            "selector": e.get("selector"),
            "tag": e.get("tag"),
            "type": e.get("type"),
            "name": e.get("name"),
            "text": (e.get("text") or "")[:50],
            "placeholder": e.get("placeholder"),
            "value": e.get("value"),
        }
        for e in visible_elements[:20]
    ]

    # Format forms
    forms_json = [
        {
            "selector": f.get("selector"),
            "method": f.get("method", "GET"),
            "action": f.get("action"),
            "fields": [
                {"name": field.get("name"), "type": field.get("type", "text")}
                for field in f.get("fields", [])
            ],
        }
        for f in forms
    ]

    # Build vulnerability hint if detected
    vuln_hint = ""
    if detected_vuln:
        vuln_hint = f"""
### Detected Vulnerability
Based on page title "{title}", this appears to be a **{detected_vuln.upper()}** challenge.
**Recommended next action**: `get_payload_suggestions("{detected_vuln}")`
"""

    # Build the context message
    context = f"""## Current State (Iteration {iteration}/{max_iterations})

**URL**: {url}
**Page Title**: {title}
{vuln_hint}
### Interactive Elements
```json
{json.dumps(elements_json, indent=2)}
```

### Forms
```json
{json.dumps(forms_json, indent=2)}
```

### Hints Found
{chr(10).join(f'- {h}' for h in hints[:10]) if hints else 'None'}

### Cookies
{chr(10).join(f'- {c.get("name")}={c.get("value", "")[:50]}' for c in cookies[:5]) if cookies else 'None'}
{_format_intercepted_request(intercepted_request)}
---
{"**NOTE**: This page has NO interactive elements. If you need to submit more payloads, use `go_back()` to return to the previous page with the input form." if not visible_elements else ""}
Based on the current page state, decide what to do next. Call exactly ONE tool."""

    return context


def get_system_prompt() -> str:
    """Get the system prompt for the CTF agent."""
    return SYSTEM_PROMPT
