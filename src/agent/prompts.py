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
- `fill_input(selector, value)` - Fill an input and submit. This is your MAIN exploitation tool.
- `click_element(selector)` - Click an element
- `execute_javascript(code)` - Run JS in page context

### Information Gathering
- `get_page_state()` - Get full page state as JSON
- `check_for_flag()` - Search page for flag patterns
- `get_page_source()` - Get raw HTML source
- `get_cookies()` - Get all cookies
- `get_local_storage()` - Get localStorage data

### Payload Knowledge (RAG)
- `get_payload_suggestions(vuln_type)` - Retrieve payload suggestions for a vulnerability type
  - Use this FIRST when you identify a vulnerability type
  - Available types: ssti, sqli, cmdi, lfi, xss, path_traversal
  - Returns detection and exploitation payloads

## Critical Rules

1. **Use exact selectors** - Always use selectors from the page state

2. **Don't repeat failed payloads** - If a payload returns empty/error, try a DIFFERENT one

3. **Retrieve payloads via RAG** - Always call `get_payload_suggestions()` before exploiting

4. **Read the output** - The flag might already be in the tool result!

5. **Enumerate before reading** - List directories first, then read specific files

## Flag Formats
Flags typically look like: `flag{...}`, `CTF{...}`, `picoCTF{...}`, `HTB{...}`, `THM{...}`

Remember: Each fill_input submits the form and shows you the OUTPUT. Read it carefully!"""


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
) -> str:
    """
    Format the current page state and action history as context for the agent.

    This becomes the HumanMessage content that provides current state.
    """
    # Detect vulnerability from title
    detected_vuln = _detect_vuln_from_title(title)

    # Format elements
    visible_elements = [e for e in elements if e.get("visible", True)]
    hidden_elements = [e for e in elements if not e.get("visible", True)]

    elements_json = {
        "visible": [
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
        ],
        "hidden": [
            {
                "selector": e.get("selector"),
                "tag": e.get("tag"),
                "name": e.get("name"),
            }
            for e in hidden_elements[:5]
        ],
    }

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

---

Based on the current page state, decide what to do next.
If you identified a vulnerability type, use `get_payload_suggestions(vuln_type)` to retrieve relevant payloads.
Call exactly ONE tool."""

    return context


def get_system_prompt() -> str:
    """Get the system prompt for the CTF agent."""
    return SYSTEM_PROMPT
