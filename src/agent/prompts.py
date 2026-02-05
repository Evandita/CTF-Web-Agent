"""System prompts for the CTF orchestrator agent."""

SYSTEM_PROMPT = """You are a CTF web challenge solver. Find the hidden flag by exploiting web vulnerabilities.

## Tools
- `try_common_payloads(selector, type)` - Detect vulnerability (ssti/sqli/cmdi/lfi). Use ONCE.
- `fill_input(selector, value)` - Fill input and submit. Main exploitation tool.
- `go_back()` - Return to previous page.
- `check_for_flag()` - Search for flag patterns.

## Workflow
1. Detect vulnerability with try_common_payloads
2. Exploit with fill_input using appropriate payloads
3. **ALWAYS list directories before reading files** - use `ls -la /` first
4. Only read files you have SEEN in directory listings

## Critical Rules
- **NEVER guess file paths** - only use paths from actual command output
- Start with `ls -la /` to see root directory, then explore what you find
- Empty output = file/path doesn't exist, try a different path
- Flag formats: flag{}, CTF{}, picoCTF{}, HTB{}"""


ANALYSIS_PROMPT = """Analyze the page. What vulnerability type? What elements to target? Next action?"""


PLANNING_PROMPT = """Iteration {iteration}/{max_iterations}. Errors: {error_count}. Type: {challenge_type}.
What's your next action?"""


REFLECTION_PROMPT = """Your recent approaches aren't working. Try a different vulnerability type or approach."""


STUCK_PROMPT = """Stuck after {error_count} errors. Consider: other vuln types, robots.txt, cookies, page source. Use request_human_help if truly stuck."""


# Discovery prompt for extracting findings from tool results
# CRITICAL: Only extract paths that are ACTUALLY visible in the tool result
DISCOVERY_PROMPT = """Extract paths from the tool result to explore next.

## Context
{exploitation_context}

## Tool Result
{tool_result}

## Current Queue
{current_queue}

## Rules
1. **ONLY extract paths that are EXPLICITLY shown in the tool result above**
2. **NEVER guess or invent paths** - if you don't see it in the output, don't add it
3. If the result is empty or shows an error, return empty array []
4. If no vulnerability confirmed yet, return empty array []

## What to Look For
- Directory listings (ls output): extract directory and file names you SEE
- Error messages: may reveal actual paths
- If you see a directory, queue it for listing (ls -la)
- If you see a file that might contain a flag, queue it for reading (cat)

## Response Format
Return ONLY a JSON array (empty if nothing found):
```json
[
  {{"target": "/actual/path/from/output", "instruction": "fill_input(selector, payload)", "priority": 1}}
]
```

Priority: 1=flag-related, 2=interesting, 3=general

**IMPORTANT: Empty array [] if the tool result doesn't show any new paths to explore.**"""


def format_discovery_prompt(
    tool_result: str,
    current_queue: list,
    exploitation_context: dict | None = None,
) -> str:
    """Format the discovery prompt with tool result, queue, and exploitation context."""
    queue_str = "Empty" if not current_queue else "\n".join(
        f"- [P{item.get('priority', 2)}] {item.get('target')}: {item.get('instruction', 'no instruction')[:80]}..."
        for item in current_queue
    )

    # Build exploitation context string
    if exploitation_context:
        ctx_lines = []
        if exploitation_context.get("vuln_type"):
            ctx_lines.append(f"Vulnerability: {exploitation_context['vuln_type']}")
        if exploitation_context.get("selector"):
            ctx_lines.append(f"Input Selector: {exploitation_context['selector']}")
        if exploitation_context.get("url"):
            ctx_lines.append(f"URL: {exploitation_context['url']}")
        context_str = "\n".join(ctx_lines) if ctx_lines else "Not yet determined"
    else:
        context_str = "Not yet determined - analyze the tool result to infer"

    return DISCOVERY_PROMPT.format(
        tool_result=tool_result[:2000],  # Limit to avoid token overflow
        current_queue=queue_str,
        exploitation_context=context_str,
    )


def format_planning_prompt(
    iteration: int,
    max_iterations: int,
    challenge_type: str | None,
    error_count: int,
) -> str:
    """Format the planning prompt with current state."""
    return PLANNING_PROMPT.format(
        iteration=iteration,
        max_iterations=max_iterations,
        challenge_type=challenge_type or "?",
        error_count=error_count,
    )


def format_reflection_prompt() -> str:
    """Format the reflection prompt."""
    return REFLECTION_PROMPT


def format_stuck_prompt(
    error_count: int,
) -> str:
    """Format the stuck prompt with current state."""
    return STUCK_PROMPT.format(
        error_count=error_count,
    )
