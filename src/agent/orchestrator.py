"""Main LangGraph orchestrator for the CTF solving agent."""

import json
import re
from typing import Literal

from langchain_core.messages import HumanMessage, SystemMessage, AIMessage, ToolMessage
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode

from .state import AgentState, create_initial_state
from .prompts import SYSTEM_PROMPT, format_planning_prompt, format_reflection_prompt, format_discovery_prompt
from ..browser.controller import BrowserController
from ..browser.tools import ALL_TOOLS, set_browser_controller, set_exploration_queue, get_exploration_queue
from ..browser.extractors import extract_interactive_elements, extract_html_hints, extract_forms
from ..models.ollama_client import get_text_model
from ..utils.flag_detector import detect_flag_in_page
from ..utils.logger import (
    log_action,
    log_observation,
    log_thinking,
    log_flag_found,
    log_error,
    log_state,
    log_iteration,
    log_tool_call,
    log_tool_result,
    log_prompt,
    log_response,
)
from ..config import get_settings


def _extract_json_with_nested_braces(content: str) -> str | None:
    """
    Extract a JSON object from text, handling nested braces.

    This is needed because SSTI payloads contain {{ and }} which break simple regex.
    """
    # Find the first { that starts a JSON-like structure
    start_patterns = [
        '{"name"',  # Tool call JSON
        "{'name'",  # Single quote variant
    ]

    start_idx = -1
    for pattern in start_patterns:
        idx = content.find(pattern)
        if idx != -1 and (start_idx == -1 or idx < start_idx):
            start_idx = idx

    if start_idx == -1:
        return None

    # Count braces to find matching end
    brace_count = 0
    in_string = False
    escape_next = False

    for i, char in enumerate(content[start_idx:], start_idx):
        if escape_next:
            escape_next = False
            continue

        if char == '\\':
            escape_next = True
            continue

        if char == '"' and not escape_next:
            in_string = not in_string
            continue

        if not in_string:
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    return content[start_idx:i+1]

    return None


def _parse_tool_call_from_text(content: str, available_tools: list) -> dict | None:
    """
    Attempt to parse a tool call from LLM text output.

    Some models output tool calls as JSON in text rather than structured tool_calls.
    This function tries to extract and match them.
    """
    if not content:
        return None

    # Get tool names
    tool_names = [t.name for t in available_tools]

    # Try to find tool name mentioned in content
    mentioned_tool = None
    for tool_name in tool_names:
        if tool_name in content or tool_name.replace('_', ' ') in content.lower():
            mentioned_tool = tool_name
            break

    if not mentioned_tool:
        return None

    # Try to extract JSON with nested braces support (for SSTI payloads with {{ }})
    json_str = _extract_json_with_nested_braces(content)

    if json_str:
        try:
            parsed = json.loads(json_str)

            # Check if it's a tool call format
            if isinstance(parsed, dict) and "name" in parsed:
                tool_name = parsed.get("name")
                if tool_name in tool_names:
                    # Extract args from "parameters" or "args" key
                    args = parsed.get("parameters", parsed.get("args", {}))
                    if isinstance(args, dict):
                        return {
                            "name": tool_name,
                            "args": args,
                            "id": f"parsed_{tool_name}",
                        }
        except json.JSONDecodeError:
            pass

    # Fallback: Try simple JSON extraction for basic cases
    try:
        # Look for simpler JSON without nested braces
        json_match = re.search(r'\{[^{}]*\}', content)
        if json_match:
            json_str = json_match.group()
            args = json.loads(json_str)

            # Validate args are reasonable (dict with string keys)
            if isinstance(args, dict) and all(isinstance(k, str) for k in args.keys()):
                return {
                    "name": mentioned_tool,
                    "args": args,
                    "id": f"parsed_{mentioned_tool}",
                }
    except (json.JSONDecodeError, AttributeError):
        pass

    return None


class CTFOrchestrator:
    """LangGraph-based orchestrator for CTF challenge solving."""

    def __init__(self, browser_controller: BrowserController):
        """
        Initialize the orchestrator.

        Args:
            browser_controller: Initialized browser controller instance.
        """
        self.browser = browser_controller
        set_browser_controller(browser_controller)

        self.llm = get_text_model()
        self.tools = ALL_TOOLS
        self.llm_with_tools = self.llm.bind_tools(self.tools)

        self.graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        """Build the LangGraph state machine."""
        # Create the graph
        graph = StateGraph(AgentState)

        # Add nodes
        graph.add_node("analyze", self._analyze_node)
        graph.add_node("plan", self._plan_node)
        graph.add_node("execute", ToolNode(self.tools))
        graph.add_node("check_result", self._check_result_node)
        graph.add_node("discovery", self._discovery_node)

        # Set entry point
        graph.set_entry_point("analyze")

        # Add edges
        # Flow: analyze → plan → execute → check_result → discovery → analyze
        graph.add_edge("analyze", "plan")
        graph.add_conditional_edges(
            "plan",
            self._should_execute,
            {
                "execute": "execute",
                "end": END,
            }
        )
        graph.add_edge("execute", "check_result")
        graph.add_conditional_edges(
            "check_result",
            self._should_continue_to_discovery,
            {
                "discovery": "discovery",
                "end": END,
            }
        )
        graph.add_edge("discovery", "analyze")

        return graph.compile()

    async def _analyze_node(self, state: AgentState) -> dict:
        """
        Analyze the current page state.

        Gathers information from the page and prepares context for planning.
        Also builds a JSON page state that will be injected into the LLM prompt.
        """
        iteration = state["iteration"] + 1
        settings = get_settings()

        log_iteration(iteration, state["max_iterations"])

        # Sync exploration queue from state to tools
        set_exploration_queue(state.get("exploration_queue", []))

        # Get page information
        if self.browser.page:
            url = self.browser.get_current_url()
            title = await self.browser.page.title()
            elements = await extract_interactive_elements(self.browser.page)
            forms = await extract_forms(self.browser.page)
            hints = await extract_html_hints(self.browser.page)
            cookies = await self.browser.get_cookies()
            local_storage = await self.browser.get_local_storage()
            html = await self.browser.get_page_content()

            # Check for flag immediately
            flag = detect_flag_in_page(
                html=html,
                cookies=cookies,
                local_storage=local_storage,
                console_logs=self.browser.get_console_logs(),
                network_responses=self.browser.get_network_traffic().get("responses", []),
            )

            if flag:
                log_flag_found(flag)
                return {
                    "iteration": iteration,
                    "current_url": url,
                    "page_title": title,
                    "interactive_elements": elements,
                    "html_hints": hints,
                    "cookies": cookies,
                    "local_storage": local_storage,
                    "flag_found": flag,
                }

            log_observation(f"Analyzing page: {url}")
            log_observation(f"Found {len(elements)} interactive elements, {len(hints)} hints")

            # Build JSON page state for LLM context injection
            visible_elements = [e for e in elements if e.get("visible", True)]
            hidden_elements = [e for e in elements if not e.get("visible", True)]

            page_state_json = {
                "url": url,
                "title": title,
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
                            "reason": e.get("interactiveReason"),
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
                            "reason": e.get("interactiveReason"),
                        }
                        for e in hidden_elements[:10]
                    ],
                },
                "forms": [
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
                ],
                "hints": hints[:20],
                "cookies": [
                    {"name": c.get("name"), "value": c.get("value", "")}
                    for c in cookies
                ] if cookies else [],
            }

            # Store as formatted JSON string for prompt injection
            page_analysis = json.dumps(page_state_json, indent=2)

            return {
                "iteration": iteration,
                "current_url": url,
                "page_title": title,
                "page_analysis": page_analysis,
                "interactive_elements": elements,
                "html_hints": hints,
                "cookies": cookies,
                "local_storage": local_storage,
            }

        return {"iteration": iteration}

    async def _plan_node(self, state: AgentState) -> dict:
        """
        Plan the next action using the LLM.

        Decides what tool to call based on current state.
        Page state is automatically injected - no need for LLM to call get_page_state.
        """
        # Check if flag already found
        if state.get("flag_found"):
            return {}

        # Check iteration limit
        if state["iteration"] >= state["max_iterations"]:
            log_error(f"Reached maximum iterations ({state['max_iterations']})")
            return {}

        # Check if we have queue items to process first
        queue = state.get("exploration_queue", [])
        dequeued_item = None
        if queue:
            # Use LLM-generated instruction from the first queue item
            first_item = queue[0]
            instruction = first_item.get("instruction")
            if instruction:
                context_prompt = f"Execute this task: {instruction}"
                log_observation(f"Processing queue: {first_item.get('target', 'unknown')}")
                # Dequeue this item (will be returned in state update)
                dequeued_item = first_item
            else:
                # No instruction, fall back to normal planning
                context_prompt = format_planning_prompt(
                    iteration=state["iteration"],
                    max_iterations=state["max_iterations"],
                    challenge_type=state.get("challenge_type"),
                    error_count=state["error_count"],
                )
        elif state["error_count"] > 3:
            # Reflection mode for many errors
            context_prompt = format_reflection_prompt()
        else:
            # Normal planning
            context_prompt = format_planning_prompt(
                iteration=state["iteration"],
                max_iterations=state["max_iterations"],
                challenge_type=state.get("challenge_type"),
                error_count=state["error_count"],
            )

        messages = state["messages"].copy()

        # Add system message if first iteration
        if state["iteration"] == 1:
            messages.append(SystemMessage(content=SYSTEM_PROMPT))

        # Build the prompt with auto-injected page state
        # This eliminates the need for LLM to call get_page_state as a tool
        page_state = state.get("page_analysis", "")
        if page_state:
            full_prompt = f"""## Current Page State (auto-extracted)
```json
{page_state}
```

## Your Task
{context_prompt}

Based on the page state above, decide what action to take next. Call the appropriate tool directly"""
        else:
            full_prompt = context_prompt

        # Add current context with page state
        messages.append(HumanMessage(content=full_prompt))

        # Log the prompt for debugging
        log_prompt(full_prompt, "PLAN")

        log_thinking("Planning next action...")

        # Get LLM response with tool calls
        try:
            response = await self.llm_with_tools.ainvoke(messages)
        except Exception as e:
            log_error(f"LLM invocation failed: {e}")
            # Return empty response to trigger retry on next iteration
            return {"messages": [], "error_count": state["error_count"] + 1}

        # Log the response for debugging
        response_text = str(response.content) if response.content else ""
        if hasattr(response, "tool_calls") and response.tool_calls:
            tool_info = [{"name": tc["name"], "args": tc.get("args", {})} for tc in response.tool_calls]
            response_text += f"\n[Tool calls: {tool_info}]"
        log_response(response_text, "PLAN")

        # Log thinking (model's reasoning)
        if response.content:
            log_thinking(str(response.content))
        elif hasattr(response, "tool_calls") and response.tool_calls:
            # Model returned tool calls without reasoning - log what it's doing
            tool_names = [tc["name"] for tc in response.tool_calls]
            log_thinking(f"(No reasoning provided - calling: {', '.join(tool_names)})")

        # Check for tool calls
        has_tool_calls = hasattr(response, "tool_calls") and response.tool_calls

        # If no tool calls, try to parse from text (fallback for models that output JSON in text)
        if not has_tool_calls and response.content:
            parsed_call = _parse_tool_call_from_text(response.content, self.tools)
            if parsed_call:
                log_observation(f"Parsed tool call from text: {parsed_call['name']}")
                # Create a new AIMessage with the parsed tool call
                response = AIMessage(
                    content=response.content,
                    tool_calls=[parsed_call],
                )
                has_tool_calls = True

        # Log tool calls if any
        if has_tool_calls:
            for tool_call in response.tool_calls:
                log_tool_call(tool_call["name"], tool_call.get("args", {}))
        else:
            log_error("No tool calls generated by LLM.")
            log_observation("The model may not support function calling or didn't decide to use a tool.")

        # Build return state
        result = {"messages": [response]}

        # If we dequeued an item, update the queue
        if dequeued_item:
            updated_queue = [item for item in queue if item["target"] != dequeued_item["target"]]
            result["exploration_queue"] = updated_queue
            set_exploration_queue(updated_queue)
            log_observation(f"Dequeued: {dequeued_item['target']} ({len(updated_queue)} remaining)")

        return result

    async def _check_result_node(self, state: AgentState) -> dict:
        """
        Check the result of the last action.

        Updates state based on tool execution results.
        """
        messages = state["messages"]
        error_count = state["error_count"]

        # Find the last tool message
        for msg in reversed(messages):
            if isinstance(msg, ToolMessage):
                result = msg.content

                log_tool_result(msg.name, str(result))

                # Check for errors
                is_error = "error" in str(result).lower()
                if is_error:
                    error_count += 1
                    log_error(f"Tool error: {result}")

                # Check for flag in result
                from ..utils.flag_detector import detect_flag
                flag = detect_flag(str(result))
                if flag:
                    log_flag_found(flag)
                    return {
                        "flag_found": flag,
                        "error_count": error_count,
                    }

                break

        # Also check page for flag
        if self.browser.page:
            html = await self.browser.get_page_content()
            cookies = await self.browser.get_cookies()
            local_storage = await self.browser.get_local_storage()

            flag = detect_flag_in_page(
                html=html,
                cookies=cookies,
                local_storage=local_storage,
                console_logs=self.browser.get_console_logs(),
                network_responses=self.browser.get_network_traffic().get("responses", []),
            )

            if flag:
                log_flag_found(flag)
                return {
                    "flag_found": flag,
                    "error_count": error_count,
                }

        # Sync exploration queue from tools back to state
        current_queue = get_exploration_queue()

        return {
            "error_count": error_count,
            "exploration_queue": current_queue,
        }

    async def _discovery_node(self, state: AgentState) -> dict:
        """
        Analyze tool results and extract discoveries to queue.

        Uses LLM to identify interesting paths, files, URLs from tool output.
        Automatically manages the exploration queue.
        Also extracts and updates exploitation context (vuln type, selector).
        """
        # Skip if flag found
        if state.get("flag_found"):
            return {}

        # Get the last tool result
        messages = state["messages"]
        last_tool_result = None
        last_tool_name = None

        for msg in reversed(messages):
            if isinstance(msg, ToolMessage):
                last_tool_result = msg.content
                last_tool_name = msg.name
                break

        # Skip discovery if no tool result or certain tool types
        skip_tools = {"check_for_flag", "request_human_help", "get_page_state", "list_interactive_elements", "try_common_payloads"}
        if not last_tool_result or last_tool_name in skip_tools:
            return {}

        result_str = str(last_tool_result)

        # Skip if result is too short (likely an error or empty)
        if len(result_str) < 50:
            return {}

        # Skip discovery if result shows empty output (no paths to extract)
        if "Output: (empty" in result_str or "File may not exist" in result_str:
            return {}

        # Only run discovery if the result looks like it contains actual paths
        # (directory listings typically have drwx, -rw, or path-like patterns)
        has_directory_listing = any(pattern in result_str for pattern in [
            "drwx", "-rw-", "total ", "lrwx",  # ls -la output indicators
            ".txt", ".py", ".php", ".html", ".conf",  # file extensions
        ])
        has_path_output = "/" in result_str and len(result_str) > 100

        if not has_directory_listing and not has_path_output:
            return {}

        current_queue = state.get("exploration_queue", [])
        exploitation_context = state.get("exploitation_context") or {}

        # Extract exploitation context from tool results (e.g., try_common_payloads)
        # Look for vulnerability confirmation patterns
        if "SSTI CONFIRMED" in result_str or "ssti" in last_tool_name.lower():
            exploitation_context["vuln_type"] = "ssti"
            exploitation_context["confirmed"] = True
            # Try to extract selector from the result
            selector_match = re.search(r"fill_input\(['\"]([^'\"]+)['\"]", result_str)
            if selector_match:
                exploitation_context["selector"] = selector_match.group(1)
        elif "SQL" in result_str.upper() and ("injection" in result_str.lower() or "error" in result_str.lower()):
            exploitation_context["vuln_type"] = "sqli"
        elif "command" in result_str.lower() and ("injection" in result_str.lower() or "executed" in result_str.lower()):
            exploitation_context["vuln_type"] = "cmdi"

        # Add URL to context
        exploitation_context["url"] = state.get("current_url", "")

        # Build discovery prompt with exploitation context
        discovery_prompt = format_discovery_prompt(
            tool_result=result_str,
            current_queue=current_queue,
            exploitation_context=exploitation_context if exploitation_context else None,
        )

        # Log the discovery prompt for debugging
        log_prompt(discovery_prompt, "DISCOVERY")

        log_thinking("Analyzing results for discoveries...")

        try:
            # Use base LLM (no tools) for discovery - faster and simpler
            response = await self.llm.ainvoke([
                HumanMessage(content=discovery_prompt)
            ])

            # Parse JSON array from response
            content = response.content

            # Log the discovery response
            log_response(str(content) if content else "(empty)", "DISCOVERY")

            if not content:
                return {}

            # Extract JSON array from response
            json_match = re.search(r'\[\s*\{.*?\}\s*\]|\[\s*\]', content, re.DOTALL)
            if json_match:
                try:
                    new_items = json.loads(json_match.group())

                    if new_items and isinstance(new_items, list):
                        # Filter out items already in queue
                        existing_targets = {item["target"] for item in current_queue}
                        filtered_items = [
                            item for item in new_items
                            if isinstance(item, dict)
                            and item.get("target")
                            and item["target"] not in existing_targets
                        ]

                        if filtered_items:
                            # Add new items to queue
                            updated_queue = current_queue + filtered_items
                            # Sort by priority
                            updated_queue.sort(key=lambda x: x.get("priority", 2))

                            log_observation(f"Queued {len(filtered_items)} new items: {[i.get('target', '?') for i in filtered_items]}")

                            # Sync to tools
                            set_exploration_queue(updated_queue)

                            return {
                                "exploration_queue": updated_queue,
                                "exploitation_context": exploitation_context if exploitation_context else None,
                            }
                except json.JSONDecodeError:
                    pass

        except Exception as e:
            log_error(f"Discovery analysis failed: {e}")

        # Return exploitation context even if no new queue items
        if exploitation_context:
            return {"exploitation_context": exploitation_context}

        return {}

    def _should_execute(self, state: AgentState) -> Literal["execute", "end"]:
        """Determine if we should execute a tool or end."""
        # End if flag found
        if state.get("flag_found"):
            return "end"

        # End if max iterations reached
        if state["iteration"] >= state["max_iterations"]:
            return "end"

        # Check if there are tool calls to execute
        messages = state["messages"]
        if messages:
            last_message = messages[-1]
            if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                return "execute"

        return "end"

    def _should_continue_to_discovery(self, state: AgentState) -> Literal["discovery", "end"]:
        """Determine if we should continue to discovery or end after checking results."""
        # End if flag found
        if state.get("flag_found"):
            log_action("Challenge solved!", f"Flag: {state['flag_found']}")
            return "end"

        # End if max iterations reached
        if state["iteration"] >= state["max_iterations"]:
            log_error("Maximum iterations reached without finding flag")
            return "end"

        # Continue to discovery node
        return "discovery"

    async def solve(self, challenge_url: str) -> dict:
        """
        Solve a CTF challenge.

        Args:
            challenge_url: URL of the CTF challenge.

        Returns:
            Final state dictionary with results.
        """
        settings = get_settings()

        log_action("Starting CTF solver", f"Target: {challenge_url}")

        # Initialize browser and navigate to challenge
        await self.browser.initialize()

        try:
            # Navigate to the challenge
            await self.browser.navigate(challenge_url)

            # Create initial state
            initial_state = create_initial_state(
                challenge_url=challenge_url,
                max_iterations=settings.max_iterations,
            )

            # Run the graph
            result = await self.graph.ainvoke(initial_state)

            # Log final state
            log_state(result)

            return result

        finally:
            await self.browser.close()

    async def solve_with_browser(self, challenge_url: str) -> dict:
        """
        Solve a CTF challenge using an already-initialized browser.

        Use this when you want to control browser lifecycle externally.

        Args:
            challenge_url: URL of the CTF challenge.

        Returns:
            Final state dictionary with results.
        """
        settings = get_settings()

        log_action("Starting CTF solver", f"Target: {challenge_url}")

        # Navigate to the challenge
        await self.browser.navigate(challenge_url)

        # Create initial state
        initial_state = create_initial_state(
            challenge_url=challenge_url,
            max_iterations=settings.max_iterations,
        )

        # Run the graph
        result = await self.graph.ainvoke(initial_state)

        # Log final state
        log_state(result)

        return result
