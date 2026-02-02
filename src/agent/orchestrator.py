"""Main LangGraph orchestrator for the CTF solving agent."""

import json
import re
from typing import Literal

from langchain_core.messages import HumanMessage, SystemMessage, AIMessage, ToolMessage
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode

from .state import AgentState, create_initial_state, add_action_to_history, format_action_history
from .prompts import SYSTEM_PROMPT, format_planning_prompt, format_reflection_prompt
from ..browser.controller import BrowserController
from ..browser.tools import ALL_TOOLS, set_browser_controller
from ..browser.extractors import extract_interactive_elements, extract_html_hints
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

        # Set entry point
        graph.set_entry_point("analyze")

        # Add edges
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
            self._should_continue,
            {
                "continue": "analyze",
                "end": END,
            }
        )

        return graph.compile()

    async def _analyze_node(self, state: AgentState) -> dict:
        """
        Analyze the current page state.

        Gathers information from the page and prepares context for planning.
        """
        iteration = state["iteration"] + 1
        settings = get_settings()

        log_iteration(iteration, state["max_iterations"])

        # Get page information
        if self.browser.page:
            url = self.browser.get_current_url()
            title = await self.browser.page.title()
            elements = await extract_interactive_elements(self.browser.page)
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

            return {
                "iteration": iteration,
                "current_url": url,
                "page_title": title,
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
        """
        # Check if flag already found
        if state.get("flag_found"):
            return {}

        # Check iteration limit
        if state["iteration"] >= state["max_iterations"]:
            log_error(f"Reached maximum iterations ({state['max_iterations']})")
            return {}

        # Build context for the LLM
        action_history = format_action_history(state)

        # Determine if we need reflection (many errors)
        if state["error_count"] > 3:
            context_prompt = format_reflection_prompt(
                url=state["current_url"],
                page_analysis=state.get("page_analysis", ""),
                action_history=action_history,
            )
        else:
            context_prompt = format_planning_prompt(
                url=state["current_url"],
                iteration=state["iteration"],
                max_iterations=state["max_iterations"],
                challenge_type=state.get("challenge_type"),
                error_count=state["error_count"],
                action_history=action_history,
            )

        # Add context about current page
        page_context = self._build_page_context(state)

        messages = state["messages"].copy()

        # Add system message if first iteration
        if state["iteration"] == 1:
            messages.append(SystemMessage(content=SYSTEM_PROMPT))
            messages.append(HumanMessage(content=f"Solve the CTF challenge at: {state['current_url']}"))

        # Add current context
        messages.append(HumanMessage(content=f"{context_prompt}\n\n{page_context}"))

        log_thinking("Planning next action...")

        # Get LLM response with tool calls
        try:
            response = await self.llm_with_tools.ainvoke(messages)
        except Exception as e:
            log_error(f"LLM invocation failed: {e}")
            # Return empty response to trigger retry on next iteration
            return {"messages": [], "error_count": state["error_count"] + 1}

        # Log thinking (full content to file, truncated to console)
        if response.content:
            log_thinking(str(response.content))

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

        return {"messages": [response]}

    def _build_page_context(self, state: AgentState) -> str:
        """Build page context string for the LLM."""
        lines = [
            f"Current URL: {state['current_url']}",
            f"Page Title: {state.get('page_title', 'Unknown')}",
            "",
        ]

        # Add elements summary
        elements = state.get("interactive_elements", [])
        if elements:
            lines.append(f"Interactive Elements ({len(elements)}):")
            for elem in elements[:10]:
                tag = elem.get("tag", "?")
                selector = elem.get("selector", "")
                text = elem.get("text", "")[:30]
                lines.append(f"  - <{tag}> {selector} : {text}")
            if len(elements) > 10:
                lines.append(f"  ... and {len(elements) - 10} more")
            lines.append("")

        # Add hints
        hints = state.get("html_hints", [])
        if hints:
            lines.append(f"HTML Hints ({len(hints)}):")
            for hint in hints[:5]:
                lines.append(f"  - {hint[:80]}")
            lines.append("")

        # Add cookies
        cookies = state.get("cookies", [])
        if cookies:
            lines.append(f"Cookies ({len(cookies)}):")
            for cookie in cookies[:5]:
                lines.append(f"  - {cookie.get('name')}={cookie.get('value', '')[:30]}")
            lines.append("")

        return "\n".join(lines)

    async def _check_result_node(self, state: AgentState) -> dict:
        """
        Check the result of the last action.

        Updates state based on tool execution results.
        """
        messages = state["messages"]
        error_count = state["error_count"]
        action_history = state["action_history"].copy()

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

                # Add to history
                action_history.append({
                    "iteration": state["iteration"],
                    "action": msg.name,
                    "args": {},  # Args not easily accessible here
                    "result": str(result)[:1000],
                    "success": not is_error,
                })

                # Check for flag in result
                from ..utils.flag_detector import detect_flag
                flag = detect_flag(str(result))
                if flag:
                    log_flag_found(flag)
                    return {
                        "flag_found": flag,
                        "error_count": error_count,
                        "action_history": action_history[-50:],
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
                    "action_history": action_history[-50:],
                }

        return {
            "error_count": error_count,
            "action_history": action_history[-50:],
        }

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

    def _should_continue(self, state: AgentState) -> Literal["continue", "end"]:
        """Determine if we should continue or end after checking results."""
        # End if flag found
        if state.get("flag_found"):
            log_action("Challenge solved!", f"Flag: {state['flag_found']}")
            return "end"

        # End if max iterations reached
        if state["iteration"] >= state["max_iterations"]:
            log_error("Maximum iterations reached without finding flag")
            return "end"

        # Continue otherwise
        return "continue"

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
