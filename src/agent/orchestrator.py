"""Main LangGraph orchestrator for the CTF solving agent - ReAct format."""

from typing import Literal

from langchain_core.messages import HumanMessage, AIMessage, ToolMessage, SystemMessage
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode

from .state import AgentState, create_initial_state
from .prompts import get_system_prompt, format_page_context
from ..browser.controller import BrowserController
from ..browser.tools import REACT_TOOLS, set_browser_controller
from ..browser.extractors import extract_interactive_elements, extract_html_hints, extract_forms
from ..models.ollama_client import get_text_model
from ..utils.flag_detector import detect_flag_in_page, detect_flag
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


class CTFOrchestrator:
    """LangGraph-based orchestrator for CTF challenge solving.

    Uses a simple ReAct pattern:
    - reason: LLM analyzes state and decides on tool call
    - act: Execute the tool
    - Loop until flag found or max iterations
    """

    def __init__(self, browser_controller: BrowserController):
        """Initialize the orchestrator."""
        self.browser = browser_controller
        set_browser_controller(browser_controller)

        self.llm = get_text_model()
        self.tools = REACT_TOOLS
        self.llm_with_tools = self.llm.bind_tools(self.tools)

        self.graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        """Build the LangGraph state machine.

        Simple ReAct flow: reason → act → reason → act → ...
        """
        graph = StateGraph(AgentState)

        # Add nodes
        graph.add_node("reason", self._reason_node)
        graph.add_node("act", ToolNode(self.tools))

        # Set entry point
        graph.set_entry_point("reason")

        # reason → act (if tool call) or end
        graph.add_conditional_edges(
            "reason",
            self._should_act,
            {
                "act": "act",
                "end": END,
            }
        )

        # act → reason (always loop back after tool execution)
        graph.add_edge("act", "reason")

        return graph.compile()

    async def _extract_page_state(self) -> dict:
        """Extract current page state for LLM context."""
        if not self.browser.page:
            return {}

        url = self.browser.get_current_url()
        title = await self.browser.page.title()
        elements = await extract_interactive_elements(self.browser.page)
        forms = await extract_forms(self.browser.page)
        hints = await extract_html_hints(self.browser.page)
        cookies = await self.browser.get_cookies()
        local_storage = await self.browser.get_local_storage()

        log_observation(f"Page: {url} | {len(elements)} elements, {len(hints)} hints")

        return {
            "current_url": url,
            "page_title": title,
            "interactive_elements": elements,
            "html_hints": hints,
            "cookies": cookies,
            "local_storage": local_storage,
            "forms": forms,
        }

    async def _reason_node(self, state: AgentState) -> dict:
        """
        Reason about the current state and decide on the next action.

        This is the core of ReAct:
        1. Check termination conditions
        2. Extract current page state
        3. Check for flag in page
        4. Build messages with full history + current context
        5. Call LLM with tools to decide next action
        """
        iteration = state["iteration"] + 1
        log_iteration(iteration, state["max_iterations"])

        # Check termination conditions
        if state.get("flag_found"):
            log_action("Challenge solved!", f"Flag: {state['flag_found']}")
            return {}

        if iteration > state["max_iterations"]:
            log_error(f"Reached maximum iterations ({state['max_iterations']})")
            return {}

        # Extract current page state
        page_state = await self._extract_page_state()

        # Check for flag in page
        if self.browser.page:
            html = await self.browser.get_page_content()
            flag = detect_flag_in_page(
                html=html,
                cookies=page_state.get("cookies", []),
                local_storage=page_state.get("local_storage", {}),
                console_logs=self.browser.get_console_logs(),
                network_responses=self.browser.get_network_traffic().get("responses", []),
            )
            if flag:
                log_flag_found(flag)
                return {
                    "iteration": iteration,
                    "flag_found": flag,
                    **page_state,
                }

        # Process any tool results from previous iteration
        messages = list(state.get("messages", []))

        # Check if last message was a ToolMessage - log it and check for flag
        if messages:
            for msg in reversed(messages):
                if isinstance(msg, ToolMessage):
                    result_str = str(msg.content)[:500]

                    # Check for flag in tool result
                    flag = detect_flag(result_str)
                    if flag:
                        log_flag_found(flag)
                        return {
                            "iteration": iteration,
                            "flag_found": flag,
                            **page_state,
                        }

                    log_tool_result(msg.name, result_str)
                    break

        # Build the context message for current state
        context_message = format_page_context(
            url=page_state.get("current_url", state["current_url"]),
            title=page_state.get("page_title", ""),
            elements=page_state.get("interactive_elements", []),
            forms=page_state.get("forms", []),
            hints=page_state.get("html_hints", []),
            cookies=page_state.get("cookies", []),
            iteration=iteration,
            max_iterations=state["max_iterations"],
        )

        # Build messages for LLM
        # First iteration: add system message and initial human message
        if iteration == 1:
            llm_messages = [
                SystemMessage(content=get_system_prompt()),
                HumanMessage(content=context_message),
            ]
        else:
            # Subsequent iterations: use existing messages + new context
            # Filter to keep only the conversation history, add new context
            llm_messages = [
                SystemMessage(content=get_system_prompt()),
            ]

            # Add conversation history (AI messages with tool calls and tool results)
            for msg in messages:
                if isinstance(msg, (AIMessage, ToolMessage)):
                    llm_messages.append(msg)

            # Add current state as new human message
            llm_messages.append(HumanMessage(content=context_message))

        # Log the prompt being sent
        log_prompt(context_message, "REASON")
        log_thinking("Deciding next action...")

        try:
            # Call LLM with tools
            response = await self.llm_with_tools.ainvoke(llm_messages)

            # Log the response
            response_text = str(response.content) if response.content else ""
            if hasattr(response, "tool_calls") and response.tool_calls:
                tool_info = [{"name": tc["name"], "args": tc.get("args", {})} for tc in response.tool_calls]
                response_text += f"\n[Tool calls: {tool_info}]"
            log_response(response_text, "REASON")

            # Check if there are tool calls
            has_tool_calls = hasattr(response, "tool_calls") and response.tool_calls

            if has_tool_calls:
                tc = response.tool_calls[0]
                log_tool_call(tc["name"], tc.get("args", {}))
                log_thinking(f"Action: {tc['name']}({tc.get('args', {})})")

            return {
                "iteration": iteration,
                "messages": [response],  # LangGraph will add this to history
                **page_state,
            }

        except Exception as e:
            log_error(f"Reason failed: {e}")
            return {
                "iteration": iteration,
                "error_count": state["error_count"] + 1,
                **page_state,
            }

    def _should_act(self, state: AgentState) -> Literal["act", "end"]:
        """Determine if we should execute a tool or end."""
        # End if flag found
        if state.get("flag_found"):
            return "end"

        # End if max iterations reached
        if state["iteration"] >= state["max_iterations"]:
            log_error("Maximum iterations reached without finding flag")
            return "end"

        # Check if last message has tool calls
        messages = state.get("messages", [])
        if messages:
            last_message = messages[-1]
            if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                return "act"

        # No tool call, end (LLM decided to stop)
        return "end"

    async def solve(self, challenge_url: str) -> dict:
        """Solve a CTF challenge."""
        settings = get_settings()

        log_action("Starting CTF solver", f"Target: {challenge_url}")

        await self.browser.initialize()

        try:
            await self.browser.navigate(challenge_url)

            initial_state = create_initial_state(
                challenge_url=challenge_url,
                max_iterations=settings.max_iterations,
            )

            result = await self.graph.ainvoke(initial_state)

            log_state(result)

            return result

        finally:
            await self.browser.close()

    async def solve_with_browser(self, challenge_url: str) -> dict:
        """Solve a CTF challenge using an already-initialized browser."""
        settings = get_settings()

        log_action("Starting CTF solver", f"Target: {challenge_url}")

        await self.browser.navigate(challenge_url)

        initial_state = create_initial_state(
            challenge_url=challenge_url,
            max_iterations=settings.max_iterations,
        )

        result = await self.graph.ainvoke(initial_state)

        log_state(result)

        return result
