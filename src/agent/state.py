"""Agent state definition for the CTF orchestrator - ReAct format."""

from typing import TypedDict, Annotated, Any

from langgraph.graph.message import add_messages


class AgentState(TypedDict):
    """State for the CTF solving agent using ReAct pattern.

    The ReAct pattern maintains full conversation history in messages,
    allowing the agent to reason about its past actions and observations.
    """

    # Full message history - this is the core of ReAct
    # Contains: SystemMessage, HumanMessage, AIMessage (with tool_calls), ToolMessage
    messages: Annotated[list, add_messages]

    # Current page state (refreshed each iteration)
    current_url: str
    page_title: str

    # Iteration tracking
    iteration: int
    max_iterations: int

    # Browser data (extracted each iteration for context)
    interactive_elements: list[dict[str, Any]]
    cookies: list[dict[str, Any]]
    local_storage: dict[str, Any]
    html_hints: list[str]

    # Flag detection
    flag_found: str | None

    # Error tracking
    error_count: int

    # Human-in-the-loop state
    needs_human_help: bool
    human_input: str | None


def create_initial_state(
    challenge_url: str,
    max_iterations: int = 30,
) -> AgentState:
    """
    Create the initial agent state for ReAct pattern.

    Args:
        challenge_url: URL of the CTF challenge.
        max_iterations: Maximum number of iterations.

    Returns:
        Initial AgentState dictionary.
    """
    return AgentState(
        messages=[],
        current_url=challenge_url,
        page_title="",
        iteration=0,
        max_iterations=max_iterations,
        interactive_elements=[],
        cookies=[],
        local_storage={},
        html_hints=[],
        flag_found=None,
        error_count=0,
        needs_human_help=False,
        human_input=None,
    )


