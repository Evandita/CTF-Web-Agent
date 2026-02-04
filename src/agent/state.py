"""Agent state definition for the CTF orchestrator."""

from typing import TypedDict, Annotated, Any

from langgraph.graph.message import add_messages


class AgentState(TypedDict):
    """State for the CTF solving agent."""

    # Message history with LangGraph's message management
    messages: Annotated[list, add_messages]

    # Current page state
    current_url: str
    page_title: str

    # Iteration tracking
    iteration: int
    max_iterations: int

    # Page analysis results
    page_analysis: str
    interactive_elements: list[dict[str, Any]]

    # Browser data
    cookies: list[dict[str, Any]]
    local_storage: dict[str, Any]
    network_traffic: list[dict[str, Any]]
    console_logs: list[str]
    html_hints: list[str]

    # Flag detection
    flag_found: str | None

    # Error tracking
    error_count: int
    last_error: str | None

    # Human-in-the-loop state
    needs_human_help: bool
    human_input: str | None

    # Challenge type classification
    challenge_type: str | None

    # Exploration queue - tracks interesting things to investigate
    # Each item: {"type": "dir|file|path|payload", "target": "/path", "reason": "why interesting", "priority": 1-3}
    exploration_queue: list[dict[str, Any]]


def create_initial_state(
    challenge_url: str,
    max_iterations: int = 30,
) -> AgentState:
    """
    Create the initial agent state.

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
        page_analysis="",
        interactive_elements=[],
        cookies=[],
        local_storage={},
        network_traffic=[],
        console_logs=[],
        html_hints=[],
        flag_found=None,
        error_count=0,
        last_error=None,
        needs_human_help=False,
        human_input=None,
        challenge_type=None,
        exploration_queue=[],
    )


def add_to_exploration_queue(
    state: AgentState,
    target: str,
    item_type: str = "unknown",
    reason: str = "",
    priority: int = 2,
) -> list[dict[str, Any]]:
    """
    Add an item to the exploration queue.

    Args:
        state: Current agent state.
        target: The path/file/payload to explore.
        item_type: Type of item ("dir", "file", "path", "payload", "url").
        reason: Why this item is interesting.
        priority: Priority level (1=high, 2=medium, 3=low).

    Returns:
        Updated exploration queue.
    """
    queue = state["exploration_queue"].copy()

    # Check if already in queue
    if any(item["target"] == target for item in queue):
        return queue

    queue.append({
        "type": item_type,
        "target": target,
        "reason": reason,
        "priority": priority,
    })

    # Sort by priority (lower number = higher priority)
    queue.sort(key=lambda x: x["priority"])

    return queue


def remove_from_exploration_queue(
    state: AgentState,
    target: str,
) -> list[dict[str, Any]]:
    """
    Remove an item from the exploration queue (after exploring it).

    Args:
        state: Current agent state.
        target: The target to remove.

    Returns:
        Updated exploration queue.
    """
    queue = state["exploration_queue"].copy()
    queue = [item for item in queue if item["target"] != target]
    return queue


def format_exploration_queue(state: AgentState) -> str:
    """
    Format the exploration queue for inclusion in prompts.

    Args:
        state: Current agent state.

    Returns:
        Formatted string of items to explore.
    """
    queue = state["exploration_queue"]
    if not queue:
        return "No pending items to explore."

    lines = ["Pending exploration queue:"]
    for i, item in enumerate(queue, 1):
        priority_label = {1: "HIGH", 2: "MED", 3: "LOW"}.get(item["priority"], "?")
        lines.append(f"  {i}. [{priority_label}] {item['type']}: {item['target']}")
        if item.get("reason"):
            lines.append(f"      Reason: {item['reason']}")

    return "\n".join(lines)
