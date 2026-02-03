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

    # Action history for avoiding repetition
    action_history: list[dict[str, Any]]

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
        action_history=[],
        needs_human_help=False,
        human_input=None,
        challenge_type=None,
        exploration_queue=[],
    )


def add_action_to_history(
    state: AgentState,
    action: str,
    args: dict[str, Any],
    result: str,
    success: bool,
) -> list[dict[str, Any]]:
    """
    Add an action to the action history.

    Args:
        state: Current agent state.
        action: Name of the action/tool.
        args: Arguments passed to the action.
        result: Result of the action.
        success: Whether the action succeeded.

    Returns:
        Updated action history list.
    """
    history = state["action_history"].copy()
    history.append({
        "iteration": state["iteration"],
        "action": action,
        "args": args,
        "result": result,  # Store full result
        "success": success,
    })

    # Keep last 50 actions
    if len(history) > 50:
        history = history[-50:]

    return history


def format_action_history(state: AgentState, last_n: int = 10) -> str:
    """
    Format recent action history for inclusion in prompts.

    Args:
        state: Current agent state.
        last_n: Number of recent actions to include.

    Returns:
        Formatted string of recent actions.
    """
    history = state["action_history"][-last_n:]
    if not history:
        return "No actions taken yet."

    lines = ["Recent actions:"]
    for action in history:
        status = "SUCCESS" if action["success"] else "FAILED"
        args_str = ", ".join(f"{k}={repr(v)}" for k, v in action["args"].items())
        lines.append(f"  [{status}] {action['action']}({args_str})")
        # Include result summary to help LLM understand what happened
        result = action.get("result", "")
        if result:
            # Show full result
            result_preview = result.replace('\n', ' ')
            lines.append(f"    Result: {result_preview}")

    return "\n".join(lines)


def check_repeated_failures(state: AgentState, action: str, threshold: int = 3) -> bool:
    """
    Check if an action has repeatedly failed.

    Args:
        state: Current agent state.
        action: Action name to check.
        threshold: Number of failures to consider as repeated.

    Returns:
        True if the action has failed more than threshold times recently.
    """
    recent_actions = state["action_history"][-10:]
    failures = sum(
        1 for a in recent_actions
        if a["action"] == action and not a["success"]
    )
    return failures >= threshold


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
