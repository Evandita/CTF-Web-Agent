"""Rich-based logging utilities for the CTF Web Agent."""

import logging
from typing import Any

from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.markdown import Markdown

# Global console instance
console = Console()

# Logger instance
logger = logging.getLogger("ctf-agent")


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure Rich-based logging."""
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
    )
    logger.setLevel(level)
    return logger


def log_action(action: str, details: str = "") -> None:
    """Log an action taken by the agent (blue panel)."""
    content = f"[bold]{action}[/bold]"
    if details:
        content += f"\n{details}"
    panel = Panel(
        content,
        title="[bold blue]Action[/bold blue]",
        border_style="blue",
        expand=False,
    )
    console.print(panel)


def log_observation(observation: str) -> None:
    """Log an observation from the environment (green panel)."""
    panel = Panel(
        observation,
        title="[bold green]Observation[/bold green]",
        border_style="green",
        expand=False,
    )
    console.print(panel)


def log_thinking(thought: str) -> None:
    """Log agent reasoning/thinking (yellow panel)."""
    panel = Panel(
        thought,
        title="[bold yellow]Thinking[/bold yellow]",
        border_style="yellow",
        expand=False,
    )
    console.print(panel)


def log_flag_found(flag: str) -> None:
    """Log when a flag is found (celebratory green panel)."""
    content = Text()
    content.append("FLAG CAPTURED!\n\n", style="bold green")
    content.append(flag, style="bold white on green")
    panel = Panel(
        content,
        title="[bold green]SUCCESS[/bold green]",
        border_style="green",
        expand=False,
        padding=(1, 2),
    )
    console.print(panel)


def log_error(error: str) -> None:
    """Log an error (red panel)."""
    panel = Panel(
        error,
        title="[bold red]Error[/bold red]",
        border_style="red",
        expand=False,
    )
    console.print(panel)


def log_state(state: dict[str, Any]) -> None:
    """Log the current agent state as a table (excludes screenshot_b64)."""
    table = Table(title="Agent State", show_header=True, header_style="bold cyan")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    # Fields to exclude from display
    exclude_fields = {"screenshot_b64", "messages"}

    for key, value in state.items():
        if key in exclude_fields:
            continue

        # Format the value for display
        if isinstance(value, list):
            if len(value) > 3:
                display_value = f"[{len(value)} items]"
            else:
                display_value = str(value)[:100]
        elif isinstance(value, dict):
            if len(value) > 3:
                display_value = f"{{{len(value)} keys}}"
            else:
                display_value = str(value)[:100]
        elif isinstance(value, str) and len(value) > 100:
            display_value = value[:100] + "..."
        else:
            display_value = str(value)

        table.add_row(key, display_value)

    console.print(table)


def log_iteration(iteration: int, max_iterations: int) -> None:
    """Log the current iteration number."""
    console.print(
        f"\n[bold cyan]--- Iteration {iteration}/{max_iterations} ---[/bold cyan]\n"
    )


def log_tool_call(tool_name: str, args: dict[str, Any]) -> None:
    """Log a tool call being made."""
    args_str = ", ".join(f"{k}={repr(v)[:50]}" for k, v in args.items())
    console.print(f"[dim]Calling tool: [bold]{tool_name}[/bold]({args_str})[/dim]")


def log_tool_result(tool_name: str, result: str) -> None:
    """Log a tool result."""
    truncated = result[:200] + "..." if len(result) > 200 else result
    console.print(f"[dim]Tool result from {tool_name}: {truncated}[/dim]")


def log_markdown(content: str) -> None:
    """Log markdown content."""
    md = Markdown(content)
    console.print(md)


def log_separator() -> None:
    """Print a visual separator."""
    console.print("[dim]" + "-" * 60 + "[/dim]")
