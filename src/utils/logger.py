"""Rich-based logging utilities for the CTF Web Agent."""

import logging
import json
from datetime import datetime
from pathlib import Path
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

# File logger for full untruncated logs
_file_logger: logging.Logger | None = None
_log_file_path: Path | None = None


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


def setup_file_logging(log_dir: str | Path = "logs") -> Path:
    """
    Setup file logging that captures all information without truncation.

    Args:
        log_dir: Directory to store log files.

    Returns:
        Path to the created log file.
    """
    global _file_logger, _log_file_path

    # Create logs directory
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    # Create timestamped log file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    _log_file_path = log_path / f"ctf_agent_{timestamp}.log"

    # Setup file logger
    _file_logger = logging.getLogger("ctf-agent-file")
    _file_logger.setLevel(logging.DEBUG)

    # Remove existing handlers
    _file_logger.handlers.clear()

    # Add file handler
    file_handler = logging.FileHandler(_log_file_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    _file_logger.addHandler(file_handler)

    # Log initial message
    _file_logger.info(f"=== CTF Web Agent Log Started ===")
    _file_logger.info(f"Log file: {_log_file_path}")

    return _log_file_path


def get_log_file_path() -> Path | None:
    """Get the current log file path."""
    return _log_file_path


def _log_to_file(level: str, category: str, message: str, data: dict | None = None) -> None:
    """
    Write a log entry to the file logger with full content (no truncation).

    Args:
        level: Log level (INFO, DEBUG, ERROR, etc.)
        category: Category of the log (ACTION, OBSERVATION, THINKING, etc.)
        message: The log message
        data: Optional additional data to log
    """
    if _file_logger is None:
        return

    log_entry = f"[{category}] {message}"

    if data:
        # Log data as JSON for easy parsing
        try:
            data_str = json.dumps(data, indent=2, default=str)
            log_entry += f"\n  DATA: {data_str}"
        except Exception:
            log_entry += f"\n  DATA: {str(data)}"

    log_func = getattr(_file_logger, level.lower(), _file_logger.info)
    log_func(log_entry)


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

    # Log to file (untruncated)
    _log_to_file("INFO", "ACTION", action, {"details": details} if details else None)


def log_observation(observation: str) -> None:
    """Log an observation from the environment (green panel)."""
    panel = Panel(
        observation,
        title="[bold green]Observation[/bold green]",
        border_style="green",
        expand=False,
    )
    console.print(panel)

    # Log to file (untruncated)
    _log_to_file("INFO", "OBSERVATION", observation)


def log_thinking(thought: str) -> None:
    """Log agent reasoning/thinking (yellow panel)."""
    panel = Panel(
        thought,
        title="[bold yellow]Thinking[/bold yellow]",
        border_style="yellow",
        expand=False,
    )
    console.print(panel)

    # Log to file
    _log_to_file("INFO", "THINKING", thought)


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

    # Log to file (untruncated)
    _log_to_file("INFO", "FLAG_FOUND", f"FLAG CAPTURED: {flag}")


def log_error(error: str) -> None:
    """Log an error (red panel)."""
    panel = Panel(
        error,
        title="[bold red]Error[/bold red]",
        border_style="red",
        expand=False,
    )
    console.print(panel)

    # Log to file
    _log_to_file("ERROR", "ERROR", error)


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
            display_value = str(value)
        elif isinstance(value, dict):
            display_value = str(value)
        else:
            display_value = str(value)

        table.add_row(key, display_value)

    console.print(table)

    # Log full state to file (excluding screenshot_b64 for size)
    file_state = {k: v for k, v in state.items() if k != "screenshot_b64"}
    _log_to_file("INFO", "STATE", "Agent state snapshot", file_state)


def log_iteration(iteration: int, max_iterations: int) -> None:
    """Log the current iteration number."""
    console.print(
        f"\n[bold cyan]--- Iteration {iteration}/{max_iterations} ---[/bold cyan]\n"
    )

    # Log to file
    _log_to_file("INFO", "ITERATION", f"Iteration {iteration}/{max_iterations}")


def log_tool_call(tool_name: str, args: dict[str, Any]) -> None:
    """Log a tool call being made."""
    args_str = ", ".join(f"{k}={repr(v)}" for k, v in args.items())
    console.print(f"[dim]Calling tool: [bold]{tool_name}[/bold]({args_str})[/dim]")

    # Log full args to file (untruncated)
    _log_to_file("INFO", "TOOL_CALL", f"Calling tool: {tool_name}", {"args": args})


def log_tool_result(tool_name: str, result: str) -> None:
    """Log a tool result."""
    console.print(f"[dim]Tool result from {tool_name}: {result}[/dim]")

    # Log full result to file
    _log_to_file("INFO", "TOOL_RESULT", f"Tool result from {tool_name}", {"result": result})


def log_markdown(content: str) -> None:
    """Log markdown content."""
    md = Markdown(content)
    console.print(md)


def log_separator() -> None:
    """Print a visual separator."""
    console.print("[dim]" + "-" * 60 + "[/dim]")
