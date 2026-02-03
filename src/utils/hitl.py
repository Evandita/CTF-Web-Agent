"""Human-in-the-loop utilities for the CTF Web Agent."""

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table

from ..config import get_settings

console = Console()


def request_human_input(reason: str, context: str = "") -> str:
    """
    Request assistance from a human operator.

    Args:
        reason: Why human input is needed.
        context: Additional context to help the human.

    Returns:
        The human's input string.
    """
    settings = get_settings()

    if not settings.hitl_enabled:
        return "HITL disabled - continuing autonomously"

    # Display the reason and context
    content = f"[bold yellow]Reason:[/bold yellow] {reason}"
    if context:
        content += f"\n\n[bold cyan]Context:[/bold cyan]\n{context}"

    panel = Panel(
        content,
        title="[bold red]Human Assistance Requested[/bold red]",
        border_style="red",
        expand=False,
    )
    console.print(panel)

    # Get human input
    response = Prompt.ask("\n[bold green]Your guidance[/bold green]")

    console.print(f"[dim]Received human input: {response}[/dim]\n")

    return response


def confirm_action(action: str, details: str = "") -> bool:
    """
    Request confirmation from a human for an action.

    Args:
        action: The action to be confirmed.
        details: Additional details about the action.

    Returns:
        True if confirmed, False otherwise.
    """
    settings = get_settings()

    if not settings.hitl_enabled:
        return True  # Auto-confirm if HITL is disabled

    # Display the action
    content = f"[bold]Proposed Action:[/bold] {action}"
    if details:
        content += f"\n\n[bold cyan]Details:[/bold cyan]\n{details}"

    panel = Panel(
        content,
        title="[bold yellow]Confirmation Required[/bold yellow]",
        border_style="yellow",
        expand=False,
    )
    console.print(panel)

    # Get confirmation
    return Confirm.ask("[bold]Proceed with this action?[/bold]")


def show_options(options: list[str], prompt: str = "Select an option") -> int:
    """
    Present multiple choices to the human.

    Args:
        options: List of option strings.
        prompt: The prompt to display.

    Returns:
        The index of the selected option (0-based).
    """
    settings = get_settings()

    if not settings.hitl_enabled:
        return 0  # Return first option if HITL is disabled

    # Create options table
    table = Table(title=prompt, show_header=True, header_style="bold cyan")
    table.add_column("#", style="cyan", width=4)
    table.add_column("Option", style="white")

    for i, option in enumerate(options):
        table.add_row(str(i + 1), option)

    console.print(table)

    # Get selection
    while True:
        selection = IntPrompt.ask(
            f"[bold]Enter choice (1-{len(options)})[/bold]",
            default=1,
        )
        if 1 <= selection <= len(options):
            return selection - 1
        console.print(f"[red]Please enter a number between 1 and {len(options)}[/red]")


def display_help_panel(title: str, suggestions: list[str]) -> None:
    """
    Display a help panel with suggestions.

    Args:
        title: The title of the help panel.
        suggestions: List of suggestions to display.
    """
    content = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(suggestions))
    panel = Panel(
        content,
        title=f"[bold blue]{title}[/bold blue]",
        border_style="blue",
        expand=False,
    )
    console.print(panel)


def get_custom_payload(payload_type: str) -> str | None:
    """
    Request a custom payload from the human.

    Args:
        payload_type: The type of payload (e.g., 'sqli', 'xss').

    Returns:
        The custom payload string, or None if cancelled.
    """
    settings = get_settings()

    if not settings.hitl_enabled:
        return None

    console.print(
        f"\n[bold yellow]Enter a custom {payload_type} payload "
        "(or 'skip' to cancel):[/bold yellow]"
    )
    response = Prompt.ask("[bold green]Payload[/bold green]")

    if response.lower() == "skip":
        return None

    return response
