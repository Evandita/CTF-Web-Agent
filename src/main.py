"""Main entry point for the CTF Web Agent."""

import asyncio
import argparse
import sys

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .config import get_settings, update_settings
from .models.ollama_client import check_ollama_available
from .browser.controller import BrowserController
from .agent.orchestrator import CTFOrchestrator
from .utils.logger import setup_logging, log_error, log_flag_found, log_action

console = Console()


def print_banner() -> None:
    """Print the application banner."""
    banner = Text()
    banner.append("╔═══════════════════════════════════════════╗\n", style="cyan")
    banner.append("║        CTF Web Agent Solver               ║\n", style="cyan bold")
    banner.append("║   LangChain + Playwright + Ollama         ║\n", style="cyan")
    banner.append("╚═══════════════════════════════════════════╝", style="cyan")
    console.print(banner)
    console.print()


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="CTF Web Challenge Solver - Automated web exploitation using AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ctf-agent http://challenge.ctf.com/login
  ctf-agent http://10.0.0.1:8080/vuln --headless
  ctf-agent http://example.com --max-iterations 50 --text-model llama3.1:70b
        """,
    )

    parser.add_argument(
        "url",
        help="URL of the CTF challenge to solve",
    )

    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run browser in headless mode (no visible window)",
    )

    parser.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        help="Maximum number of iterations before giving up (overrides .env)",
    )

    parser.add_argument(
        "--text-model",
        default=None,
        help="Ollama text model to use for reasoning (overrides .env)",
    )

    parser.add_argument(
        "--vision-model",
        default=None,
        help="Ollama vision model to use for screenshots (overrides .env)",
    )

    parser.add_argument(
        "--no-hitl",
        action="store_true",
        help="Disable human-in-the-loop prompts",
    )

    parser.add_argument(
        "--no-vision",
        action="store_true",
        help="Disable vision model (skip screenshot analysis)",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Timeout in seconds for browser operations (overrides .env)",
    )

    parser.add_argument(
        "--ollama-url",
        default=None,
        help="Ollama server URL (overrides .env)",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    return parser.parse_args()


async def main_async(args: argparse.Namespace) -> int:
    """
    Async main function.

    Args:
        args: Parsed command line arguments.

    Returns:
        Exit code (0 for success, 1 for failure).
    """
    # Print banner
    print_banner()

    # Build settings updates from CLI args (only if explicitly provided)
    settings_updates = {}
    if args.ollama_url is not None:
        settings_updates["ollama_base_url"] = args.ollama_url
    if args.text_model is not None:
        settings_updates["ollama_text_model"] = args.text_model
    if args.vision_model is not None:
        settings_updates["ollama_vision_model"] = args.vision_model
    if args.max_iterations is not None:
        settings_updates["max_iterations"] = args.max_iterations
    if args.timeout is not None:
        settings_updates["timeout_seconds"] = args.timeout
    if args.headless:
        settings_updates["headless"] = True
    if args.no_hitl:
        settings_updates["hitl_enabled"] = False
    if args.no_vision:
        settings_updates["vision_enabled"] = False

    # Update settings only with explicitly provided values
    if settings_updates:
        update_settings(**settings_updates)

    settings = get_settings()

    # Display configuration
    vision_status = f"{settings.ollama_vision_model}" if settings.vision_enabled else "Disabled"
    console.print(Panel(
        f"[bold]Target URL:[/bold] {args.url}\n"
        f"[bold]Text Model:[/bold] {settings.ollama_text_model}\n"
        f"[bold]Vision Model:[/bold] {vision_status}\n"
        f"[bold]Max Iterations:[/bold] {settings.max_iterations}\n"
        f"[bold]Headless:[/bold] {settings.headless}\n"
        f"[bold]HITL Enabled:[/bold] {settings.hitl_enabled}",
        title="Configuration",
        border_style="blue",
    ))
    console.print()

    # Check Ollama availability
    console.print("[cyan]Checking Ollama availability...[/cyan]")
    if not check_ollama_available():
        console.print(Panel(
            "[bold red]Ollama is not available![/bold red]\n\n"
            "Please ensure:\n"
            "1. Ollama is installed and running\n"
            f"2. The server is accessible at {settings.ollama_base_url}\n"
            f"3. Required models are installed:\n"
            f"   - ollama pull {settings.ollama_text_model}\n"
            f"   - ollama pull {settings.ollama_vision_model}",
            title="Error",
            border_style="red",
        ))
        return 1

    console.print("[green]Ollama is available![/green]\n")

    # Create browser controller
    browser = BrowserController()

    # Create orchestrator
    orchestrator = CTFOrchestrator(browser)

    try:
        # Run the solver
        console.print("[cyan]Starting CTF solver...[/cyan]\n")
        result = await orchestrator.solve(args.url)

        # Check results
        flag = result.get("flag_found")
        if flag:
            console.print()
            log_flag_found(flag)
            console.print(Panel(
                f"[bold green]Successfully captured the flag![/bold green]\n\n"
                f"[bold white on green] {flag} [/bold white on green]",
                title="SUCCESS",
                border_style="green",
            ))
            return 0
        else:
            console.print(Panel(
                "[bold yellow]Could not find the flag.[/bold yellow]\n\n"
                f"Iterations used: {result.get('iteration', 0)}/{settings.max_iterations}\n"
                f"Errors encountered: {result.get('error_count', 0)}\n\n"
                "Try:\n"
                "- Increasing max iterations (--max-iterations)\n"
                "- Running with HITL enabled to provide guidance\n"
                "- Checking if the challenge is solvable",
                title="No Flag Found",
                border_style="yellow",
            ))
            return 1

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        return 130

    except Exception as e:
        log_error(f"Fatal error: {e}")
        console.print(Panel(
            f"[bold red]An error occurred:[/bold red]\n\n{e}",
            title="Error",
            border_style="red",
        ))
        if args.verbose:
            console.print_exception()
        return 1


def main() -> None:
    """Main entry point."""
    args = parse_args()

    # Setup logging
    import logging
    level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(level)

    # Run async main
    exit_code = asyncio.run(main_async(args))
    sys.exit(exit_code)


def main_sync() -> None:
    """Synchronous entry point for setuptools."""
    main()


if __name__ == "__main__":
    main()
