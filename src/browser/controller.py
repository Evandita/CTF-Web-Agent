"""Playwright browser controller for web automation."""

import base64
from typing import Any

from playwright.async_api import (
    async_playwright,
    Browser,
    BrowserContext,
    Page,
    Playwright,
    Request,
    Response,
    ConsoleMessage,
)

from ..config import get_settings
from ..utils.logger import log_action, log_error


class BrowserController:
    """Browser controller wrapping Playwright for CTF web automation."""

    def __init__(self):
        """Initialize the browser controller."""
        self.playwright: Playwright | None = None
        self.browser: Browser | None = None
        self.context: BrowserContext | None = None
        self.page: Page | None = None

        # Captured data
        self.network_requests: list[dict[str, Any]] = []
        self.network_responses: list[dict[str, Any]] = []
        self.console_logs: list[str] = []

    async def initialize(self) -> None:
        """Initialize the browser and create a new page."""
        settings = get_settings()

        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=settings.headless,
            slow_mo=settings.slow_mo,
        )
        self.context = await self.browser.new_context(
            viewport={
                "width": settings.viewport_width,
                "height": settings.viewport_height,
            },
            ignore_https_errors=True,
        )
        self.page = await self.context.new_page()

        # Set up event listeners
        self.page.on("request", self._capture_request)
        self.page.on("response", self._capture_response)
        self.page.on("console", self._capture_console)

        log_action("Browser initialized", f"Headless: {settings.headless}")

    async def close(self) -> None:
        """Close the browser and clean up resources."""
        if self.page:
            await self.page.close()
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

        log_action("Browser closed")

    def _capture_request(self, request: Request) -> None:
        """Capture network request data."""
        self.network_requests.append({
            "url": request.url,
            "method": request.method,
            "headers": dict(request.headers),
            "post_data": request.post_data,
        })

    async def _capture_response(self, response: Response) -> None:
        """Capture network response data."""
        try:
            # Try to get response body for text responses
            content_type = response.headers.get("content-type", "")
            body = ""
            if "text" in content_type or "json" in content_type:
                try:
                    body = await response.text()
                except Exception:
                    body = "[Could not read body]"

            self.network_responses.append({
                "url": response.url,
                "status": response.status,
                "headers": dict(response.headers),
                "body": body if body else "",
            })
        except Exception:
            # Ignore errors in response capture
            pass

    def _capture_console(self, msg: ConsoleMessage) -> None:
        """Capture console messages."""
        self.console_logs.append(f"[{msg.type}] {msg.text}")

    def clear_captures(self) -> None:
        """Clear all captured network and console data."""
        self.network_requests.clear()
        self.network_responses.clear()
        self.console_logs.clear()

    async def navigate(self, url: str) -> str:
        """
        Navigate the browser to a URL.

        Args:
            url: The URL to navigate to.

        Returns:
            Status message indicating success or failure.
        """
        if not self.page:
            return "Error: Browser not initialized"

        try:
            settings = get_settings()
            self.clear_captures()

            response = await self.page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=settings.timeout_seconds * 1000,
            )

            status = response.status if response else "unknown"
            current_url = self.page.url

            log_action("Navigate", f"URL: {url}, Status: {status}")
            return f"OK ({status})"

        except Exception as e:
            log_error(f"Navigation failed: {e}")
            return f"Error navigating to {url}: {e}"

    async def click(self, selector: str) -> str:
        """
        Click an element using a CSS selector.

        Args:
            selector: CSS selector or text selector for the element.

        Returns:
            Status message indicating success or failure.
        """
        if not self.page:
            return "Error: Browser not initialized"

        try:
            settings = get_settings()

            await self.page.click(
                selector,
                timeout=settings.timeout_seconds * 1000,
            )

            # Wait for potential navigation or updates
            await self.page.wait_for_load_state("domcontentloaded", timeout=5000)

            log_action("Click", f"Selector: {selector}")
            return "Clicked."

        except Exception as e:
            log_error(f"Click failed: {e}")
            return f"Error clicking {selector}: {e}"

    async def fill(self, selector: str, value: str) -> str:
        """
        Fill an input field with a value.

        Args:
            selector: CSS selector for the input element.
            value: The value to fill.

        Returns:
            Status message indicating success or failure.
        """
        if not self.page:
            return "Error: Browser not initialized"

        try:
            settings = get_settings()

            await self.page.fill(
                selector,
                value,
                timeout=settings.timeout_seconds * 1000,
            )

            log_action("Fill", f"Selector: {selector}, Value: {value}")
            return "Filled."

        except Exception as e:
            log_error(f"Fill failed: {e}")
            return f"Error filling {selector}: {e}"

    async def screenshot(self) -> str:
        """
        Take a screenshot of the current page.

        Returns:
            Base64 encoded PNG screenshot.
        """
        if not self.page:
            return ""

        try:
            screenshot_bytes = await self.page.screenshot(type="png", full_page=False)
            return base64.b64encode(screenshot_bytes).decode("utf-8")
        except Exception as e:
            log_error(f"Screenshot failed: {e}")
            return ""

    async def get_cookies(self) -> list[dict[str, Any]]:
        """
        Get all cookies for the current page.

        Returns:
            List of cookie dictionaries.
        """
        if not self.context:
            return []

        try:
            cookies = await self.context.cookies()
            return cookies
        except Exception as e:
            log_error(f"Get cookies failed: {e}")
            return []

    async def get_local_storage(self) -> dict[str, Any]:
        """
        Get localStorage data from the page.

        Returns:
            Dictionary of localStorage key-value pairs.
        """
        if not self.page:
            return {}

        try:
            storage = await self.page.evaluate("() => Object.assign({}, localStorage)")
            return storage
        except Exception as e:
            log_error(f"Get localStorage failed: {e}")
            return {}

    async def get_page_content(self) -> str:
        """
        Get the full HTML content of the page.

        Returns:
            The page HTML source.
        """
        if not self.page:
            return ""

        try:
            return await self.page.content()
        except Exception as e:
            log_error(f"Get content failed: {e}")
            return ""

    async def execute_js(self, code: str) -> str:
        """
        Execute JavaScript in the page context.

        Args:
            code: JavaScript code to execute.

        Returns:
            String representation of the result.
        """
        if not self.page:
            return "Error: Browser not initialized"

        try:
            result = await self.page.evaluate(code)
            log_action("Execute JS", f"Code: {code}")
            return str(result)
        except Exception as e:
            log_error(f"JS execution failed: {e}")
            return f"Error executing JavaScript: {e}"

    async def go_back(self) -> str:
        """Navigate back in browser history."""
        if not self.page:
            return "Error: Browser not initialized"

        try:
            await self.page.go_back(wait_until="domcontentloaded")
            log_action("Go back", f"Current URL: {self.page.url}")
            return "Back."
        except Exception as e:
            return f"Error going back: {e}"

    async def go_forward(self) -> str:
        """Navigate forward in browser history."""
        if not self.page:
            return "Error: Browser not initialized"

        try:
            await self.page.go_forward(wait_until="domcontentloaded")
            log_action("Go forward", f"Current URL: {self.page.url}")
            return "Forward."
        except Exception as e:
            return f"Error going forward: {e}"

    async def refresh(self) -> str:
        """Refresh the current page."""
        if not self.page:
            return "Error: Browser not initialized"

        try:
            self.clear_captures()
            await self.page.reload(wait_until="domcontentloaded")
            log_action("Refresh", f"Current URL: {self.page.url}")
            return "Refreshed."
        except Exception as e:
            return f"Error refreshing page: {e}"

    async def wait(self, seconds: float) -> str:
        """
        Wait for a specified number of seconds.

        Args:
            seconds: Number of seconds to wait.

        Returns:
            Confirmation message.
        """
        if not self.page:
            return "Error: Browser not initialized"

        try:
            await self.page.wait_for_timeout(seconds * 1000)
            return "OK."
        except Exception as e:
            return f"Error waiting: {e}"

    async def scroll(self, direction: str, amount: int = 500) -> str:
        """
        Scroll the page.

        Args:
            direction: 'up' or 'down'.
            amount: Pixels to scroll.

        Returns:
            Confirmation message.
        """
        if not self.page:
            return "Error: Browser not initialized"

        try:
            if direction.lower() == "down":
                await self.page.evaluate(f"window.scrollBy(0, {amount})")
            else:
                await self.page.evaluate(f"window.scrollBy(0, -{amount})")

            log_action("Scroll", f"Direction: {direction}, Amount: {amount}px")
            return "Scrolled."
        except Exception as e:
            return f"Error scrolling: {e}"

    async def hover(self, selector: str) -> str:
        """
        Hover over an element.

        Args:
            selector: CSS selector for the element.

        Returns:
            Status message.
        """
        if not self.page:
            return "Error: Browser not initialized"

        try:
            settings = get_settings()
            await self.page.hover(selector, timeout=settings.timeout_seconds * 1000)
            log_action("Hover", f"Selector: {selector}")
            return "Hovering."
        except Exception as e:
            return f"Error hovering over {selector}: {e}"

    async def select_option(self, selector: str, value: str) -> str:
        """
        Select an option from a dropdown.

        Args:
            selector: CSS selector for the select element.
            value: Value to select.

        Returns:
            Status message.
        """
        if not self.page:
            return "Error: Browser not initialized"

        try:
            settings = get_settings()
            await self.page.select_option(
                selector,
                value,
                timeout=settings.timeout_seconds * 1000,
            )
            log_action("Select option", f"Selector: {selector}, Value: {value}")
            return "Selected."
        except Exception as e:
            return f"Error selecting option: {e}"

    async def press_key(self, key: str) -> str:
        """
        Press a keyboard key.

        Args:
            key: Key to press (e.g., 'Enter', 'Tab', 'Escape').

        Returns:
            Status message.
        """
        if not self.page:
            return "Error: Browser not initialized"

        try:
            await self.page.keyboard.press(key)
            log_action("Press key", f"Key: {key}")
            return "OK."
        except Exception as e:
            return f"Error pressing key: {e}"

    async def get_element_text(self, selector: str) -> str:
        """
        Get the text content of an element.

        Args:
            selector: CSS selector for the element.

        Returns:
            Text content of the element.
        """
        if not self.page:
            return "Error: Browser not initialized"

        try:
            settings = get_settings()
            element = await self.page.wait_for_selector(
                selector,
                timeout=settings.timeout_seconds * 1000,
            )
            if element:
                text = await element.text_content()
                return text or ""
            return ""
        except Exception as e:
            return f"Error getting text: {e}"

    async def get_attribute(self, selector: str, attribute: str) -> str:
        """
        Get an attribute value from an element.

        Args:
            selector: CSS selector for the element.
            attribute: Attribute name to get.

        Returns:
            Attribute value.
        """
        if not self.page:
            return "Error: Browser not initialized"

        try:
            settings = get_settings()
            element = await self.page.wait_for_selector(
                selector,
                timeout=settings.timeout_seconds * 1000,
            )
            if element:
                value = await element.get_attribute(attribute)
                return value or ""
            return ""
        except Exception as e:
            return f"Error getting attribute: {e}"

    async def wait_for_selector(self, selector: str, timeout: int = 30) -> str:
        """
        Wait for an element to appear on the page.

        Args:
            selector: CSS selector to wait for.
            timeout: Maximum time to wait in seconds.

        Returns:
            Status message.
        """
        if not self.page:
            return "Error: Browser not initialized"

        try:
            await self.page.wait_for_selector(
                selector,
                timeout=timeout * 1000,
            )
            return "Found."
        except Exception as e:
            return f"Timeout waiting for {selector}: {e}"

    async def type_text(self, selector: str, text: str, delay: int = 50) -> str:
        """
        Type text into an element character by character.

        Args:
            selector: CSS selector for the element.
            text: Text to type.
            delay: Delay between keystrokes in milliseconds.

        Returns:
            Status message.
        """
        if not self.page:
            return "Error: Browser not initialized"

        try:
            settings = get_settings()
            await self.page.type(
                selector,
                text,
                delay=delay,
                timeout=settings.timeout_seconds * 1000,
            )
            log_action("Type", f"Selector: {selector}, Text: {text}")
            return "Typed."
        except Exception as e:
            return f"Error typing text: {e}"

    def get_current_url(self) -> str:
        """Get the current page URL."""
        if self.page:
            return self.page.url
        return ""

    def get_network_traffic(self) -> dict[str, list[dict[str, Any]]]:
        """Get captured network traffic."""
        return {
            "requests": self.network_requests.copy(),
            "responses": self.network_responses.copy(),
        }

    def get_console_logs(self) -> list[str]:
        """Get captured console logs."""
        return self.console_logs.copy()
