"""DOM extraction utilities for extracting page information."""

from typing import Any

from playwright.async_api import Page

from ..utils.logger import log_error


# JavaScript for extracting interactive elements
INTERACTIVE_ELEMENTS_JS = """
() => {
    const elements = document.querySelectorAll(
        'input, button, a, form, select, textarea, [onclick], [role="button"], ' +
        '[type="submit"], [type="button"], [tabindex]'
    );

    const results = [];

    for (const el of elements) {
        // Build a reliable selector
        let selector = '';

        if (el.id) {
            selector = '#' + CSS.escape(el.id);
        } else if (el.name && el.tagName.toLowerCase() !== 'form') {
            selector = `${el.tagName.toLowerCase()}[name="${el.name}"]`;
        } else if (el.getAttribute('data-testid')) {
            selector = `[data-testid="${el.getAttribute('data-testid')}"]`;
        } else if (el.className && typeof el.className === 'string' && el.className.trim()) {
            const classes = el.className.trim().split(/\\s+/).slice(0, 2).join('.');
            selector = `${el.tagName.toLowerCase()}.${classes}`;
        } else {
            // Use tag with index
            const siblings = Array.from(el.parentNode?.children || [])
                .filter(c => c.tagName === el.tagName);
            if (siblings.length > 1) {
                const index = siblings.indexOf(el) + 1;
                selector = `${el.tagName.toLowerCase()}:nth-of-type(${index})`;
            } else {
                selector = el.tagName.toLowerCase();
            }
        }

        // Get text content, truncated
        let text = (el.textContent || '').trim().substring(0, 100);

        // Get href for links
        const href = el.tagName.toLowerCase() === 'a' ? el.getAttribute('href') : null;

        results.push({
            tag: el.tagName.toLowerCase(),
            id: el.id || null,
            name: el.getAttribute('name') || null,
            class: el.className || null,
            type: el.getAttribute('type') || null,
            text: text,
            href: href,
            placeholder: el.getAttribute('placeholder') || null,
            value: el.tagName.toLowerCase() === 'input' ? el.value : null,
            selector: selector,
            role: el.getAttribute('role') || null,
            disabled: el.disabled || false,
            visible: el.offsetParent !== null
        });
    }

    return results;
}
"""

# JavaScript for extracting HTML hints
HTML_HINTS_JS = """
() => {
    const hints = [];

    // Get all comments
    const walker = document.createTreeWalker(
        document,
        NodeFilter.SHOW_COMMENT,
        null,
        false
    );

    while (walker.nextNode()) {
        const comment = walker.currentNode.textContent.trim();
        if (comment) {
            hints.push('Comment: ' + comment);
        }
    }

    // Get hidden inputs
    document.querySelectorAll('input[type="hidden"]').forEach(el => {
        hints.push(`Hidden input: name="${el.name}" value="${el.value}"`);
    });

    // Get data attributes with interesting values
    document.querySelectorAll('[data-flag], [data-secret], [data-token], [data-key]').forEach(el => {
        for (const attr of el.attributes) {
            if (attr.name.startsWith('data-')) {
                hints.push(`Data attribute: ${attr.name}="${attr.value}"`);
            }
        }
    });

    // Check for interesting meta tags
    document.querySelectorAll('meta[name="flag"], meta[name="secret"], meta[name="hint"]').forEach(el => {
        hints.push(`Meta: ${el.getAttribute('name')}="${el.getAttribute('content')}"`);
    });

    // Check for base64 in script tags (could be encoded flags)
    document.querySelectorAll('script').forEach(el => {
        const content = el.textContent || '';
        const b64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/g;
        const matches = content.match(b64Pattern);
        if (matches) {
            matches.slice(0, 3).forEach(m => {
                hints.push(`Possible base64 in script: ${m.substring(0, 50)}...`);
            });
        }
    });

    // Check page title
    if (document.title) {
        hints.push(`Page title: ${document.title}`);
    }

    return hints;
}
"""

# JavaScript for extracting forms
FORMS_JS = """
() => {
    const forms = [];

    document.querySelectorAll('form').forEach((form, index) => {
        const fields = [];

        form.querySelectorAll('input, select, textarea').forEach(el => {
            fields.push({
                tag: el.tagName.toLowerCase(),
                type: el.getAttribute('type') || 'text',
                name: el.getAttribute('name') || null,
                id: el.id || null,
                placeholder: el.getAttribute('placeholder') || null,
                required: el.required || false,
                value: el.value || null
            });
        });

        // Build form selector
        let selector = '';
        if (form.id) {
            selector = '#' + form.id;
        } else if (form.name) {
            selector = `form[name="${form.name}"]`;
        } else if (form.className) {
            selector = `form.${form.className.split(' ')[0]}`;
        } else {
            selector = `form:nth-of-type(${index + 1})`;
        }

        forms.push({
            selector: selector,
            action: form.action || null,
            method: (form.method || 'GET').toUpperCase(),
            id: form.id || null,
            name: form.getAttribute('name') || null,
            fields: fields
        });
    });

    return forms;
}
"""

# JavaScript for extracting links
LINKS_JS = """
() => {
    const links = [];

    document.querySelectorAll('a[href]').forEach(a => {
        const href = a.getAttribute('href');
        // Skip empty or javascript links
        if (!href || href === '#' || href.startsWith('javascript:')) {
            return;
        }

        let selector = '';
        if (a.id) {
            selector = '#' + a.id;
        } else {
            selector = `a[href="${href}"]`;
        }

        links.push({
            href: href,
            text: (a.textContent || '').trim().substring(0, 100),
            selector: selector,
            target: a.getAttribute('target') || null
        });
    });

    return links;
}
"""


async def extract_interactive_elements(page: Page) -> list[dict[str, Any]]:
    """
    Extract all interactive elements from the page.

    Args:
        page: Playwright page instance.

    Returns:
        List of element dictionaries with selectors and properties.
    """
    try:
        elements = await page.evaluate(INTERACTIVE_ELEMENTS_JS)
        # Filter to only visible elements
        visible_elements = [e for e in elements if e.get("visible", True)]
        return visible_elements
    except Exception as e:
        log_error(f"Failed to extract interactive elements: {e}")
        return []


async def extract_html_hints(page: Page) -> list[str]:
    """
    Extract hints from HTML including comments, hidden fields, etc.

    Args:
        page: Playwright page instance.

    Returns:
        List of hint strings found in the HTML.
    """
    try:
        hints = await page.evaluate(HTML_HINTS_JS)
        return hints
    except Exception as e:
        log_error(f"Failed to extract HTML hints: {e}")
        return []


async def extract_forms(page: Page) -> list[dict[str, Any]]:
    """
    Extract detailed form structures from the page.

    Args:
        page: Playwright page instance.

    Returns:
        List of form dictionaries with action, method, and fields.
    """
    try:
        forms = await page.evaluate(FORMS_JS)
        return forms
    except Exception as e:
        log_error(f"Failed to extract forms: {e}")
        return []


async def extract_links(page: Page) -> list[dict[str, Any]]:
    """
    Extract all links from the page.

    Args:
        page: Playwright page instance.

    Returns:
        List of link dictionaries with href and text.
    """
    try:
        links = await page.evaluate(LINKS_JS)
        return links
    except Exception as e:
        log_error(f"Failed to extract links: {e}")
        return []


def build_element_selector(element_info: dict[str, Any]) -> str:
    """
    Build a reliable CSS selector for an element.

    Args:
        element_info: Dictionary with element properties.

    Returns:
        CSS selector string.
    """
    # Prefer ID
    if element_info.get("id"):
        return f"#{element_info['id']}"

    # Then name attribute
    if element_info.get("name"):
        tag = element_info.get("tag", "*")
        return f"{tag}[name=\"{element_info['name']}\"]"

    # Then stored selector
    if element_info.get("selector"):
        return element_info["selector"]

    # Fallback to tag with text
    tag = element_info.get("tag", "*")
    text = element_info.get("text", "")
    if text:
        # Playwright text selector
        return f"{tag}:has-text(\"{text[:30]}\")"

    return tag


async def find_elements_by_text(page: Page, text: str) -> list[dict[str, Any]]:
    """
    Find elements containing specific text.

    Args:
        page: Playwright page instance.
        text: Text to search for.

    Returns:
        List of matching elements with selectors.
    """
    js_code = f"""
    () => {{
        const searchText = "{text}".toLowerCase();
        const results = [];

        const walker = document.createTreeWalker(
            document.body,
            NodeFilter.SHOW_ELEMENT,
            null,
            false
        );

        while (walker.nextNode()) {{
            const el = walker.currentNode;
            const elText = (el.textContent || '').toLowerCase();

            if (elText.includes(searchText)) {{
                // Only include leaf-ish elements
                if (el.children.length <= 3) {{
                    let selector = '';
                    if (el.id) {{
                        selector = '#' + el.id;
                    }} else {{
                        selector = el.tagName.toLowerCase();
                        if (el.className) {{
                            selector += '.' + el.className.split(' ')[0];
                        }}
                    }}

                    results.push({{
                        tag: el.tagName.toLowerCase(),
                        text: el.textContent.trim().substring(0, 100),
                        selector: selector
                    }});
                }}
            }}
        }}

        return results.slice(0, 10);
    }}
    """

    try:
        elements = await page.evaluate(js_code)
        return elements
    except Exception as e:
        log_error(f"Failed to find elements by text: {e}")
        return []


async def get_page_summary(page: Page) -> dict[str, Any]:
    """
    Get a comprehensive summary of the page state.

    Args:
        page: Playwright page instance.

    Returns:
        Dictionary with page summary information.
    """
    summary = {
        "url": page.url,
        "title": await page.title(),
        "interactive_elements": await extract_interactive_elements(page),
        "forms": await extract_forms(page),
        "links": await extract_links(page),
        "hints": await extract_html_hints(page),
    }

    return summary
