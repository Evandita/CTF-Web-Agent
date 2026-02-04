"""DOM extraction utilities for extracting page information.

Enhanced with patterns from browser-use for better interactivity detection:
- ARIA roles and properties for semantic interactivity
- Cursor:pointer detection (indicates clickability)
- Search element pattern detection
- Form control wrappers (labels, spans in React/Vue)
- CSS-based visibility checking (display, visibility, opacity)
- Better selector generation with multiple fallback strategies

CTF-specific features preserved:
- Hidden element extraction (important for CTF challenges)
- HTML comment detection
- Base64 pattern detection in scripts
- Data attribute extraction for flags/secrets
"""

from typing import Any

from playwright.async_api import Page

from ..utils.logger import log_error


# Enhanced JavaScript for extracting interactive elements
# Based on browser-use's ClickableElementDetector patterns
INTERACTIVE_ELEMENTS_JS = """
() => {
    const results = [];
    const processedElements = new Set();

    // Interactive ARIA roles (from browser-use ClickableElementDetector)
    const INTERACTIVE_ROLES = new Set([
        'button', 'link', 'menuitem', 'option', 'radio', 'checkbox',
        'tab', 'textbox', 'combobox', 'slider', 'spinbutton', 'search',
        'searchbox', 'row', 'cell', 'gridcell', 'listbox', 'menu',
        'menubar', 'menuitemcheckbox', 'menuitemradio', 'switch', 'treeitem'
    ]);

    // Tags that are inherently interactive
    const INTERACTIVE_TAGS = new Set([
        'button', 'input', 'select', 'textarea', 'a', 'details',
        'summary', 'option', 'optgroup', 'form'
    ]);

    // Search-related class/id patterns (from browser-use)
    const SEARCH_PATTERNS = [
        'search', 'magnify', 'glass', 'lookup', 'find', 'query',
        'search-icon', 'search-btn', 'search-button', 'searchbox'
    ];

    // Build a reliable selector with multiple fallback strategies
    function buildSelector(el) {
        const tag = el.tagName.toLowerCase();

        // 1. ID (most reliable)
        if (el.id) {
            return '#' + CSS.escape(el.id);
        }

        // 2. Testing attributes (data-testid, data-test, data-cy)
        const testAttrs = ['data-testid', 'data-test', 'data-cy', 'data-selenium'];
        for (const attr of testAttrs) {
            const val = el.getAttribute(attr);
            if (val) return `[${attr}="${CSS.escape(val)}"]`;
        }

        // 3. Name attribute (for form elements)
        if (el.name && tag !== 'form') {
            return `${tag}[name="${CSS.escape(el.name)}"]`;
        }

        // 4. Aria-label (accessibility)
        const ariaLabel = el.getAttribute('aria-label');
        if (ariaLabel && ariaLabel.length < 50) {
            return `[aria-label="${CSS.escape(ariaLabel)}"]`;
        }

        // 5. Href for links (if unique enough)
        if (tag === 'a') {
            const href = el.getAttribute('href');
            if (href && href !== '#' && !href.startsWith('javascript:') && href.length < 100) {
                const selector = `a[href="${CSS.escape(href)}"]`;
                try {
                    if (document.querySelectorAll(selector).length === 1) {
                        return selector;
                    }
                } catch (e) {}
            }
        }

        // 6. Unique class combination
        if (el.className && typeof el.className === 'string' && el.className.trim()) {
            const classes = el.className.trim().split(/\\s+/).filter(c => c.length > 0).slice(0, 2);
            if (classes.length > 0) {
                const selector = `${tag}.${classes.map(c => CSS.escape(c)).join('.')}`;
                try {
                    if (document.querySelectorAll(selector).length === 1) {
                        return selector;
                    }
                } catch (e) {}
            }
        }

        // 7. Type attribute for inputs
        if (tag === 'input') {
            const type = el.getAttribute('type') || 'text';
            const placeholder = el.getAttribute('placeholder');
            if (placeholder) {
                const selector = `input[type="${type}"][placeholder="${CSS.escape(placeholder)}"]`;
                try {
                    if (document.querySelectorAll(selector).length === 1) {
                        return selector;
                    }
                } catch (e) {}
            }
        }

        // 8. Nth-of-type fallback with parent context
        const parent = el.parentNode;
        if (parent) {
            const siblings = Array.from(parent.children).filter(c => c.tagName === el.tagName);
            if (siblings.length > 1) {
                const index = siblings.indexOf(el) + 1;
                return `${tag}:nth-of-type(${index})`;
            }
        }

        return tag;
    }

    // Check visibility using computed styles (browser-use pattern)
    function checkVisibility(el) {
        // Check offsetParent first (handles display:none on ancestors)
        const hasOffsetParent = el.offsetParent !== null;

        // Fixed/sticky positioned elements may have null offsetParent but still be visible
        let isPositionedException = false;
        try {
            const style = window.getComputedStyle(el);
            isPositionedException = (style.position === 'fixed' || style.position === 'sticky');
        } catch (e) {}

        if (!hasOffsetParent && !isPositionedException && el.tagName.toLowerCase() !== 'body') {
            return { visible: false, reason: 'no_offset_parent' };
        }

        // Check computed styles
        try {
            const style = window.getComputedStyle(el);

            if (style.display === 'none') {
                return { visible: false, reason: 'display_none' };
            }
            if (style.visibility === 'hidden') {
                return { visible: false, reason: 'visibility_hidden' };
            }
            if (parseFloat(style.opacity) <= 0) {
                return { visible: false, reason: 'opacity_zero' };
            }
        } catch (e) {}

        // Check bounding rect (0x0 elements are typically hidden but may be important in CTF)
        const rect = el.getBoundingClientRect();
        if (rect.width === 0 && rect.height === 0) {
            return { visible: false, reason: 'zero_size' };
        }

        return { visible: true, reason: null };
    }

    // Check if element has search-related indicators (browser-use pattern)
    function hasSearchIndicators(el) {
        const classList = (el.className || '').toLowerCase();
        const id = (el.id || '').toLowerCase();

        for (const pattern of SEARCH_PATTERNS) {
            if (classList.includes(pattern) || id.includes(pattern)) {
                return true;
            }
        }

        // Check data attributes
        for (const attr of el.attributes) {
            if (attr.name.startsWith('data-')) {
                const val = attr.value.toLowerCase();
                for (const pattern of SEARCH_PATTERNS) {
                    if (val.includes(pattern)) return true;
                }
            }
        }

        return false;
    }

    // Check if element has form controls as descendants (for labels/spans)
    function hasFormControlDescendant(el, maxDepth = 2) {
        if (maxDepth <= 0) return false;

        for (const child of el.children) {
            const tag = child.tagName.toLowerCase();
            if (tag === 'input' || tag === 'select' || tag === 'textarea') {
                return true;
            }
            if (hasFormControlDescendant(child, maxDepth - 1)) {
                return true;
            }
        }
        return false;
    }

    // Determine if element is interactive (based on browser-use ClickableElementDetector)
    function getInteractivity(el) {
        const tag = el.tagName.toLowerCase();

        // Skip non-content elements
        if (['html', 'head', 'script', 'style', 'meta', 'link', 'title', 'noscript', 'br', 'hr'].includes(tag)) {
            return { interactive: false, reason: null };
        }

        // Check disabled/hidden states
        if (el.disabled) {
            return { interactive: false, reason: 'disabled' };
        }
        if (el.getAttribute('aria-disabled') === 'true') {
            return { interactive: false, reason: 'aria_disabled' };
        }

        // 1. Inherently interactive tags
        if (INTERACTIVE_TAGS.has(tag)) {
            return { interactive: true, reason: 'interactive_tag' };
        }

        // 2. Interactive ARIA roles
        const role = el.getAttribute('role');
        if (role && INTERACTIVE_ROLES.has(role.toLowerCase())) {
            return { interactive: true, reason: 'aria_role:' + role };
        }

        // 3. Event handler attributes
        const eventAttrs = ['onclick', 'onmousedown', 'onmouseup', 'onkeydown', 'onkeyup', 'ontouchstart', 'onsubmit'];
        for (const attr of eventAttrs) {
            if (el.hasAttribute(attr)) {
                return { interactive: true, reason: 'event_handler:' + attr };
            }
        }

        // 4. Tabindex (focusable elements)
        const tabindex = el.getAttribute('tabindex');
        if (tabindex !== null && tabindex !== '-1') {
            return { interactive: true, reason: 'tabindex' };
        }

        // 5. Cursor pointer (browser-use: cursor style indicates interactivity)
        try {
            const style = window.getComputedStyle(el);
            if (style.cursor === 'pointer') {
                return { interactive: true, reason: 'cursor_pointer' };
            }
        } catch (e) {}

        // 6. Search element detection (browser-use pattern)
        if (hasSearchIndicators(el)) {
            return { interactive: true, reason: 'search_element' };
        }

        // 7. Labels that wrap form controls (browser-use pattern)
        if (tag === 'label') {
            if (!el.getAttribute('for') && hasFormControlDescendant(el, 2)) {
                return { interactive: true, reason: 'label_wrapper' };
            }
        }

        // 8. Contenteditable elements
        if (el.getAttribute('contenteditable') === 'true') {
            return { interactive: true, reason: 'contenteditable' };
        }

        // 9. Elements with draggable attribute
        if (el.getAttribute('draggable') === 'true') {
            return { interactive: true, reason: 'draggable' };
        }

        return { interactive: false, reason: null };
    }

    // Get text content intelligently
    function getTextContent(el) {
        const tag = el.tagName.toLowerCase();

        // For inputs, prefer placeholder or aria-label
        if (tag === 'input' || tag === 'textarea') {
            return el.placeholder || el.getAttribute('aria-label') || el.value || '';
        }

        // For buttons/links, get direct text
        if (tag === 'button' || tag === 'a' || tag === 'label' || tag === 'summary') {
            return (el.textContent || '').trim().substring(0, 100);
        }

        // For other elements, prefer direct child text nodes
        let directText = '';
        for (const node of el.childNodes) {
            if (node.nodeType === Node.TEXT_NODE) {
                directText += node.textContent.trim() + ' ';
            }
        }
        directText = directText.trim();

        if (directText) {
            return directText.substring(0, 100);
        }

        return (el.textContent || '').trim().substring(0, 100);
    }

    // Process an element
    function processElement(el) {
        if (processedElements.has(el)) return;
        processedElements.add(el);

        const interactivity = getInteractivity(el);
        if (!interactivity.interactive) return;

        const tag = el.tagName.toLowerCase();
        const visibility = checkVisibility(el);
        const rect = el.getBoundingClientRect();

        results.push({
            tag: tag,
            id: el.id || null,
            name: el.getAttribute('name') || null,
            class: (typeof el.className === 'string') ? el.className : null,
            type: el.getAttribute('type') || null,
            text: getTextContent(el),
            href: tag === 'a' ? el.getAttribute('href') : null,
            placeholder: el.getAttribute('placeholder') || null,
            value: (tag === 'input' || tag === 'textarea' || tag === 'select') ? el.value : null,
            selector: buildSelector(el),
            role: el.getAttribute('role') || null,
            ariaLabel: el.getAttribute('aria-label') || null,
            disabled: el.disabled || false,
            visible: visibility.visible,
            visibilityReason: visibility.reason,
            interactiveReason: interactivity.reason,
            bounds: {
                x: Math.round(rect.x),
                y: Math.round(rect.y),
                width: Math.round(rect.width),
                height: Math.round(rect.height)
            }
        });
    }

    // Walk the DOM tree
    const walker = document.createTreeWalker(
        document.body || document.documentElement,
        NodeFilter.SHOW_ELEMENT,
        null,
        false
    );

    while (walker.nextNode()) {
        processElement(walker.currentNode);
    }

    // Also check shadow DOMs (important for modern web apps)
    function processShadowRoots(root) {
        const elements = root.querySelectorAll('*');
        for (const el of elements) {
            processElement(el);
            if (el.shadowRoot) {
                processShadowRoots(el.shadowRoot);
            }
        }
    }

    document.querySelectorAll('*').forEach(el => {
        if (el.shadowRoot) {
            processShadowRoots(el.shadowRoot);
        }
    });

    return results;
}
"""

# Enhanced JavaScript for extracting HTML hints (CTF-focused)
HTML_HINTS_JS = """
() => {
    const hints = [];
    const seen = new Set();  // Deduplicate hints

    function addHint(hint) {
        if (hint && !seen.has(hint)) {
            seen.add(hint);
            hints.push(hint);
        }
    }

    // 1. HTML Comments (often contain flags, hints, or debug info)
    const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT, null, false);
    while (walker.nextNode()) {
        const c = walker.currentNode.textContent.trim();
        if (c) {
            // Truncate long comments but preserve flag-like patterns
            const flagMatch = c.match(/[a-zA-Z0-9_]+\\{[^}]+\\}/);
            if (flagMatch) {
                addHint('<!--FLAG:' + flagMatch[0] + '-->');
            } else {
                addHint('<!--' + c.substring(0, 150) + (c.length > 150 ? '...' : '') + '-->');
            }
        }
    }

    // 2. Hidden inputs (common in CTF for hidden flags or tokens)
    document.querySelectorAll('input[type="hidden"]').forEach(el => {
        const name = el.name || el.id || 'unnamed';
        const value = el.value || '';
        addHint(`hidden_input:${name}=${value.substring(0, 100)}`);
    });

    // 3. Disabled inputs (may contain hints)
    document.querySelectorAll('input[disabled], textarea[disabled], select[disabled]').forEach(el => {
        const name = el.name || el.id || 'unnamed';
        const value = el.value || '';
        if (value) {
            addHint(`disabled_input:${name}=${value.substring(0, 100)}`);
        }
    });

    // 4. Data attributes with interesting names
    const interestingDataAttrs = [
        'data-flag', 'data-secret', 'data-token', 'data-key', 'data-password',
        'data-hint', 'data-answer', 'data-code', 'data-hash', 'data-admin',
        'data-debug', 'data-test', 'data-hidden', 'data-value', 'data-id'
    ];

    document.querySelectorAll('*').forEach(el => {
        for (const attr of el.attributes) {
            if (attr.name.startsWith('data-')) {
                // Check if it's an interesting attribute or has interesting value
                const isInteresting = interestingDataAttrs.some(a => attr.name.includes(a.replace('data-', '')));
                const hasInterestingValue = attr.value && (
                    attr.value.match(/[a-zA-Z0-9_]+\\{[^}]+\\}/) ||  // Flag pattern
                    attr.value.match(/^[A-Za-z0-9+/]{20,}={0,2}$/) ||  // Base64
                    attr.value.match(/^[a-f0-9]{32,}$/i)  // Hash
                );

                if (isInteresting || hasInterestingValue) {
                    addHint(`${attr.name}=${attr.value.substring(0, 100)}`);
                }
            }
        }
    });

    // 5. Meta tags (all of them, not just specific ones)
    document.querySelectorAll('meta[name], meta[property]').forEach(el => {
        const name = el.getAttribute('name') || el.getAttribute('property');
        const content = el.getAttribute('content');
        if (name && content) {
            // Prioritize interesting meta tags
            const interesting = ['flag', 'secret', 'hint', 'author', 'generator', 'debug', 'admin', 'token'];
            if (interesting.some(i => name.toLowerCase().includes(i)) || content.match(/[a-zA-Z0-9_]+\\{[^}]+\\}/)) {
                addHint(`meta:${name}=${content.substring(0, 100)}`);
            }
        }
    });

    // 6. Script content analysis (Base64, flags, interesting strings)
    document.querySelectorAll('script:not([src])').forEach(el => {
        const content = el.textContent || '';

        // Look for flag patterns
        const flags = content.match(/[a-zA-Z0-9_]+\\{[^}]{1,100}\\}/g);
        if (flags) {
            flags.slice(0, 3).forEach(f => addHint(`script_flag:${f}`));
        }

        // Look for Base64 strings (potential encoded data)
        const b64 = content.match(/["'][A-Za-z0-9+/]{30,}={0,2}["']/g);
        if (b64) {
            b64.slice(0, 2).forEach(m => {
                const clean = m.replace(/["']/g, '');
                addHint(`script_b64:${clean.substring(0, 60)}...`);
            });
        }

        // Look for password/secret variable assignments
        const secrets = content.match(/(password|secret|flag|token|key|admin)\\s*[:=]\\s*["'][^"']{1,50}["']/gi);
        if (secrets) {
            secrets.slice(0, 3).forEach(s => addHint(`script_secret:${s}`));
        }

        // Look for API endpoints or interesting URLs
        const urls = content.match(/["']\\/(?:api|admin|flag|secret|hidden|debug|backup)[^"']*["']/gi);
        if (urls) {
            urls.slice(0, 3).forEach(u => addHint(`script_url:${u.replace(/["']/g, '')}`));
        }
    });

    // 7. Elements with suspicious styling (hidden but present)
    document.querySelectorAll('[style*="display:none"], [style*="display: none"], [style*="visibility:hidden"], [style*="visibility: hidden"]').forEach(el => {
        const text = el.textContent?.trim();
        if (text && text.length < 200) {
            // Check if it contains flag-like content
            if (text.match(/[a-zA-Z0-9_]+\\{[^}]+\\}/) || text.match(/flag|secret|password|admin/i)) {
                addHint(`hidden_element:${text.substring(0, 100)}`);
            }
        }
    });

    // 8. Noscript tags (sometimes hide content for non-JS users)
    document.querySelectorAll('noscript').forEach(el => {
        const content = el.textContent?.trim();
        if (content && content.match(/[a-zA-Z0-9_]+\\{[^}]+\\}/)) {
            addHint(`noscript:${content.substring(0, 100)}`);
        }
    });

    // 9. Template tags (may contain hidden content)
    document.querySelectorAll('template').forEach(el => {
        const content = el.innerHTML?.trim();
        if (content && content.length < 500) {
            const flagMatch = content.match(/[a-zA-Z0-9_]+\\{[^}]+\\}/);
            if (flagMatch) {
                addHint(`template:${flagMatch[0]}`);
            }
        }
    });

    // 10. Source code comments in CSS
    document.querySelectorAll('style').forEach(el => {
        const content = el.textContent || '';
        const comments = content.match(/\\/\\*[^*]*\\*+(?:[^/*][^*]*\\*+)*\\//g);
        if (comments) {
            comments.forEach(c => {
                const clean = c.replace(/\\/\\*|\\*\\//g, '').trim();
                if (clean) {
                    addHint(`css_comment:${clean.substring(0, 80)}`);
                }
            });
        }
    });

    // 11. Check for interesting link targets
    document.querySelectorAll('a[href]').forEach(el => {
        const href = el.getAttribute('href') || '';
        const interesting = ['/admin', '/flag', '/secret', '/debug', '/backup', '/hidden', '/.git', '/.env', '/config'];
        if (interesting.some(i => href.includes(i))) {
            addHint(`interesting_link:${href}`);
        }
    });

    // 12. Forms with interesting actions
    document.querySelectorAll('form[action]').forEach(el => {
        const action = el.getAttribute('action') || '';
        if (action && !action.startsWith('#')) {
            const method = (el.getAttribute('method') || 'GET').toUpperCase();
            addHint(`form_action:${method} ${action}`);
        }
    });

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
    Extract all interactive elements from the page using enhanced detection.

    Uses browser-use inspired patterns for detecting interactivity:
    - ARIA roles (button, link, menuitem, checkbox, etc.)
    - Cursor:pointer style
    - Event handler attributes
    - Search element patterns
    - Form control wrappers

    Args:
        page: Playwright page instance.

    Returns:
        List of element dictionaries with selectors and properties.
        Each element includes:
        - tag, id, name, class, type, text, href, placeholder, value
        - selector: CSS selector for the element
        - role: ARIA role if present
        - ariaLabel: aria-label if present
        - disabled: whether element is disabled
        - visible: CSS visibility status
        - visibilityReason: why element is hidden (if hidden)
        - interactiveReason: why element was detected as interactive
        - bounds: {x, y, width, height}
    """
    try:
        elements = await page.evaluate(INTERACTIVE_ELEMENTS_JS)

        # Sort elements: visible first, then by position (top to bottom, left to right)
        def sort_key(el):
            visible = 0 if el.get('visible', True) else 1
            bounds = el.get('bounds', {})
            y = bounds.get('y', 9999)
            x = bounds.get('x', 9999)
            return (visible, y, x)

        elements.sort(key=sort_key)

        return elements
    except Exception as e:
        log_error(f"Failed to extract interactive elements: {e}")
        return []


async def extract_interactive_elements_summary(page: Page) -> str:
    """
    Extract interactive elements and format as a concise summary for LLM.

    Args:
        page: Playwright page instance.

    Returns:
        Formatted string summarizing interactive elements.
    """
    elements = await extract_interactive_elements(page)

    if not elements:
        return "No interactive elements found."

    lines = []
    visible_count = 0
    hidden_count = 0

    for i, el in enumerate(elements):
        is_visible = el.get('visible', True)
        if is_visible:
            visible_count += 1
        else:
            hidden_count += 1

        # Build concise element description
        tag = el.get('tag', '?')
        selector = el.get('selector', '')
        text = el.get('text', '')[:50]
        el_type = el.get('type', '')
        role = el.get('role', '')
        reason = el.get('interactiveReason', '')

        # Format: [V/H] tag#id.class "text" (type) [role] -> selector | reason
        visibility = 'V' if is_visible else 'H'
        parts = [f"[{visibility}]", tag]

        if el.get('id'):
            parts.append(f"#{el['id']}")
        elif el.get('name'):
            parts.append(f"[name={el['name']}]")

        if text:
            parts.append(f'"{text}"')
        if el_type:
            parts.append(f"({el_type})")
        if role:
            parts.append(f"[{role}]")

        parts.append(f"-> {selector}")

        if reason and reason not in ['interactive_tag']:
            parts.append(f"| {reason}")

        lines.append(' '.join(parts))

    summary = f"Found {len(elements)} interactive elements ({visible_count} visible, {hidden_count} hidden):\n"
    summary += '\n'.join(lines[:50])  # Limit to 50 elements

    if len(elements) > 50:
        summary += f"\n... and {len(elements) - 50} more elements"

    return summary


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
        return f"{tag}:has-text(\"{text}\")"

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


async def get_page_state_for_llm(page: Page) -> str:
    """
    Get a formatted page state optimized for LLM consumption.

    This provides a concise but comprehensive view of the page that's
    suitable for including in an LLM prompt.

    Args:
        page: Playwright page instance.

    Returns:
        Formatted string with page state.
    """
    parts = []

    # Basic info
    parts.append(f"URL: {page.url}")
    try:
        title = await page.title()
        if title:
            parts.append(f"Title: {title}")
    except Exception:
        pass

    # Interactive elements summary
    parts.append("\n## Interactive Elements")
    elements_summary = await extract_interactive_elements_summary(page)
    parts.append(elements_summary)

    # Forms
    forms = await extract_forms(page)
    if forms:
        parts.append(f"\n## Forms ({len(forms)} found)")
        for form in forms[:5]:
            action = form.get('action', 'none')
            method = form.get('method', 'GET')
            selector = form.get('selector', '')
            fields = form.get('fields', [])
            field_names = [f.get('name') or f.get('type', 'unnamed') for f in fields[:5]]
            parts.append(f"  {method} {action} ({selector}): {', '.join(field_names)}")

    # Hints (CTF-specific)
    hints = await extract_html_hints(page)
    if hints:
        parts.append(f"\n## HTML Hints ({len(hints)} found)")
        for hint in hints[:20]:
            parts.append(f"  {hint}")
        if len(hints) > 20:
            parts.append(f"  ... and {len(hints) - 20} more hints")

    return '\n'.join(parts)


async def extract_all_text_content(page: Page) -> str:
    """
    Extract all visible text content from the page.

    Useful for searching for flags or hints in page content.

    Args:
        page: Playwright page instance.

    Returns:
        All visible text content concatenated.
    """
    try:
        text = await page.evaluate("""
        () => {
            // Get all text from body, excluding scripts and styles
            const body = document.body;
            if (!body) return '';

            const clone = body.cloneNode(true);

            // Remove script and style elements
            clone.querySelectorAll('script, style, noscript').forEach(el => el.remove());

            return clone.textContent || '';
        }
        """)
        # Clean up whitespace
        import re
        text = re.sub(r'\s+', ' ', text).strip()
        return text
    except Exception as e:
        log_error(f"Failed to extract text content: {e}")
        return ""
