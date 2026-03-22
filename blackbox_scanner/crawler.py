"""
Playwright-based SPA crawler for XSSGuard.
Handles hash routing, interactive element clicks, and AJAX wait.
"""

import logging
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, urlunparse

logger = logging.getLogger(__name__)

# Graceful import: Playwright is optional
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    sync_playwright = None
    PLAYWRIGHT_AVAILABLE = False


class BrowserCrawler:
    """
    Playwright-based crawler for Single Page Applications (SPAs).

    - Handles hash routing: detects and follows #-based routes
    - Clicks interactive elements: buttons, links, nav items
    - Waits for AJAX/network idle after navigation and interactions
    - Returns discovered URLs, forms, and dynamic content
    """

    def __init__(
        self,
        timeout_ms: int = 10000,
        ajax_wait_ms: int = 1500,
        max_pages: int = 50,
        same_domain_only: bool = True,
    ):
        self.timeout_ms = timeout_ms
        self.ajax_wait_ms = ajax_wait_ms
        self.max_pages = max_pages
        self.same_domain_only = same_domain_only

    def crawl(self, url: str) -> Dict[str, Any]:
        """
        Crawl a URL using Playwright. Discovers URLs, forms, and dynamic content.

        Args:
            url: Starting URL to crawl

        Returns:
            Dict with keys: urls, forms, html_snapshots, error (if Playwright unavailable)
        """
        result: Dict[str, Any] = {
            "urls": [],
            "forms": [],
            "html_snapshots": {},
            "error": None,
        }

        if not PLAYWRIGHT_AVAILABLE:
            result["error"] = "Playwright not installed. Install with: pip install playwright"
            logger.warning(result["error"])
            return result

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()

                visited: Set[str] = set()
                to_visit: List[str] = [url]
                base_domain = urlparse(url).netloc

                while to_visit and len(visited) < self.max_pages:
                    current = to_visit.pop(0)
                    if current in visited:
                        continue

                    parsed = urlparse(current)
                    if self.same_domain_only and parsed.netloc != base_domain:
                        continue

                    visited.add(current)
                    logger.debug("SPA crawl: %s", current)

                    try:
                        page.goto(current, timeout=self.timeout_ms, wait_until="networkidle")
                    except Exception as e:
                        logger.debug("Navigation failed for %s: %s", current, e)
                        continue

                    # Wait for AJAX/network idle after load
                    page.wait_for_timeout(self.ajax_wait_ms)

                    html = page.content()
                    result["html_snapshots"][current] = html

                    # Extract links (including hash-based routes)
                    links = self._extract_links(page, current, base_domain)
                    for link in links:
                        if link not in visited and link not in to_visit:
                            to_visit.append(link)

                    # Detect and follow hash routing
                    hash_urls = self._extract_hash_routes(page, current)
                    for h in hash_urls:
                        if h not in visited and h not in to_visit:
                            to_visit.append(h)

                    # Click interactive elements to reveal dynamic content
                    new_urls = self._click_interactive_elements(page, current, base_domain)
                    for nu in new_urls:
                        if nu not in visited and nu not in to_visit:
                            to_visit.append(nu)

                    # Extract forms from current page
                    forms = self._extract_forms(page, current)
                    result["forms"].extend(forms)

                result["urls"] = list(visited)
                browser.close()

        except Exception as e:
            result["error"] = str(e)
            logger.warning("BrowserCrawler error: %s", e)

        return result

    def _extract_links(self, page: Any, base_url: str, base_domain: str) -> List[str]:
        """Extract all links from the page, including hash fragments."""
        try:
            links = page.evaluate("""
                () => {
                    const out = [];
                    for (const a of document.querySelectorAll('a[href]')) {
                        const href = a.getAttribute('href');
                        if (href && href !== '#' && !href.startsWith('javascript:')) {
                            out.push(href);
                        }
                    }
                    return out;
                }
            """)
        except Exception:
            return []

        result = []
        for href in links or []:
            full = urljoin(base_url, href)
            parsed = urlparse(full)
            if self.same_domain_only and parsed.netloc != base_domain:
                continue
            # Normalize: include hash for hash routing
            result.append(full)
        return result

    def _extract_hash_routes(self, page: Any, base_url: str) -> List[str]:
        """
        Detect hash-based routing. Collects links with # fragments
        and builds full URLs for SPA hash routing.
        """
        try:
            hash_fragments = page.evaluate("""
                () => {
                    const out = [];
                    for (const a of document.querySelectorAll('a[href]')) {
                        const href = a.getAttribute('href');
                        if (href && href.includes('#')) {
                            const idx = href.indexOf('#');
                            const fragment = href.slice(idx);
                            if (fragment !== '#') out.push(fragment);
                        }
                    }
                    // Also check for data-* attributes that might hold hash routes
                    for (const el of document.querySelectorAll('[data-route], [data-hash]')) {
                        const r = el.getAttribute('data-route') || el.getAttribute('data-hash');
                        if (r && r.startsWith('#')) out.push(r);
                    }
                    return [...new Set(out)];
                }
            """)
        except Exception:
            return []

        result = []
        parsed = urlparse(base_url)
        base_no_hash = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ""))
        for frag in hash_fragments or []:
            if frag.startswith("#"):
                result.append(base_no_hash + frag)
        return result

    def _click_interactive_elements(
        self, page: Any, current_url: str, base_domain: str
    ) -> List[str]:
        """
        Click buttons, nav links, and other interactive elements to reveal
        dynamic content and new routes.
        """
        discovered: List[str] = []
        selectors = [
            "button:not([disabled])",
            "a[href]",
            "[role='button']",
            "[role='tab']",
            "[role='menuitem']",
            "nav a",
            ".nav-link",
            "[data-toggle]",
        ]

        for selector in selectors:
            try:
                elements = page.query_selector_all(selector)
                for i, el in enumerate(elements[:5]):  # Limit clicks per selector
                    try:
                        href = el.get_attribute("href")
                        if href and "#" in href:
                            parsed = urlparse(current_url)
                            base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ""))
                            frag = href[href.index("#"):]
                            discovered.append(base + frag)
                        el.click(timeout=2000)
                        page.wait_for_timeout(self.ajax_wait_ms)
                        discovered.append(page.url)
                    except Exception:
                        continue
            except Exception:
                continue

        return [u for u in discovered if urlparse(u).netloc == base_domain]

    def _extract_forms(self, page: Any, base_url: str) -> List[Dict[str, Any]]:
        """Extract form metadata from the page."""
        try:
            forms_data = page.evaluate("""
                () => {
                    const out = [];
                    for (const form of document.querySelectorAll('form')) {
                        const action = form.getAttribute('action') || '';
                        const method = (form.getAttribute('method') || 'GET').toUpperCase();
                        const inputs = [];
                        for (const inp of form.querySelectorAll('input, textarea, select')) {
                            const name = inp.getAttribute('name');
                            if (name) inputs.push({ name, type: inp.getAttribute('type') || 'text' });
                        }
                        out.push({ action, method, inputs });
                    }
                    return out;
                }
            """)
        except Exception:
            return []

        result = []
        for fd in forms_data or []:
            action = fd.get("action", "")
            form_url = urljoin(base_url, action) if action else base_url
            result.append({
                "action": form_url,
                "method": fd.get("method", "GET"),
                "inputs": fd.get("inputs", []),
            })
        return result
