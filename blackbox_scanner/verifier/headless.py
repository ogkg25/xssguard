"""
Headless Browser Verifier for XSS Execution Confirmation.
Provides high-confidence verification using Playwright.
Includes DOM XSS detection via fragment injection and MutationObserver.
"""

import time
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlunparse


class HeadlessVerifier:
    """
    Verifies XSS payload execution using a headless browser.

    Provides high-confidence confirmation that a reflected
    payload actually executes in a browser context.
    """

    def __init__(self, timeout: int = 10, browser: str = "chromium", wait_time_ms: int = 1000):
        """
        Initialize the verifier.

        Args:
            timeout: Maximum time to wait for page load (seconds)
            browser: Browser engine name (chromium, firefox, webkit)
            wait_time_ms: Additional time to wait for scripts (milliseconds)
        """
        self.timeout = timeout * 1000  # Convert to milliseconds
        self.browser = browser
        self.wait_time_ms = wait_time_ms
        self.alert_triggered = False
        self.console_messages = []

    def verify_xss(self, url: str, cookies: Optional[List[Dict]] = None) -> Dict:
        """
        Verify XSS execution at the given URL.

        Args:
            url: URL with injected payload to verify
            cookies: Optional Playwright cookies to add to the browser context (for authenticated pages)

        Returns:
            Dictionary with verification results
        """
        result = {
            "executed": False,
            "alert_triggered": False,
            "console_output": [],
            "error": None,
        }

        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as p:
                browser_type = getattr(p, self.browser, p.chromium)
                browser = browser_type.launch(headless=True)
                context = browser.new_context()
                if cookies:
                    try:
                        context.add_cookies(cookies)
                    except Exception:
                        # If cookies are malformed, proceed without them
                        pass
                page = context.new_page()

                self.alert_triggered = False
                self.console_messages = []

                page.on("dialog", self._handle_dialog)
                page.on("console", self._handle_console)

                try:
                    page.goto(url, timeout=self.timeout, wait_until="networkidle")
                except Exception:
                    pass

                time.sleep(self.wait_time_ms / 1000.0)

                result["alert_triggered"] = self.alert_triggered
                result["console_output"] = self.console_messages.copy()
                result["executed"] = self.alert_triggered or len(self.console_messages) > 0

                browser.close()

        except ImportError:
            result["error"] = "Playwright not installed. Install with: pip install playwright"
        except Exception as e:
            result["error"] = str(e)

        return result

    def check_dom_xss(self, url: str, payload: str, cookies: Optional[List[Dict]] = None) -> Dict:
        """
        Check for DOM XSS via fragment injection.

        Builds url#payload, navigates to it, and uses MutationObserver to detect
        if the payload causes DOM mutations (e.g., script injection, unsafe
        location.hash usage).

        Args:
            url: Base URL to test (fragment will be replaced with payload)
            payload: XSS payload to inject into the URL fragment (e.g. <script>alert(1)</script>)
            cookies: Optional Playwright cookies for authenticated pages

        Returns:
            Dictionary with dom_xss_detected, alert_triggered, mutation_detected, error
        """
        result = {
            "dom_xss_detected": False,
            "alert_triggered": False,
            "mutation_detected": False,
            "error": None,
        }

        # Build fragment URL: strip existing fragment, append payload
        parsed = urlparse(url)
        fragment_url = urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, payload)
        )

        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as p:
                browser_type = getattr(p, self.browser, p.chromium)
                browser = browser_type.launch(headless=True)
                context = browser.new_context()
                if cookies:
                    try:
                        context.add_cookies(cookies)
                    except Exception:
                        pass
                page = context.new_page()

                self.alert_triggered = False
                self.console_messages = []

                page.on("dialog", self._handle_dialog)
                page.on("console", self._handle_console)

                page.add_init_script(f"""
                    window.__xssguard_mutation_detected = false;
                    const obs = new MutationObserver(() => {{ window.__xssguard_mutation_detected = true; }});
                    const go = () => {{
                        if (document.body) obs.observe(document.body, {{ childList: true, subtree: true }});
                        else if (document.documentElement) obs.observe(document.documentElement, {{ childList: true, subtree: true }});
                    }};
                    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', go);
                    else go();
                """)

                try:
                    page.goto(fragment_url, timeout=self.timeout, wait_until="networkidle")
                except Exception:
                    pass

                time.sleep(self.wait_time_ms / 1000.0)

                try:
                    mutation_detected = page.evaluate(
                        "() => window.__xssguard_mutation_detected === true"
                    )
                except Exception:
                    mutation_detected = False
                if mutation_detected is None:
                    mutation_detected = False

                result["alert_triggered"] = self.alert_triggered
                result["mutation_detected"] = bool(mutation_detected)
                result["dom_xss_detected"] = self.alert_triggered or bool(mutation_detected)

                browser.close()

        except ImportError:
            result["error"] = "Playwright not installed. Install with: pip install playwright"
        except Exception as e:
            result["error"] = str(e)

        return result

    def _handle_dialog(self, dialog):
        """Handle browser dialogs (alert, confirm, prompt)."""
        self.alert_triggered = True
        try:
            dialog.dismiss()
        except Exception:
            pass

    def _handle_console(self, msg):
        """Handle console messages."""
        self.console_messages.append({"type": msg.type, "text": msg.text})
