"""
Black-Box Scanner for XSS Vulnerability Detection.
Performs dynamic analysis of running web applications.
"""

import logging
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from blackbox_scanner.crawler import BrowserCrawler
from blackbox_scanner.payloads import generate_payloads
from xssguard.core.models import InputVector, Vulnerability

logger = logging.getLogger(__name__)


class BlackBoxScanner:
    """
    Dynamic analysis scanner for XSS vulnerability detection.

    Crawls web applications, identifies input vectors, and tests
    for XSS vulnerabilities through payload injection.
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the scanner with optional configuration.

        Args:
            config: Optional dictionary with scanner settings
        """
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": self.config.get("user_agent", "XSSGuard/1.0 Security Scanner")}
        )
        self.timeout = int(self.config.get("timeout", 10))
        self.verify_ssl = bool(self.config.get("verify_ssl", True))
        self.max_depth = int(self.config.get("max_depth", 3))
        self.max_pages = int(self.config.get("max_pages", 100))
        self.same_domain_only = bool(self.config.get("same_domain_only", True))
        self.scope_path = self.config.get("scope_path", None)  # Optional path prefix restriction
        self.request_delay = float(self.config.get("request_delay", 0.1))
        self.payloads = self._load_payloads(self.config.get("payloads"))
        self.visited_urls: Set[str] = set()
        self._stored_submissions_for_sweep: List[Tuple[str, str, InputVector]] = []

        # Log scope restriction if enabled
        if self.scope_path:
            logger.info("Scope restriction enabled: only crawling URLs matching '%s'", self.scope_path)
        self.visited_url_patterns: Set[str] = set()  # Track URL patterns to avoid duplicates
        self.use_browser_crawl = bool(self.config.get("use_browser_crawl", False))

    def browser_crawl(self, url: str) -> List[str]:
        """
        Use Playwright-based BrowserCrawler for SPA targets.
        Returns discovered URLs when browser-based crawling is available.
        """
        crawler = BrowserCrawler(
            timeout_ms=int(self.config.get("browser_timeout_ms", 10000)),
            ajax_wait_ms=int(self.config.get("ajax_wait_ms", 1500)),
            max_pages=min(50, self.max_pages),
            same_domain_only=self.same_domain_only,
        )
        result = crawler.crawl(url)
        if result.get("error"):
            logger.debug("Browser crawl skipped: %s", result["error"])
            return []
        urls = result.get("urls", [])
        if self.scope_path:
            urls = [u for u in urls if urlparse(u).path.startswith(self.scope_path)]
        return urls

    def set_cookie(self, cookie_string: str):
        """Set authentication cookie for requests."""
        # Parse cookie string (e.g., "PHPSESSID=abc123; security=low")
        cookies = {}
        for part in cookie_string.split(';'):
            if '=' in part:
                key, value = part.strip().split('=', 1)
                cookies[key] = value
        
        # Update session cookies
        for key, value in cookies.items():
            self.session.cookies.set(key, value)

    def _normalize_url_pattern(self, url: str) -> str:
        """
        Normalize URL to a pattern for deduplication.
        URLs with same path and parameters (but different values) map to same pattern.
        
        Example:
            /page?id=1&name=test -> /page?id=&name=
            /page?id=2&name=foo  -> /page?id=&name=
        """
        parsed = urlparse(url)
        
        # Extract parameter names only (ignore values)
        if parsed.query:
            params = parse_qs(parsed.query)
            # Sort parameter names for consistent pattern
            param_pattern = "&".join(sorted(params.keys()))
            pattern = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param_pattern}"
        else:
            pattern = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        return pattern
    
    def _should_skip_url(self, url: str) -> bool:
        """
        Determine if a URL should be skipped (likely a navigation/index page).
        
        Returns True if URL appears to be a navigation/listing page without forms.
        """
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Skip common static resources
        static_extensions = {'.css', '.js', '.jpg', '.jpeg', '.png', '.gif', 
                           '.svg', '.ico', '.woff', '.woff2', '.ttf', '.pdf'}
        if any(path.endswith(ext) for ext in static_extensions):
            return True
        
        # Skip common admin/management paths without parameters
        skip_patterns = ['/admin', '/logout', '/settings', '/config', '/dashboard']
        if any(pattern in path for pattern in skip_patterns) and not parsed.query:
            return True
        
        # If we have a scope restriction, NEVER skip URLs within that scope
        # (they may contain forms even without query params)
        if self.scope_path and path.startswith(self.scope_path.lower()):
            return False
        
        # Skip URLs without parameters only if they look like pure navigation
        # But allow them if they might contain forms (we'll discover forms during scan)
        # Only skip if it's clearly a top-level listing (e.g., /, /products/, /blog/)
        if not parsed.query:
            # Allow single-level paths (e.g., /search, /login, /contact)
            if path.count('/') <= 1:
                return False
            # Allow if path doesn't end with / (likely a specific page)
            if not path.endswith('/'):
                return False
            # Skip only obvious top-level navigation directories
            # (but scan everything else - forms may be present)
            top_level_nav = ['/', '/products/', '/blog/', '/news/', '/articles/']
            if path in top_level_nav:
                return True
        
        return False

    def _load_payloads(self, custom_payloads: Optional[List[Dict]]) -> List[Dict]:
        """Load XSS payload library."""
        payloads = [
            # Basic script injection
            {
                "payload": "<script>alert('XSS')</script>",
                "context": "html",
                "type": "basic"
            },
            {
                "payload": "<script>alert(1)</script>",
                "context": "html",
                "type": "basic"
            },
            # Event handler payloads
            {
                "payload": "<img src=x onerror=alert('XSS')>",
                "context": "html",
                "type": "event_handler"
            },
            {
                "payload": "<img src=x onerror=alert(1)>",
                "context": "html",
                "type": "event_handler"
            },
            {
                "payload": "<svg onload=alert('XSS')>",
                "context": "html", 
                "type": "event_handler"
            },
            {
                "payload": "<body onload=alert('XSS')>",
                "context": "html",
                "type": "event_handler"
            },
            {
                "payload": "<iframe src=javascript:alert('XSS')>",
                "context": "html",
                "type": "event_handler"
            },
            # Attribute injection
            {
                "payload": "\" onmouseover=\"alert('XSS')\" x=\"",
                "context": "attribute",
                "type": "attribute_injection"
            },
            {
                "payload": "' onmouseover='alert(1)' x='",
                "context": "attribute",
                "type": "attribute_injection"
            },
            {
                "payload": "\" onfocus=\"alert('XSS')\" autofocus x=\"",
                "context": "attribute",
                "type": "attribute_injection"
            },
            # JavaScript context
            {
                "payload": "';alert('XSS');//",
                "context": "javascript",
                "type": "js_injection"
            },
            {
                "payload": "\";alert('XSS');//",
                "context": "javascript",
                "type": "js_injection"
            },
            {
                "payload": "'-alert('XSS')-'",
                "context": "javascript",
                "type": "template_literal"
            },
            # Polyglot payloads (work in multiple contexts)
            {
                "payload": "javascript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//>/",
                "context": "universal",
                "type": "polyglot"
            },
            {
                "payload": "'><script>alert('XSS')</script>",
                "context": "attribute_html",
                "type": "breakout"
            },
            {
                "payload": "\"><script>alert('XSS')</script>",
                "context": "attribute_html",
                "type": "breakout"
            },
            # Encoded payloads
            {
                "payload": "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
                "context": "html",
                "type": "encoded"
            },
            {
                "payload": "<script>\\u0061lert('XSS')</script>",
                "context": "html",
                "type": "unicode_encoded"
            }
        ]
        if custom_payloads and isinstance(custom_payloads, list):
            # Only use custom_payloads if it's actually a list of payload dicts
            # (not a config dict like {use_builtin: True, max_per_param: 10})
            payloads = list(custom_payloads)
        max_per_param = int(self.config.get("max_per_param", len(payloads)))
        return payloads[:max_per_param]

    def scan_url(self, target_url: str) -> List[Vulnerability]:
        """
        Scan a URL for XSS vulnerabilities.
        
        Args:
            target_url: The URL to scan
            
        Returns:
            List of Vulnerability objects for detected issues
        """
        vulnerabilities: List[Vulnerability] = []

        # Fetch the page once to check for DOM sinks
        try:
            response = self.session.get(target_url, timeout=self.timeout, verify=self.verify_ssl)
            page_html = response.text
        except requests.RequestException:
            page_html = ""

        input_vectors = self._discover_inputs(target_url)
        has_dom_sinks = None  # Evaluated lazily on first vector
        dom_tested_params: Set[str] = set()  # Track which params we've already tested for DOM XSS
        
        for vector in input_vectors:
            # Lazily check for DOM sinks only if we have vectors to test
            if has_dom_sinks is None:
                has_dom_sinks = bool(page_html and self._detect_dom_sinks(page_html))

            # Test for DOM XSS if page contains DOM sinks
            # Only test each parameter once to avoid duplicates
            if has_dom_sinks and vector.param_name not in dom_tested_params:
                dom_vulns = self._test_dom_xss_vector(vector, page_html)
                vulnerabilities.extend(dom_vulns)
                dom_tested_params.add(vector.param_name)
            
            # Always test for standard reflected/stored XSS
            # A page can have both DOM and reflected/stored XSS
            vulns = self._test_input_vector(vector)
            vulnerabilities.extend(vulns)

        # HTTP header injection detection (Referer, User-Agent, X-Forwarded-For)
        header_vulns = self._test_header_injection(target_url)
        vulnerabilities.extend(header_vulns)

        return vulnerabilities

    def crawl_and_scan(self, start_url: str) -> List[Vulnerability]:
        """
        Crawl a website and scan all discovered pages.
        
        Args:
            start_url: The starting URL for crawling
            
        Returns:
            List of all vulnerabilities found
        """
        vulnerabilities: List[Vulnerability] = []
        urls_to_scan: List[Tuple[str, int]] = [(start_url, 0)]
        self.visited_urls = set()
        self.visited_url_patterns = set()
        self._stored_submissions_for_sweep = []

        # Optionally use browser-based SPA crawl to discover additional URLs
        if self.use_browser_crawl:
            spa_urls = self.browser_crawl(start_url)
            for u in spa_urls:
                if u not in self.visited_urls:
                    urls_to_scan.append((u, 1))

        while urls_to_scan and len(self.visited_urls) < self.max_pages:
            current_url, depth = urls_to_scan.pop(0)
            
            # Skip if already visited
            if current_url in self.visited_urls or depth > self.max_depth:
                continue
            
            # Get URL pattern for deduplication
            url_pattern = self._normalize_url_pattern(current_url)
            
            # Skip if we've already scanned this pattern
            if url_pattern in self.visited_url_patterns:
                logger.debug("Skipping duplicate pattern: %s", current_url)
                continue
            
            # Skip listing/index pages without parameters
            if self._should_skip_url(current_url):
                logger.debug("Skipping listing/index page: %s", current_url)
                self.visited_urls.add(current_url)  # Mark as visited but don't scan
                continue

            self.visited_urls.add(current_url)
            self.visited_url_patterns.add(url_pattern)
            logger.info("Scanning: %s", current_url)

            vulns = self.scan_url(current_url)
            vulnerabilities.extend(vulns)

            if depth < self.max_depth:
                new_urls = self._crawl_page(current_url, start_url)
                urls_to_scan.extend([(url, depth + 1) for url in new_urls])

            time.sleep(self.request_delay)

        # Stored XSS verification sweep: revisit visited pages to detect payloads
        # that were stored by form submissions and appear on other pages
        sweep_vulns = self._verification_sweep(vulnerabilities)
        vulnerabilities.extend(sweep_vulns)

        return vulnerabilities

    def _discover_inputs(self, url: str) -> List[InputVector]:
        """Discover all input vectors on a page."""
        vectors = []

        # Extract URL parameters
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name in params:
                vectors.append(InputVector(
                    url=url,
                    method='GET',
                    param_name=param_name,
                    param_type='query'
                ))
        
        # Fetch page and extract forms
        try:
            response = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            soup = BeautifulSoup(response.text, 'html.parser')

            for form_index, form in enumerate(soup.find_all('form')):
                form_action = form.get('action', '')
                form_url = urljoin(url, form_action) if form_action else url
                form_method = form.get('method', 'GET').upper()

                for input_elem in form.find_all(['input', 'textarea', 'select']):
                    input_name = input_elem.get('name')
                    if not input_name:
                        continue

                    tag = input_elem.name.lower()
                    input_type = (input_elem.get('type', 'text') or 'text').lower()

                    # Never inject into pure buttons/images
                    if input_type in ['button', 'image']:
                        continue

                    # Hidden + submit fields are important for *submission*,
                    # but are usually not meaningful injection points.
                    if input_type in ['hidden', 'submit']:
                        continue

                    vectors.append(
                        InputVector(
                            url=form_url,
                            method=form_method,
                            param_name=input_name,
                            param_type='form',
                            page_url=url,
                            form_action=form_url,
                            form_index=form_index,
                        )
                    )

        except requests.RequestException as e:
            logger.warning("Error fetching %s: %s", url, e)

        return vectors

    def _map_scanner_context_to_payloads(self, context: str) -> Optional[str]:
        """Map scanner context names to payloads module context names."""
        mapping = {
            "html_body": "html_body",
            "attribute": "html_attribute",
            "javascript": "js_string",
            "comment": "comment",
            "css": "html_body",  # payloads has no css; use html_body
        }
        return mapping.get(context)

    def _submit_payload(
        self, vector: InputVector, payload: str
    ) -> Optional[Tuple[requests.Response, str]]:
        """
        Submit a payload to the vector and return (response, test_url) or None.
        """
        try:
            test_url = vector.url
            response = None
            if vector.param_type == "form":
                if not vector.page_url:
                    return None
                form_fields = self._get_form_fields(
                    page_url=vector.page_url,
                    action_url=vector.form_action or vector.url,
                    method=vector.method,
                    form_index=vector.form_index,
                )
                if not form_fields:
                    return None
                form_fields[vector.param_name] = payload
                if vector.method == "GET":
                    parsed = urlparse(vector.url)
                    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    test_url = f"{base}?{urlencode(form_fields, doseq=True)}"
                    response = self.session.get(
                        test_url, timeout=self.timeout, verify=self.verify_ssl
                    )
                else:
                    response = self.session.post(
                        vector.url,
                        data=form_fields,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        allow_redirects=True,
                    )
                if vector.page_url:
                    self._stored_submissions_for_sweep.append(
                        (vector.page_url, payload, vector)
                    )
            else:
                if vector.method == "GET":
                    test_url = self._inject_url_param(
                        vector.url, vector.param_name, payload
                    )
                    response = self.session.get(
                        test_url, timeout=self.timeout, verify=self.verify_ssl
                    )
                else:
                    response = self.session.post(
                        vector.url,
                        data={vector.param_name: payload},
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        allow_redirects=True,
                    )
            return (response, test_url) if response is not None else None
        except requests.RequestException:
            return None

    def _detect_dom_sinks(self, response_text: str) -> bool:
        """
        Detect potential DOM XSS sinks in JavaScript code.
        Returns True if the page contains dangerous DOM manipulation patterns.
        """
        # Common DOM XSS sinks
        dom_sinks = [
            'document.write(',
            'document.writeln(',
            '.innerHTML',
            '.outerHTML',
            'eval(',
            'setTimeout(',
            'setInterval(',
            'Function(',
            '.insertAdjacentHTML(',
            'document.location',
            'window.location',
        ]
        
        response_lower = response_text.lower()
        for sink in dom_sinks:
            if sink.lower() in response_lower:
                return True
        return False

    def _test_dom_xss_vector(self, vector: InputVector, response_text: str) -> List[Vulnerability]:
        """
        Test for DOM-based XSS vulnerabilities.
        
        DOM XSS is different from reflected/stored XSS:
        - Payload is processed client-side by JavaScript
        - Payload doesn't appear in HTTP response body
        - Requires browser execution to detect
        
        This method detects pages with DOM sinks and reports them as
        potential DOM XSS that require browser verification.
        """
        vulnerabilities = []
        
        # Only test if page contains DOM sinks
        if not self._detect_dom_sinks(response_text):
            return vulnerabilities
        
        # For DOM XSS, we report potential vulnerabilities that need browser verification
        # Use a few targeted payloads suitable for DOM contexts
        dom_payloads = [
            "<img src=x onerror=alert(1)>",
            "'-alert(1)-'",
            "\"><img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "#<img src=x onerror=alert(1)>",
        ]
        
        for payload in dom_payloads:
            # Build test URL with payload
            test_url = self._inject_url_param(vector.url, vector.param_name, payload)
            
            # Report as potential DOM XSS (confidence=Low, requires verification)
            vuln = Vulnerability(
                url=test_url,
                parameter=vector.param_name,
                payload=payload,
                vuln_type="DOM XSS",
                confidence="Low",  # Needs browser verification to confirm
                context="javascript",
                request_details={
                    "method": vector.method,
                    "param_type": vector.param_type,
                    "test_url": test_url,
                    "verify_url": test_url,
                    "requires_verification": True,
                },
                response_snippet="DOM sink detected in JavaScript",
            )
            vulnerabilities.append(vuln)
            
            # Only report one potential vuln per vector to avoid spam
            break
        
        return vulnerabilities

    def _test_input_vector(self, vector: InputVector) -> List[Vulnerability]:
        """Test a single input vector with XSS payloads."""
        import time
        start_time = time.time()
        vulnerabilities = []
        tried_payloads: Set[str] = set()
        payload_count = 0

        def _try_payload_and_report(payload: str) -> Tuple[bool, Optional[str]]:
            """
            Try a payload; if reflected and executable, report vuln and return (True, context).
            Otherwise return (False, None).
            """
            result = self._submit_payload(vector, payload)
            if result is None:
                return (False, None)
            response, test_url = result
            if not self._is_payload_reflected(response.text, payload):
                return (False, None)
            context = self._determine_context(response.text, payload)
            vuln_type = "Reflected XSS"
            verify_url = test_url
            if vector.param_type == "form" and vector.page_url:
                try:
                    revisit = self.session.get(
                        vector.page_url, timeout=self.timeout, verify=self.verify_ssl
                    )
                    if self._is_payload_reflected(revisit.text, payload):
                        vuln_type = "Stored XSS"
                        verify_url = vector.page_url
                except requests.RequestException:
                    pass
            if not self._is_executable_context(context, payload):
                return (False, None)
            vuln = Vulnerability(
                url=verify_url if vuln_type == "Stored XSS" else vector.url,
                parameter=vector.param_name,
                payload=payload,
                vuln_type=vuln_type,
                confidence="High" if context != "unknown" else "Medium",
                context=context,
                request_details={
                    "method": vector.method,
                    "param_type": vector.param_type,
                    "page_url": vector.page_url,
                    "form_action": vector.form_action,
                    "form_index": vector.form_index,
                    "test_url": test_url,
                    "verify_url": verify_url,
                },
                response_snippet=self._extract_snippet(response.text, payload),
            )
            vulnerabilities.append(vuln)
            return (True, context)

        def _try_payload_list(payload_list: List[str]) -> bool:
            """Try each payload; return True if any reported a vuln."""
            nonlocal payload_count
            for p in payload_list:
                if p in tried_payloads:
                    continue
                tried_payloads.add(p)
                payload_count += 1
                found, detected_context = _try_payload_and_report(p)
                if found:
                    # Context-appropriate payload variants: wire generate_payloads for reporting
                    mapped = self._map_scanner_context_to_payloads(detected_context)
                    if mapped is not None:
                        payload_variants = generate_payloads(context=mapped)
                    return True
            return False

        # First pass: use built-in payloads (fast, most common cases)
        for payload_data in self.payloads:
            payload = payload_data["payload"]
            if _try_payload_list([payload]):
                elapsed = time.time() - start_time
                logger.info(f"Vector {vector.param_name}: Found vuln after {payload_count} payloads in {elapsed:.2f}s")
                return vulnerabilities

        # Second pass: ONLY if no vulnerability found in first pass
        # Use a limited set of additional payloads to avoid testing 125+ variants
        # The built-in payloads already cover most cases; this is just for edge cases
        # Limit to 20 additional payloads for performance
        payload_variants = generate_payloads(context=None)[:20]
        if _try_payload_list(payload_variants):
            elapsed = time.time() - start_time
            logger.info(f"Vector {vector.param_name}: Found vuln after {payload_count} payloads in {elapsed:.2f}s")
            return vulnerabilities

        elapsed = time.time() - start_time
        logger.info(f"Vector {vector.param_name}: No vuln found after testing {payload_count} payloads in {elapsed:.2f}s")
        return vulnerabilities

    def _test_header_injection(self, url: str) -> List[Vulnerability]:
        """
        Test for XSS via HTTP header injection (Referer, User-Agent, X-Forwarded-For).
        Sends payloads in each header and checks if reflected in the response.
        """
        vulnerabilities: List[Vulnerability] = []
        header_names = ["Referer", "User-Agent", "X-Forwarded-For"]

        # Use a few payloads for header tests (header reflection often needs simple payloads)
        payloads_to_try = [p["payload"] for p in self.payloads[:5]]
        payloads_to_try.extend(generate_payloads(context=None)[:3])

        for header_name in header_names:
            for payload in payloads_to_try:
                try:
                    headers = dict(self.session.headers)
                    headers[header_name] = payload
                    response = self.session.get(
                        url,
                        headers=headers,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                    )
                    if not self._is_payload_reflected(response.text, payload):
                        continue
                    context = self._determine_context(response.text, payload)
                    if not self._is_executable_context(context, payload):
                        continue
                    vuln = Vulnerability(
                        url=url,
                        parameter=header_name,
                        payload=payload,
                        vuln_type="Header XSS",
                        confidence="High" if context != "unknown" else "Medium",
                        context=context,
                        request_details={
                            "source": "header",
                            "header_name": header_name,
                        },
                        response_snippet=self._extract_snippet(response.text, payload),
                    )
                    vulnerabilities.append(vuln)
                    break  # One vuln per header is enough; move to next header
                except requests.RequestException:
                    continue
            time.sleep(self.request_delay)

        return vulnerabilities

    def _get_form_fields(
        self, page_url: str, action_url: str, method: str, form_index: Optional[int]
    ) -> Dict[str, str]:
        """
        Refetch `page_url` and reconstruct the form field map for the target form.
        Includes hidden inputs (e.g., CSRF tokens) and submit values when present.
        """
        try:
            resp = self.session.get(page_url, timeout=self.timeout, verify=self.verify_ssl)
        except requests.RequestException:
            return {}

        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            return {}

        candidate_forms = []
        for idx, form in enumerate(forms):
            form_action = form.get("action", "")
            form_url = urljoin(page_url, form_action) if form_action else page_url
            form_method = form.get("method", "GET").upper()
            if form_index is not None and idx != form_index:
                continue
            if form_method != method.upper():
                continue
            # Match action URL loosely (some pages use relative actions)
            if action_url and form_url and form_url != action_url:
                # If indices match, allow it; otherwise keep searching
                if form_index is None:
                    continue
            candidate_forms.append(form)

        selected_form = None
        if candidate_forms:
            selected_form = candidate_forms[0]
        elif form_index is not None and 0 <= form_index < len(forms):
            selected_form = forms[form_index]
        else:
            selected_form = forms[0]

        fields: Dict[str, str] = {}
        for elem in selected_form.find_all(["input", "textarea", "select"]):
            name = elem.get("name")
            if not name:
                continue

            tag = elem.name.lower()
            if tag == "textarea":
                fields[name] = elem.text or ""
                continue

            if tag == "select":
                selected = elem.find("option", selected=True)
                if selected is None:
                    selected = elem.find("option")
                fields[name] = (selected.get("value") if selected else "") or ""
                continue

            input_type = (elem.get("type", "text") or "text").lower()
            if input_type in ["button", "image"]:
                continue
            fields[name] = (elem.get("value") or "")

        return fields

    def _inject_url_param(self, url: str, param: str, value: str) -> str:
        """Inject a value into a URL parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    def _is_payload_reflected(self, response_text: str, payload: str) -> bool:
        """Check if payload appears in response in a browser-executable form."""
        import html as html_module
        from urllib.parse import unquote

        decoded = unquote(payload)

        # When the payload is URL-encoded, only the decoded form can be executed
        # by a browser.  The URL-encoded form (%3Cscript%3E...) appearing literally
        # in HTML is just plain text — not executable.  So for URL-encoded payloads,
        # only count the reflection if the *decoded* tag characters are present.
        if decoded != payload:
            if decoded in response_text:
                return True
            if html_module.unescape(decoded) in response_text:
                return True
            return False

        # Payload is not URL-encoded: check for exact match
        if payload in response_text:
            return True

        # Also check for HTML-unescaped form (handles HTML entity-encoded payloads)
        if html_module.unescape(payload) in response_text:
            return True

        return False

    def _detect_context(self, html: str, payload: str) -> str:
        """
        Detect XSS reflection context via full DOM parsing with BeautifulSoup.
        Returns one of: html_attribute, script_tag (javascript), css, comment, html_body.
        """
        import html as html_module
        from urllib.parse import unquote

        payload_variants = [payload, html_module.unescape(payload), unquote(payload)]
        payload_variants = [p for p in payload_variants if p and p in html]

        if not payload_variants:
            return "unknown"

        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return "unknown"

        # Check comment first (inside <!-- -->)
        from bs4 import Comment
        for comment_node in soup.find_all(string=lambda t: isinstance(t, Comment)):
            for p in payload_variants:
                if p in comment_node:
                    return "comment"

        # Check css (inside <style> block)
        for style_tag in soup.find_all("style"):
            for s in style_tag.strings:
                for p in payload_variants:
                    if p in s:
                        return "css"

        # Check script_tag (inside <script> block) - return "javascript" for backward compat
        # Note: HTML parser truncates script at first </script>, so payload may be split
        for script_tag in soup.find_all("script"):
            for s in script_tag.strings:
                for p in payload_variants:
                    if p in s:
                        return "javascript"  # script_tag context, executable
                    # Fallback: payload contains </script> which truncates script content
                    if "</script>" in p and p.split("</script>")[0] in s:
                        return "javascript"

        # Check html_attribute (payload inside an attribute value)
        for tag in soup.find_all(True):
            for attr, val in tag.attrs.items():
                if isinstance(val, list):
                    val = " ".join(str(v) for v in val)
                if isinstance(val, str):
                    for p in payload_variants:
                        if p in val:
                            return "attribute"

        # Default: payload in html body
        return "html_body"

    def _determine_context(self, response_text: str, payload: str) -> str:
        """Determine the HTML context where payload is reflected via full DOM parsing."""
        return self._detect_context(response_text, payload)

    def _is_executable_context(self, context: str, payload: str = "") -> bool:
        """
        Check if the reflection context allows script execution for the given payload.

        Context alone is not enough — the payload's characters determine whether
        it can actually break out of or inject into an executable position:

        - javascript / css / tag: always executable regardless of payload content.
        - html_body: only executable if the payload contains '<', enabling tag injection.
          A tagless payload (e.g. 'onclick=alert(1)') in body text is just plain text.
        - attribute: only executable if the payload can break out of attribute quotes
          ('" or "'" present) or inject tags (< or >).  A payload confined inside
          a properly-quoted attribute value cannot execute.
        """
        if context in {'javascript', 'css', 'tag'}:
            return True
        if context == 'html_body':
            # When no payload provided, assume executable; with payload, require tag injection char
            return True if not payload else '<' in payload
        if context == 'attribute':
            # When no payload provided, assume executable; with payload, require breakout chars
            return True if not payload else any(c in payload for c in ('"', "'", '<', '>'))
        return False

    def _verification_sweep(self, existing_vulns: List["Vulnerability"]) -> List["Vulnerability"]:
        """
        Revisit pages where form payloads were submitted to detect stored XSS.

        During crawl_and_scan, POST form submissions are recorded in
        _stored_submissions_for_sweep as (page_url, payload, vector) tuples.
        This sweep re-fetches each page and checks whether any injected payload
        now appears in the response, indicating persistent (stored) XSS.

        Findings already captured in existing_vulns are skipped to avoid duplicates.
        """
        if not self._stored_submissions_for_sweep:
            return []

        existing_keys: Set[str] = set()
        for v in existing_vulns:
            existing_keys.add(f"{v.url}:{v.parameter}:{v.payload}")

        new_vulns: List["Vulnerability"] = []
        visited_sweep: Set[str] = set()

        for page_url, payload, vector in self._stored_submissions_for_sweep:
            sweep_key = f"{page_url}:{payload}"
            if sweep_key in visited_sweep:
                continue
            visited_sweep.add(sweep_key)

            try:
                resp = self.session.get(page_url, timeout=self.timeout, verify=self.verify_ssl)
            except Exception:
                continue

            if not self._is_payload_reflected(resp.text, payload):
                continue

            context = self._determine_context(resp.text, payload)
            if not self._is_executable_context(context, payload):
                continue

            dedup_key = f"{page_url}:{vector.param_name}:{payload}"
            if dedup_key in existing_keys:
                continue
            existing_keys.add(dedup_key)

            vuln = Vulnerability(
                url=page_url,
                parameter=vector.param_name,
                payload=payload,
                vuln_type="Stored XSS",
                confidence="High" if context != "unknown" else "Medium",
                context=context,
                request_details={
                    "method": vector.method,
                    "param_type": vector.param_type,
                    "page_url": vector.page_url,
                    "form_action": vector.form_action,
                    "form_index": vector.form_index,
                    "verify_url": page_url,
                },
                response_snippet=self._extract_snippet(resp.text, payload),
            )
            new_vulns.append(vuln)

        return new_vulns

    def _crawl_page(self, url: str, base_url: str) -> List[str]:
        """Extract links from a page for crawling."""
        new_urls = []
        base_domain = urlparse(base_url).netloc

        try:
            response = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            soup = BeautifulSoup(response.text, 'html.parser')

            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                parsed = urlparse(full_url)

                # Remove fragment
                full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if parsed.query:
                    full_url += f"?{parsed.query}"

                # Check domain restriction
                if self.same_domain_only and parsed.netloc != base_domain:
                    continue
                
                # Check scope path restriction
                if self.scope_path and not parsed.path.startswith(self.scope_path):
                    logger.debug("URL %s outside scope %s, skipping", full_url, self.scope_path)
                    continue
                
                if full_url not in self.visited_urls:
                    new_urls.append(full_url)

        except requests.RequestException as exc:
            logger.debug("Crawl error for %s: %s", url, exc)

        return new_urls

    def _extract_snippet(self, response_text: str, payload: str) -> str:
        """Extract a code snippet around the reflected payload."""
        pos = response_text.find(payload)
        if pos == -1:
            return ""
        
        start = max(0, pos - 50)
        end = min(len(response_text), pos + len(payload) + 50)
        
        return f"...{response_text[start:end]}..."
