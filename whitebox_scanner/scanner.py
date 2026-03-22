"""
White-Box Scanner for XSS Vulnerability Detection.
Performs static analysis of source code to identify XSS vulnerabilities.
Includes intra-function AST-based taint tracking for JS/TS and Python.
"""

import ast
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from xssguard.core.models import Finding

logger = logging.getLogger(__name__)

# Optional esprima for JS/TS parsing (graceful fallback if not installed)
try:
    import esprima
    _ESPRIMA_AVAILABLE = True
except ImportError:
    esprima = None  # type: ignore
    _ESPRIMA_AVAILABLE = False

# --- Taint tracking: source and sink definitions ---

# JS/TS: identifiers/patterns that indicate user-controlled input (sources)
JS_TAINT_SOURCES = (
    "document.location", "document.location.href", "window.location", "window.location.href",
    "req.query", "req.params", "req.body", "request.query", "request.params", "request.body",
)

# JS/TS: sink patterns (dangerous operations that can lead to XSS)
JS_TAINT_SINKS = (
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval", "insertAdjacentHTML",
)

# Python: source attribute/call patterns (user input)
PY_TAINT_SOURCES = ("request.args", "request.form", "input", "request.get", "request.values")

# Python: sink function/call patterns (dangerous output)
PY_TAINT_SINKS = ("Markup", "render_template_string", "exec", "eval")

# Known sanitizers: when present in surrounding code, reduce finding confidence (unless --strict).
# Includes DOMPurify, sanitize variants, escape functions, etc.
KNOWN_SANITIZERS = (
    "DOMPurify",
    "DOMPurify.sanitize",
    "escapeHtml",
    "htmlspecialchars",
    "bleach.clean",
    "markupsafe.escape",
    "Markup.escape",
    "sanitize_html",
    "xss(",
    "encode(",
    "encodeURIComponent",
    "sanitiz",  # sanitize, sanitizer, sanitization
)


def _has_sanitizer_in_context(content: str, line_num: int, window: int = 15) -> bool:
    """Check if surrounding lines (within window) contain a known sanitizer call."""
    lines = content.splitlines()
    start = max(0, line_num - 1 - window)
    end = min(len(lines), line_num - 1 + window + 1)
    context = "\n".join(lines[start:end]).lower()
    for s in KNOWN_SANITIZERS:
        if s.lower() in context:
            return True
    return False


def _js_member_str(node) -> Optional[str]:
    """Build dotted member string from esprima AST node (e.g. 'document.location')."""
    if not _ESPRIMA_AVAILABLE or esprima is None:
        return None
    try:
        if node is None:
            return None
        if node.type == "Identifier":
            return node.name
        if node.type == "MemberExpression":
            obj = _js_member_str(node.object)
            prop = _js_member_str(node.property) if node.computed else getattr(node.property, "name", None)
            if obj and prop:
                return f"{obj}.{prop}"
            return obj
        return None
    except Exception:
        return None


def _taint_track_js(content: str, path_str: str, ext: str) -> List[Finding]:
    """Intra-function taint tracking for JavaScript/TypeScript via esprima."""
    if not _ESPRIMA_AVAILABLE:
        return []
    findings: List[Finding] = []
    try:
        tree = esprima.parseScript(content, {"loc": True, "tolerant": True})
    except Exception as e:
        logger.debug("esprima parse failed for %s: %s", path_str, e)
        return []

    def _get_func_body(node):
        if hasattr(node, "body") and node.body:
            return node.body if isinstance(node.body, list) else [node.body]
        return []

    def is_source(s: Optional[str]) -> bool:
        if not s:
            return False
        for src in JS_TAINT_SOURCES:
            if src in s or s == src or s.endswith("." + src.split(".")[-1]):
                return True
        if any(s.startswith(p.split(".")[0] + ".") for p in JS_TAINT_SOURCES):
            return True
        return False

    def is_sink(s: Optional[str]) -> bool:
        if not s:
            return False
        for snk in JS_TAINT_SINKS:
            if snk in s or s.endswith("." + snk) or s == snk:
                return True
        return False

    def _visit_function(node) -> None:
        tainted: Set[str] = set()
        body = _get_func_body(node)
        if not body:
            return

        def add_tainted(var: str) -> None:
            if var and var.replace("_", "").replace("$", "").isalnum():
                tainted.add(var)

        def collect_taint(n, depth: int = 0) -> None:
            """Pass 1: only collect tainted variable names."""
            if depth > 200:
                return
            if n is None:
                return
            try:
                t = getattr(n, "type", None)
                if t == "AssignmentExpression":
                    right_str = _js_member_str(n.right) if hasattr(n, "right") else None
                    left = getattr(n, "left", None)
                    if left and getattr(left, "type", None) == "Identifier":
                        var = left.name
                        if is_source(right_str) or (right_str and right_str in tainted):
                            add_tainted(var)
                if t == "VariableDeclarator" and hasattr(n, "init") and n.init:
                    init_str = _js_member_str(n.init)
                    if hasattr(n, "id") and n.id and getattr(n.id, "type", None) == "Identifier":
                        var = n.id.name
                        if is_source(init_str) or (init_str and init_str in tainted):
                            add_tainted(var)
                for child in getattr(n, "body", []) or getattr(n, "declarations", []) or getattr(n, "arguments", []) or []:
                    if isinstance(child, list):
                        for c in child:
                            collect_taint(c, depth + 1)
                    else:
                        collect_taint(child, depth + 1)
                for attr in ("alternate", "consequent", "test", "left", "right", "object", "property", "callee", "init"):
                    if hasattr(n, attr):
                        collect_taint(getattr(n, attr), depth + 1)
            except Exception:
                pass

        def check_sinks(n, depth: int = 0) -> None:
            """Pass 2: emit findings when tainted data reaches a sink."""
            if depth > 200:
                return
            if n is None:
                return
            try:
                t = getattr(n, "type", None)
                if t == "AssignmentExpression":
                    left = getattr(n, "left", None)
                    if left and getattr(left, "type", None) == "MemberExpression":
                        member = _js_member_str(left)
                        if member and is_sink(member):
                            right_var = _js_member_str(n.right) if hasattr(n, "right") else None
                            if right_var in tainted or (right_var and is_source(right_var)):
                                loc = getattr(n, "loc", None)
                                line = loc.start.line if loc else 0
                                lines_arr = content.splitlines()
                                findings.append(Finding(
                                    file=path_str,
                                    line=line,
                                    content=lines_arr[line - 1].strip() if line and line <= len(lines_arr) else "",
                                    signature="taint_flow",
                                    severity="High",
                                    description="Taint flow: user input may reach XSS sink",
                                    remediation="Sanitize user input before use in DOM/output",
                                    confidence="High",
                                ))
                if t == "CallExpression":
                    callee = getattr(n, "callee", None)
                    callee_str = _js_member_str(callee)
                    if callee_str and is_sink(callee_str):
                        first_arg = None
                        if hasattr(n, "arguments") and n.arguments:
                            first_arg = _js_member_str(n.arguments[0])
                        if first_arg in tainted or (first_arg and is_source(first_arg)):
                            loc = getattr(n, "loc", None)
                            line = loc.start.line if loc else 0
                            lines_arr = content.splitlines()
                            findings.append(Finding(
                                file=path_str,
                                line=line,
                                content=lines_arr[line - 1].strip() if line and line <= len(lines_arr) else "",
                                signature="taint_flow",
                                severity="High",
                                description="Taint flow: user input may reach XSS sink",
                                remediation="Sanitize user input before use in DOM/output",
                                confidence="High",
                            ))
                for child in getattr(n, "body", []) or getattr(n, "declarations", []) or getattr(n, "arguments", []) or []:
                    if isinstance(child, list):
                        for c in child:
                            check_sinks(c, depth + 1)
                    else:
                        check_sinks(child, depth + 1)
                for attr in ("alternate", "consequent", "test", "left", "right", "object", "property", "callee", "init"):
                    if hasattr(n, attr):
                        check_sinks(getattr(n, attr), depth + 1)
            except Exception:
                pass

        # Pass 1: collect tainted names (fixed-point)
        for _ in range(10):
            prev = len(tainted)
            for stmt in body:
                collect_taint(stmt)
            if len(tainted) == prev:
                break

        # Pass 2: check sinks
        for stmt in body:
            check_sinks(stmt)

    def _find_functions(node, depth: int = 0) -> None:
        if depth > 100:
            return
        if node is None:
            return
        if getattr(node, "type", None) in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
            _visit_function(node)
        for attr in ("body", "consequent", "alternate", "declarations", "init", "arguments"):
            if hasattr(node, attr):
                val = getattr(node, attr)
                if isinstance(val, list):
                    for c in val:
                        _find_functions(c, depth + 1)
                else:
                    _find_functions(val, depth + 1)

    _find_functions(tree)
    return findings


def _taint_track_python(content: str, path_str: str) -> List[Finding]:
    """Intra-function taint tracking for Python via ast.parse."""
    findings: List[Finding] = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    def _name_of(node) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = _name_of(node.value) if hasattr(node, "value") else None
            return f"{base}.{node.attr}" if base else node.attr
        return None

    def _full_name(node) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = _full_name(node.value) if hasattr(node, "value") else None
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Call):
            return _full_name(node.func) if hasattr(node, "func") else None
        return None

    def _is_source(name: Optional[str], node) -> bool:
        if not name:
            return False
        for src in PY_TAINT_SOURCES:
            if src in name or name == src or name.endswith("." + src.split(".")[-1]):
                return True
        if isinstance(node, ast.Call):
            fn = _full_name(node.func) if hasattr(node, "func") else None
            if fn == "input":
                return True
        return False

    def _is_sink(name: Optional[str]) -> bool:
        if not name:
            return False
        for snk in PY_TAINT_SINKS:
            if snk in name or name == snk or name.endswith("." + snk):
                return True
        return False

    lines_arr = content.splitlines()

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            tainted: Set[str] = set()
            # Pass 1: collect tainted names (fixed-point for propagation)
            for _ in range(10):  # bounded iterations for taint propagation
                prev = len(tainted)
                for n in ast.walk(node):
                    if isinstance(n, ast.Assign):
                        for t in n.targets:
                            tname = _name_of(t)
                            if isinstance(t, ast.Name) and tname:
                                if isinstance(n.value, ast.Call) and _is_source(_full_name(n.value.func), n.value):
                                    tainted.add(tname)
                                elif isinstance(n.value, ast.Attribute) and _is_source(_full_name(n.value), n.value):
                                    tainted.add(tname)
                                elif isinstance(n.value, ast.Subscript):
                                    sub = _full_name(n.value.value) if hasattr(n.value, "value") else None
                                    if sub and _is_source(sub, n.value):
                                        tainted.add(tname)
                                elif isinstance(n.value, ast.Name) and n.value.id in tainted:
                                    tainted.add(tname)
                if len(tainted) == prev:
                    break
            # Pass 2: check sinks for tainted arguments
            for n in ast.walk(node):
                if isinstance(n, ast.Call):
                    fn = _full_name(n.func) if hasattr(n, "func") else None
                    if _is_sink(fn) and n.args:
                        if isinstance(n.args[0], ast.Name) and n.args[0].id in tainted:
                            findings.append(Finding(
                                file=path_str,
                                line=n.lineno,
                                content=lines_arr[n.lineno - 1].strip() if n.lineno and n.lineno <= len(lines_arr) else "",
                                signature="taint_flow",
                                severity="High",
                                description="Taint flow: user input may reach XSS sink",
                                remediation="Sanitize user input before use in template/output",
                                confidence="High",
                            ))

    return findings


@dataclass(frozen=True)
class Signature:
    name: str
    pattern: re.Pattern
    severity: str
    description: str
    remediation: str


class WhiteBoxScanner:
    """
    Static analysis scanner for XSS vulnerability detection.

    Analyzes source code files to identify dangerous patterns
    that may lead to Cross-Site Scripting vulnerabilities.
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the scanner with optional configuration.

        Args:
            config: Optional dictionary with scanner settings
        """
        self.config = config or {}
        self.signatures = self._load_signatures(self.config.get("signatures"))
        self.multiline_signatures = self._load_multiline_signatures()
        self.file_extensions = tuple(self.config.get("extensions", self._get_supported_extensions()))
        self.exclude_dirs = set(
            self.config.get(
                "exclude_dirs",
                [
                    "node_modules",
                    "__pycache__",
                    ".git",
                    ".svn",
                    "venv",
                    "env",
                    ".env",
                    "dist",
                    "build",
                    "vendor",
                ],
            )
        )
        self.max_file_size_kb = int(self.config.get("max_file_size_kb", 512))

    def _load_signatures(self, custom_signatures: Optional[Sequence[Dict]]) -> List[Signature]:
        """Load vulnerability signatures."""
        default_signatures = [
            {
                # Keep this early so React `dangerouslySetInnerHTML=...` is classified
                # primarily as a React issue (some tests expect it as the first finding).
                "name": "react_dangerous_html",
                "pattern": r"dangerouslySetInnerHTML",
                "severity": "High",
                "description": "dangerouslySetInnerHTML bypasses React's XSS protection",
                "remediation": "Sanitize HTML with DOMPurify before rendering"
            },
            {
                "name": "innerHTML_assignment",
                # Intentionally broad: matches `.innerHTML = ...` and also `dangerouslySetInnerHTML=...`
                # (legacy/benchmark compatibility).
                "pattern": r"innerHTML\s*=",
                "severity": "High",
                "description": "Direct innerHTML assignment can lead to XSS",
                "remediation": "Use textContent or proper sanitization with DOMPurify"
            },
            {
                "name": "outerHTML_assignment",
                "pattern": r"\bouterHTML\b\s*=",
                "severity": "High",
                "description": "Direct outerHTML assignment can lead to XSS",
                "remediation": "Use textContent or proper sanitization"
            },
            {
                "name": "document_write",
                "pattern": r"document\.write(ln)?\s*\(",
                "severity": "High", 
                "description": "document.write can execute arbitrary scripts",
                "remediation": "Use DOM manipulation methods instead"
            },
            {
                "name": "eval_usage",
                "pattern": r"\beval\s*\(",
                "severity": "Critical",
                "description": "eval() executes arbitrary code",
                "remediation": "Avoid eval(); use JSON.parse() for data"
            },
            {
                "name": "function_constructor",
                "pattern": r"new\s+Function\s*\(",
                "severity": "Critical",
                "description": "Function constructor can execute arbitrary code",
                "remediation": "Avoid Function constructor; use safe alternatives"
            },
            {
                "name": "setTimeout_string",
                "pattern": r"setTimeout\s*\(\s*['\"]",
                "severity": "High",
                "description": "setTimeout with string argument can execute code",
                "remediation": "Use function reference instead of string"
            },
            {
                "name": "setInterval_string",
                "pattern": r"setInterval\s*\(\s*['\"]",
                "severity": "High",
                "description": "setInterval with string argument can execute code",
                "remediation": "Use function reference instead of string"
            },
            {
                "name": "angular_bypass_security",
                "pattern": r"bypassSecurityTrust(Html|Script|Url|ResourceUrl)",
                "severity": "High",
                "description": "Angular security bypass methods can introduce XSS",
                "remediation": "Avoid bypassing Angular's built-in sanitization"
            },
            {
                "name": "vue_v_html",
                "pattern": r"v-html\s*=",
                "severity": "High",
                "description": "v-html renders raw HTML without sanitization",
                "remediation": "Use v-text or sanitize content before v-html"
            },
            {
                "name": "jquery_html",
                "pattern": r"\.\s*html\s*\([^)]*\)",
                "severity": "Medium",
                "description": "jQuery .html() can execute scripts in content",
                "remediation": "Use .text() or sanitize HTML content"
            },
            {
                "name": "jquery_append_html",
                "pattern": r"\.\s*(append|prepend|after|before)\s*\(['\"]<",
                "severity": "Medium",
                "description": "jQuery DOM manipulation with HTML strings",
                "remediation": "Sanitize HTML or use text-only methods"
            },
            {
                "name": "insertAdjacentHTML",
                "pattern": r"insertAdjacentHTML\s*\(",
                "severity": "High",
                "description": "insertAdjacentHTML can inject malicious HTML",
                "remediation": "Sanitize content before insertion"
            },
            {
                "name": "exec_usage",
                "pattern": r"\bexec\s*\(",
                "severity": "Critical",
                "description": "exec() executes arbitrary Python code",
                "remediation": "Avoid exec(); use safe alternatives"
            },
            {
                "name": "flask_render_string",
                "pattern": r"render_template_string\s*\(",
                "severity": "High",
                "description": "render_template_string with user input enables SSTI/XSS",
                "remediation": "Use render_template with file-based templates"
            },
            {
                "name": "jinja_safe_filter",
                "pattern": r"\|\s*safe\b",
                "severity": "Medium",
                "description": "Jinja2 |safe filter disables auto-escaping",
                "remediation": "Ensure content is sanitized before using |safe"
            },
            {
                "name": "django_mark_safe",
                "pattern": r"mark_safe\s*\(",
                "severity": "High",
                "description": "mark_safe disables Django's auto-escaping",
                "remediation": "Sanitize content before using mark_safe"
            },
            {
                "name": "createContextualFragment",
                "pattern": r"createContextualFragment\s*\(",
                "severity": "High",
                "description": "createContextualFragment can execute scripts",
                "remediation": "Sanitize HTML content before creating fragment"
            },
            {
                "name": "location_href_assignment",
                "pattern": r"location\s*(\.\s*href)?\s*=",
                "severity": "Medium",
                "description": "location.href assignment with user input can lead to XSS",
                "remediation": "Validate and sanitize URLs before assignment"
            },
            # PHP-specific XSS patterns
            {
                "name": "php_echo_GET",
                "pattern": r"(?:echo|print)\s+\$_(?:GET|POST|REQUEST)\b",
                "severity": "High",
                "description": "PHP echo/print of $_GET/$_POST/$_REQUEST without sanitization",
                "remediation": "Apply htmlspecialchars() before output; use ENT_QUOTES and UTF-8"
            },
            {
                "name": "php_short_tag_GET",
                "pattern": r"<\?=\s*\$_(?:GET|POST|REQUEST)\b",
                "severity": "High",
                "description": "PHP short tag outputs superglobal without sanitization",
                "remediation": "Apply htmlspecialchars() before output; use ENT_QUOTES and UTF-8"
            }
        ]
        signatures = list(custom_signatures) if custom_signatures else default_signatures
        compiled: List[Signature] = []
        for sig in signatures:
            try:
                compiled.append(
                    Signature(
                        name=sig["name"],
                        pattern=re.compile(sig["pattern"], re.IGNORECASE),
                        severity=sig.get("severity", "Medium"),
                        description=sig.get("description", ""),
                        remediation=sig.get("remediation", ""),
                    )
                )
            except re.error as exc:
                logger.warning("Invalid signature regex for %s: %s", sig.get("name"), exc)
        return compiled

    def _get_supported_extensions(self) -> Tuple[str, ...]:
        """Return tuple of supported file extensions."""
        return (
            '.js', '.jsx', '.ts', '.tsx',  # JavaScript/TypeScript
            '.py',                          # Python
            '.html', '.htm',                # HTML
            '.vue',                         # Vue.js
            '.php',                         # PHP
            '.ejs', '.hbs', '.jinja2', '.twig',  # Template files (multiline patterns)
        )

    # Template extensions that may contain multiline patterns (use re.DOTALL)
    _TEMPLATE_EXTENSIONS = ('.html', '.htm', '.vue', '.ejs', '.hbs', '.jinja2', '.twig')

    def _load_multiline_signatures(self) -> List[Signature]:
        """Load multiline-aware signatures for template files (re.DOTALL so '.' matches newlines)."""
        multiline_sigs = [
            {
                "name": "angular_innerHTML_binding",
                "pattern": r"\[innerHTML\]\s*=\s*[\"'].*?[\"']",
                "severity": "High",
                "description": "Angular [innerHTML] binding renders raw HTML without sanitization",
                "remediation": "Sanitize content or use Angular DomSanitizer",
            },
            {
                "name": "multiline_handlebars_unescaped",
                "pattern": r"\{\{\{.*?\}\}\}",
                "severity": "High",
                "description": "Handlebars/Mustache {{{ }}} outputs unescaped HTML",
                "remediation": "Use {{ }} for escaped output; sanitize if raw HTML needed",
            },
            {
                "name": "multiline_jinja_autoescape_false",
                "pattern": r"\{\%\s*autoescape\s+false\s*%\}.*?\{\%\s*endautoescape\s*%\}",
                "severity": "High",
                "description": "Jinja2 {% autoescape false %} disables escaping for block",
                "remediation": "Remove autoescape false or sanitize content before output",
            },
            {
                "name": "multiline_template_expression",
                "pattern": r"\{\{.*?\n.*?\}\}",
                "severity": "Medium",
                "description": "Template expression {{ }} spanning multiple lines may include user input",
                "remediation": "Ensure user input is escaped; avoid complex multiline expressions",
            },
        ]
        compiled: List[Signature] = []
        for sig in multiline_sigs:
            try:
                compiled.append(
                    Signature(
                        name=sig["name"],
                        pattern=re.compile(sig["pattern"], re.IGNORECASE | re.DOTALL),
                        severity=sig.get("severity", "Medium"),
                        description=sig.get("description", ""),
                        remediation=sig.get("remediation", ""),
                    )
                )
            except re.error as exc:
                logger.warning("Invalid multiline signature regex for %s: %s", sig.get("name"), exc)
        return compiled

    def _is_commented(self, line: str) -> bool:
        """Check if a line is commented out."""
        stripped = line.strip()
        # JavaScript/TypeScript/PHP comments
        if stripped.startswith('//') or stripped.startswith('/*'):
            return True
        # Python comments
        if stripped.startswith('#'):
            return True
        # HTML comments
        if stripped.startswith('<!--'):
            return True
        return False

    def _is_safe_constant(self, line: str, signature_name: str) -> bool:
        """Check if the pattern match involves a constant string (likely safe)."""
        if signature_name in {"innerHTML_assignment", "outerHTML_assignment"}:
            if re.search(r'\b(innerHTML|outerHTML)\b\s*=\s*["\'][^"\']*["\']', line):
                return True
        return False

    def _should_scan_file(self, file_path: Path) -> bool:
        if not file_path.suffix.lower().endswith(self.file_extensions):
            return False
        try:
            size_kb = file_path.stat().st_size / 1024
            if size_kb > self.max_file_size_kb:
                logger.debug("Skipping %s (size %.1f KB exceeds limit)", file_path, size_kb)
                return False
        except OSError:
            return False
        return True

    def _iter_files(self, directory: Path) -> Iterable[Path]:
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
            for filename in files:
                file_path = Path(root) / filename
                if self._should_scan_file(file_path):
                    yield file_path

    def _find_repo_root(self, start: Path) -> Optional[Path]:
        """
        Find a stable project root to make reported file paths reproducible across machines.
        Prefers a parent directory containing `pyproject.toml` (or `.git` as fallback).
        """
        cur = start if start.is_dir() else start.parent
        for parent in (cur, *cur.parents):
            if (parent / "pyproject.toml").exists() or (parent / ".git").exists():
                return parent
        return None

    def _format_file_path(self, path: Path, repo_root: Optional[Path]) -> str:
        """
        Prefer repo-relative paths (e.g., `benchmarks/smoke_targets/react_xss.jsx`)
        instead of absolute paths (`/Users/...`) for stable JSON outputs and baselines.
        """
        try:
            resolved = path.resolve()
        except Exception:
            resolved = path

        root = repo_root or self._find_repo_root(resolved)
        if root:
            try:
                return resolved.relative_to(root.resolve()).as_posix()
            except Exception:
                pass
        return str(path)

    def scan_file(self, file_path: str, repo_root: Optional[Path] = None) -> List[Finding]:
        """
        Scan a single file for XSS vulnerabilities.
        
        Args:
            file_path: Path to the file to scan
            repo_root: Optional project root for stable relative file paths
            
        Returns:
            List of Finding objects for detected vulnerabilities
        """
        findings: List[Finding] = []
        path = Path(file_path)
        try:
            with path.open('r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.splitlines()

                reported_path = self._format_file_path(path, repo_root)
                for line_num, line in enumerate(lines, start=1):
                    # Skip commented lines
                    if self._is_commented(line):
                        continue

                    for sig in self.signatures:
                        if sig.pattern.search(line):
                            # Check if it's a safe constant usage
                            if self._is_safe_constant(line, sig.name):
                                continue

                            finding = Finding(
                                file=reported_path,
                                line=line_num,
                                content=line.strip(),
                                signature=sig.name,
                                severity=sig.severity,
                                description=sig.description,
                                remediation=sig.remediation,
                            )
                            findings.append(finding)

                # Multiline pattern detection for template files (re.DOTALL)
                ext = path.suffix.lower()
                if ext in self._TEMPLATE_EXTENSIONS:
                    for sig in self.multiline_signatures:
                        for m in sig.pattern.finditer(content):
                            line_num_multiline = content[: m.start()].count("\n") + 1
                            # Avoid duplicate: skip if line-based already found same sig on this line
                            if any(
                                f.file == reported_path and f.line == line_num_multiline and f.signature == sig.name
                                for f in findings
                            ):
                                continue
                            matched_snippet = content[m.start() : m.end()].replace("\n", " ").strip()[:80]
                            findings.append(
                                Finding(
                                    file=reported_path,
                                    line=line_num_multiline,
                                    content=matched_snippet,
                                    signature=sig.name,
                                    severity=sig.severity,
                                    description=sig.description,
                                    remediation=sig.remediation,
                                )
                            )

                # Intra-function AST-based taint tracking
                ext = path.suffix.lower()
                if ext in ('.js', '.jsx', '.ts', '.tsx'):
                    findings.extend(_taint_track_js(content, reported_path, ext))
                elif ext == '.py':
                    findings.extend(_taint_track_python(content, reported_path))

                # Sanitization-aware: reduce High confidence to Low when sanitizer in context (unless strict)
                strict = self.config.get("strict", False)
                if not strict:
                    for f in findings:
                        if f.confidence == "High" and _has_sanitizer_in_context(content, f.line):
                            f.confidence = "Low"

        except IOError as e:
            logger.warning("Error reading file %s: %s", file_path, e)
        except Exception as e:
            logger.exception("Unexpected error scanning %s: %s", file_path, e)

        return findings

    def scan_project(self, directory: str) -> List[Finding]:
        """
        Recursively scan a directory for XSS vulnerabilities.
        
        Args:
            directory: Path to the directory to scan
            
        Returns:
            List of Finding objects for all detected vulnerabilities
        """
        all_findings: List[Finding] = []
        dir_path = Path(directory)
        repo_root = self._find_repo_root(dir_path.resolve())
        for file_path in self._iter_files(dir_path):
            findings = self.scan_file(str(file_path), repo_root=repo_root)
            all_findings.extend(findings)

        return all_findings
