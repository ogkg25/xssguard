"""
Unit tests for White-Box Scanner
"""

import os
import tempfile
import pytest
from whitebox_scanner.scanner import WhiteBoxScanner, Finding


@pytest.fixture
def scanner():
    return WhiteBoxScanner()


def test_scanner_initialization(scanner):
    assert scanner is not None
    assert isinstance(scanner.signatures, list)
    assert len(scanner.signatures) > 0


def test_detect_innerHTML_assignment(scanner):
    code = """
    function render(data) {
        element.innerHTML = data;
    }
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write(code)
        f.flush()
        temp_file = f.name

    try:
        findings = scanner.scan_file(temp_file)
        assert len(findings) > 0
        assert findings[0].signature == "innerHTML_assignment"
        assert findings[0].severity == "High"
    finally:
        os.unlink(temp_file)


def test_detect_document_write(scanner):
    code = """
    function display(text) {
        document.write(text);
    }
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write(code)
        f.flush()
        temp_file = f.name

    try:
        findings = scanner.scan_file(temp_file)
        assert len(findings) > 0
        assert findings[0].signature == "document_write"
    finally:
        os.unlink(temp_file)


def test_detect_eval(scanner):
    code = """
    function execute(cmd) {
        eval(cmd);
    }
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write(code)
        f.flush()
        temp_file = f.name

    try:
        findings = scanner.scan_file(temp_file)
        assert len(findings) > 0
        assert findings[0].signature == "eval_usage"
        assert findings[0].severity == "Critical"
    finally:
        os.unlink(temp_file)


def test_detect_react_dangerous_html(scanner):
    code = """
    function Component({ html }) {
        return <div dangerouslySetInnerHTML={{__html: html}} />;
    }
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsx', delete=False) as f:
        f.write(code)
        f.flush()
        temp_file = f.name

    try:
        findings = scanner.scan_file(temp_file)
        assert len(findings) > 0
        assert findings[0].signature == "react_dangerous_html"
    finally:
        os.unlink(temp_file)


def test_detect_vue_v_html(scanner):
    code = """
    <template>
        <div v-html="userContent"></div>
    </template>
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.vue', delete=False) as f:
        f.write(code)
        f.flush()
        temp_file = f.name

    try:
        findings = scanner.scan_file(temp_file)
        assert len(findings) > 0
        assert findings[0].signature == "vue_v_html"
    finally:
        os.unlink(temp_file)


def test_safe_constant_assignment(scanner):
    code = """
    function render() {
        element.innerHTML = "<h1>Hello</h1>";
    }
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write(code)
        f.flush()
        temp_file = f.name

    try:
        findings = scanner.scan_file(temp_file)
        # Should not detect constant string assignments
        assert len(findings) == 0
    finally:
        os.unlink(temp_file)


def test_commented_code_ignored(scanner):
    code = """
    function render(data) {
        // element.innerHTML = data;
        element.textContent = data;
    }
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write(code)
        f.flush()
        temp_file = f.name

    try:
        findings = scanner.scan_file(temp_file)
        assert len(findings) == 0
    finally:
        os.unlink(temp_file)


def test_scan_project(scanner):
    with tempfile.TemporaryDirectory() as temp_dir:
        file1 = os.path.join(temp_dir, 'test1.js')
        file2 = os.path.join(temp_dir, 'test2.js')

        with open(file1, 'w') as f:
            f.write('element.innerHTML = userInput;')

        with open(file2, 'w') as f:
            f.write('document.write(data);')

        findings = scanner.scan_project(temp_dir)
        assert len(findings) == 2


def test_exclude_directories(scanner):
    with tempfile.TemporaryDirectory() as temp_dir:
        node_modules = os.path.join(temp_dir, 'node_modules')
        os.makedirs(node_modules)

        vuln_file = os.path.join(node_modules, 'test.js')
        with open(vuln_file, 'w') as f:
            f.write('eval(userInput);')

        findings = scanner.scan_project(temp_dir)
        # Should not find anything because node_modules is excluded
        assert len(findings) == 0


def test_python_exec_detection(scanner):
    code = """
    def execute_code(code_str):
        exec(code_str)
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        temp_file = f.name

    try:
        findings = scanner.scan_file(temp_file)
        assert len(findings) > 0
        assert findings[0].signature == "exec_usage"
    finally:
        os.unlink(temp_file)


def test_finding_dataclass():
    finding = Finding(
        file="test.js",
        line=42,
        content="element.innerHTML = data",
        signature="innerHTML_assignment",
        severity="High",
        description="Test finding",
        remediation="Use textContent"
    )

    assert finding.file == "test.js"
    assert finding.line == 42
    assert finding.severity == "High"


def test_angular_bypass_security(scanner):
    code = """
    sanitize(html) {
        return this.sanitizer.bypassSecurityTrustHtml(html);
    }
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.ts', delete=False) as f:
        f.write(code)
        f.flush()
        temp_file = f.name

    try:
        findings = scanner.scan_file(temp_file)
        assert len(findings) > 0
        assert findings[0].signature == "angular_bypass_security"
    finally:
        os.unlink(temp_file)


def test_jquery_html_method(scanner):
    code = """
    function updateContent(content) {
        $('#container').html(content);
    }
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write(code)
        f.flush()
        temp_file = f.name

    try:
        findings = scanner.scan_file(temp_file)
        assert len(findings) > 0
        assert findings[0].signature == "jquery_html"
    finally:
        os.unlink(temp_file)


def test_multiple_vulnerabilities_single_file(scanner):
    code = """
    function vulnerable() {
        element.innerHTML = data;
        document.write(content);
        eval(code);
    }
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write(code)
        f.flush()
        temp_file = f.name

    try:
        findings = scanner.scan_file(temp_file)
        assert len(findings) == 3
    finally:
        os.unlink(temp_file)
