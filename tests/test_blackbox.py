"""
Unit tests for Black-Box Scanner
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from blackbox_scanner.scanner import BlackBoxScanner, Vulnerability, InputVector


@pytest.fixture
def scanner():
    return BlackBoxScanner()


@pytest.fixture
def scanner_with_timeout():
    return BlackBoxScanner(config={'timeout': 5})


def test_scanner_initialization(scanner):
    assert scanner is not None
    assert isinstance(scanner.payloads, list)
    assert len(scanner.payloads) > 0


def test_payload_library_loaded(scanner):
    payloads = scanner.payloads
    assert len(payloads) > 10

    contexts = [p.get('context') for p in payloads]
    assert 'html' in contexts
    assert 'attribute' in contexts
    assert 'javascript' in contexts


def test_inject_url_param(scanner):
    url = "http://example.com/search?q=test"
    result = scanner._inject_url_param(url, 'q', '<script>alert(1)</script>')

    assert 'q=' in result
    assert 'script' in result


def test_is_payload_reflected_exact(scanner):
    payload = "<script>alert('XSS')</script>"
    response = f"<div>{payload}</div>"

    assert scanner._is_payload_reflected(response, payload)


def test_is_payload_reflected_not_present(scanner):
    payload = "<script>alert('XSS')</script>"
    response = "<div>Safe content</div>"

    assert not scanner._is_payload_reflected(response, payload)


def test_determine_context_html_body(scanner):
    response = "<div><script>alert('XSS')</script></div>"
    payload = "<script>alert('XSS')</script>"

    context = scanner._determine_context(response, payload)
    assert context == "html_body"


def test_determine_context_javascript(scanner):
    response = "<script>var x = '<script>alert('XSS')</script>';</script>"
    payload = "<script>alert('XSS')</script>"

    context = scanner._determine_context(response, payload)
    assert context == "javascript"


def test_determine_context_attribute(scanner):
    response = '<input value="payload here">'
    payload = "payload here"

    context = scanner._determine_context(response, payload)
    assert context == "attribute"


def test_is_executable_context(scanner):
    assert scanner._is_executable_context("html_body")
    assert scanner._is_executable_context("javascript")
    assert scanner._is_executable_context("attribute")
    assert not scanner._is_executable_context("comment")


def test_extract_snippet(scanner):
    payload = "<script>alert(1)</script>"
    response = "Some content before " + payload + " some content after"

    snippet = scanner._extract_snippet(response, payload)
    assert payload in snippet
    assert snippet.startswith("...")
    assert snippet.endswith("...")


def test_input_vector_dataclass():
    vector = InputVector(
        url="http://example.com/search",
        method="GET",
        param_name="q",
        param_type="query"
    )

    assert vector.url == "http://example.com/search"
    assert vector.method == "GET"
    assert vector.param_name == "q"


def test_vulnerability_dataclass():
    vuln = Vulnerability(
        url="http://example.com/search?q=test",
        parameter="q",
        payload="<script>alert(1)</script>",
        vuln_type="Reflected XSS",
        confidence="High",
        context="html_body"
    )

    assert vuln.url == "http://example.com/search?q=test"
    assert vuln.vuln_type == "Reflected XSS"
    assert vuln.confidence == "High"


@patch('requests.Session.get')
def test_discover_inputs_url_params(mock_get, scanner):
    url = "http://example.com/search?q=test&category=books"

    mock_response = Mock()
    mock_response.text = "<html><body>Test</body></html>"
    mock_get.return_value = mock_response

    vectors = scanner._discover_inputs(url)

    param_names = [v.param_name for v in vectors if v.param_type == 'query']
    assert 'q' in param_names
    assert 'category' in param_names


@patch('requests.Session.get')
def test_discover_inputs_forms(mock_get, scanner):
    url = "http://example.com/login"

    mock_response = Mock()
    mock_response.text = """
    <html>
    <form action="/login" method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
        <input type="submit">
    </form>
    </html>
    """
    mock_get.return_value = mock_response

    vectors = scanner._discover_inputs(url)

    form_inputs = [v.param_name for v in vectors if v.param_type == 'form']
    assert 'username' in form_inputs
    assert 'password' in form_inputs
    # Submit button should not be included
    assert 'submit' not in form_inputs


@patch('requests.Session.get')
def test_crawl_page(mock_get, scanner_with_timeout):
    url = "http://example.com/"
    base_url = "http://example.com/"

    mock_response = Mock()
    mock_response.text = """
    <html>
    <a href="/page1">Page 1</a>
    <a href="/page2">Page 2</a>
    <a href="http://external.com/page3">External</a>
    </html>
    """
    mock_get.return_value = mock_response

    new_urls = scanner_with_timeout._crawl_page(url, base_url)

    assert len(new_urls) > 0
    # Should not include external links
    for discovered_url in new_urls:
        assert discovered_url.startswith("http://example.com")
