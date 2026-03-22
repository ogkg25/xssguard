"""
Test for scope control feature in blackbox scanner.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from blackbox_scanner.scanner import BlackBoxScanner


def test_scope_restriction_filters_urls():
    """Test that scope_path filters out URLs outside the specified path."""
    config = {
        "scope_path": "/vulnerabilities/xss_r/",
        "same_domain_only": True,
        "timeout": 10,
        "verify_ssl": False,
    }
    
    scanner = BlackBoxScanner(config=config)
    
    # Mock HTML with links to different paths
    mock_html = """
    <html>
        <body>
            <a href="/vulnerabilities/xss_r/?name=test">XSS Reflected</a>
            <a href="/vulnerabilities/xss_r/index.php">XSS Index</a>
            <a href="/vulnerabilities/xss_s/">XSS Stored</a>
            <a href="/vulnerabilities/csp/">CSP</a>
            <a href="/setup.php">Setup</a>
        </body>
    </html>
    """
    
    # Mock the HTTP response
    mock_response = Mock()
    mock_response.text = mock_html
    
    with patch.object(scanner.session, 'get', return_value=mock_response):
        new_urls = scanner._crawl_page(
            "http://localhost:8081/vulnerabilities/xss_r/",
            "http://localhost:8081"
        )
    
    # Should only include URLs that start with /vulnerabilities/xss_r/
    expected_urls = [
        "http://localhost:8081/vulnerabilities/xss_r/",
        "http://localhost:8081/vulnerabilities/xss_r/index.php",
    ]
    
    # Verify all returned URLs match the scope
    for url in new_urls:
        assert "/vulnerabilities/xss_r/" in url, f"URL {url} should be within scope"
    
    # Verify URLs outside scope are filtered out
    for url in new_urls:
        assert "/xss_s/" not in url, "Should not include xss_s URLs"
        assert "/csp/" not in url, "Should not include CSP URLs"
        assert "/setup.php" not in url, "Should not include setup URLs"


def test_no_scope_restriction():
    """Test that without scope_path, all same-domain URLs are crawled."""
    config = {
        "scope_path": None,  # No scope restriction
        "same_domain_only": True,
        "timeout": 10,
        "verify_ssl": False,
    }
    
    scanner = BlackBoxScanner(config=config)
    
    mock_html = """
    <html>
        <body>
            <a href="/vulnerabilities/xss_r/">XSS Reflected</a>
            <a href="/vulnerabilities/xss_s/">XSS Stored</a>
            <a href="/vulnerabilities/csp/">CSP</a>
        </body>
    </html>
    """
    
    mock_response = Mock()
    mock_response.text = mock_html
    
    with patch.object(scanner.session, 'get', return_value=mock_response):
        new_urls = scanner._crawl_page(
            "http://localhost:8081/",
            "http://localhost:8081"
        )
    
    # Should include all same-domain URLs
    assert len(new_urls) == 3, "Should crawl all URLs when no scope restriction"


def test_scope_with_query_params():
    """Test that scope restriction works with query parameters."""
    config = {
        "scope_path": "/vulnerabilities/xss_r/",
        "same_domain_only": True,
        "timeout": 10,
        "verify_ssl": False,
    }
    
    scanner = BlackBoxScanner(config=config)
    
    mock_html = """
    <html>
        <body>
            <a href="/vulnerabilities/xss_r/?name=test">Test Link</a>
            <a href="/vulnerabilities/xss_r/?foo=bar">Another Test</a>
            <a href="/other/page.php?name=test">Other Page</a>
        </body>
    </html>
    """
    
    mock_response = Mock()
    mock_response.text = mock_html
    
    with patch.object(scanner.session, 'get', return_value=mock_response):
        new_urls = scanner._crawl_page(
            "http://localhost:8081/vulnerabilities/xss_r/",
            "http://localhost:8081"
        )
    
    # Should include URLs with query params within scope
    assert len(new_urls) == 2, "Should include query param URLs within scope"
    for url in new_urls:
        assert "/vulnerabilities/xss_r/" in url


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
