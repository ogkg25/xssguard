#!/usr/bin/env python3
"""
Synthetic XSS matrix target server.
Provides one endpoint per XSS type/context cell, plus safe variants.
"""

from flask import Flask, request, Response
import html
import json

app = Flask(__name__)

# Stored XSS simulation (in-memory only)
stored_values = {
    "html_body": [],
    "html_body_safe": [],
    "html_attr": [],
    "html_attr_safe": [],
    "js_string": [],
    "js_string_safe": [],
}


def _get_param(name: str) -> str:
    return request.args.get(name, "")


@app.route("/")
def index():
    return """
    <html>
    <head><title>XSS Matrix Server</title></head>
    <body>
        <h1>XSS Matrix Server</h1>
        <ul>
            <li><a href="/reflected/html-body?q=test">Reflected HTML Body</a></li>
            <li><a href="/reflected/html-attr?q=test">Reflected HTML Attribute</a></li>
            <li><a href="/reflected/js-string?q=test">Reflected JS String</a></li>
            <li><a href="/reflected/json?q=test">Reflected JSON</a></li>
            <li><a href="/reflected/url-href?q=test">Reflected URL/href</a></li>
            <li><a href="/dom/html-body?q=test">DOM HTML Body</a></li>
            <li><a href="/dom/html-attr?q=test">DOM HTML Attribute</a></li>
            <li><a href="/dom/js-string?q=test">DOM JS String</a></li>
            <li><a href="/dom/url-href?q=test">DOM URL/href</a></li>
            <li><a href="/stored/html-body">Stored HTML Body</a></li>
            <li><a href="/stored/html-attr">Stored HTML Attribute</a></li>
            <li><a href="/stored/js-string">Stored JS String</a></li>
        </ul>
    </body>
    </html>
    """


# Reflected XSS endpoints
@app.route("/reflected/html-body")
def reflected_html_body():
    q = _get_param("q")
    return f"<div>Result: {q}</div>"


@app.route("/reflected/html-body-safe")
def reflected_html_body_safe():
    q = _get_param("q")
    return f"<div>Result: {html.escape(q)}</div>"


@app.route("/reflected/html-attr")
def reflected_html_attr():
    q = _get_param("q")
    return f'<input type="text" value="{q}">'


@app.route("/reflected/html-attr-safe")
def reflected_html_attr_safe():
    q = _get_param("q")
    return f'<input type="text" value="{html.escape(q)}">'


@app.route("/reflected/js-string")
def reflected_js_string():
    q = _get_param("q")
    return f"<script>var msg = '{q}';</script>"


@app.route("/reflected/js-string-safe")
def reflected_js_string_safe():
    q = _get_param("q")
    return f"<script>var msg = {json.dumps(q)};</script>"


@app.route("/reflected/json")
def reflected_json():
    q = _get_param("q")
    payload = {"result": q}
    return Response(json.dumps(payload), mimetype="application/json")


@app.route("/reflected/json-safe")
def reflected_json_safe():
    payload = {"result": "safe"}
    return Response(json.dumps(payload), mimetype="application/json")


@app.route("/reflected/url-href")
def reflected_url_href():
    q = _get_param("q")
    return f'<a href="{q}">click</a>'


@app.route("/reflected/url-href-safe")
def reflected_url_href_safe():
    q = _get_param("q")
    safe = q if q.startswith(("http://", "https://")) else "#"
    safe = html.escape(safe)
    return f'<a href="{safe}">click</a>'


# Stored XSS endpoints
@app.route("/stored/html-body", methods=["GET", "POST"])
def stored_html_body():
    if request.method == "POST":
        stored_values["html_body"].append(request.form.get("comment", ""))
    rendered = "<br>".join(stored_values["html_body"])
    return f"""
    <form method="POST">
        <textarea name="comment"></textarea>
        <button type="submit">Submit</button>
    </form>
    <div>{rendered}</div>
    """


@app.route("/stored/html-body-safe", methods=["GET", "POST"])
def stored_html_body_safe():
    if request.method == "POST":
        stored_values["html_body_safe"].append(request.form.get("comment", ""))
    rendered = "<br>".join(html.escape(x) for x in stored_values["html_body_safe"])
    return f"""
    <form method="POST">
        <textarea name="comment"></textarea>
        <button type="submit">Submit</button>
    </form>
    <div>{rendered}</div>
    """


@app.route("/stored/html-attr", methods=["GET", "POST"])
def stored_html_attr():
    if request.method == "POST":
        stored_values["html_attr"].append(request.form.get("value", ""))
    last = stored_values["html_attr"][-1] if stored_values["html_attr"] else ""
    return f"""
    <form method="POST">
        <input name="value" />
        <button type="submit">Submit</button>
    </form>
    <input type="text" value="{last}">
    """


@app.route("/stored/html-attr-safe", methods=["GET", "POST"])
def stored_html_attr_safe():
    if request.method == "POST":
        stored_values["html_attr_safe"].append(request.form.get("value", ""))
    last = stored_values["html_attr_safe"][-1] if stored_values["html_attr_safe"] else ""
    return f"""
    <form method="POST">
        <input name="value" />
        <button type="submit">Submit</button>
    </form>
    <input type="text" value="{html.escape(last)}">
    """


@app.route("/stored/js-string", methods=["GET", "POST"])
def stored_js_string():
    if request.method == "POST":
        stored_values["js_string"].append(request.form.get("value", ""))
    last = stored_values["js_string"][-1] if stored_values["js_string"] else ""
    return f"""
    <form method="POST">
        <input name="value" />
        <button type="submit">Submit</button>
    </form>
    <script>var msg = '{last}';</script>
    """


@app.route("/stored/js-string-safe", methods=["GET", "POST"])
def stored_js_string_safe():
    if request.method == "POST":
        stored_values["js_string_safe"].append(request.form.get("value", ""))
    last = stored_values["js_string_safe"][-1] if stored_values["js_string_safe"] else ""
    return f"""
    <form method="POST">
        <input name="value" />
        <button type="submit">Submit</button>
    </form>
    <script>var msg = {json.dumps(last)};</script>
    """


# DOM-based XSS endpoints (require browser execution)
@app.route("/dom/html-body")
def dom_html_body():
    return """
    <div id="out"></div>
    <script>
      const q = new URLSearchParams(window.location.search).get('q') || '';
      document.getElementById('out').innerHTML = q;
    </script>
    """

@app.route("/dom/html-body-safe")
def dom_html_body_safe():
    return """
    <div id="out"></div>
    <script>
      const q = new URLSearchParams(window.location.search).get('q') || '';
      // Safe: treat input as text, not HTML
      document.getElementById('out').textContent = q;
    </script>
    """


@app.route("/dom/html-attr")
def dom_html_attr():
    return """
    <input id="target" />
    <script>
      const q = new URLSearchParams(window.location.search).get('q') || '';
      document.getElementById('target').setAttribute('value', q);
    </script>
    """

@app.route("/dom/html-attr-safe")
def dom_html_attr_safe():
    return """
    <input id="target" />
    <script>
      const q = new URLSearchParams(window.location.search).get('q') || '';
      // Safe: use the property (browser will not treat it as HTML)
      document.getElementById('target').value = q;
    </script>
    """


@app.route("/dom/js-string")
def dom_js_string():
    return """
    <script>
      const q = new URLSearchParams(window.location.search).get('q') || '';
      eval("var msg = '" + q + "';");
    </script>
    """

@app.route("/dom/js-string-safe")
def dom_js_string_safe():
    return """
    <script>
      const q = new URLSearchParams(window.location.search).get('q') || '';
      // Safe: no eval; ensure proper string encoding
      const msg = String(q);
      window.__xssguard_msg = msg;
    </script>
    """


@app.route("/dom/url-href")
def dom_url_href():
    return """
    <a id="link">link</a>
    <script>
      const q = new URLSearchParams(window.location.search).get('q') || '';
      document.getElementById('link').setAttribute('href', q);
    </script>
    """

@app.route("/dom/url-href-safe")
def dom_url_href_safe():
    return """
    <a id="link" href="#">link</a>
    <script>
      const q = new URLSearchParams(window.location.search).get('q') || '';
      // Safe: only allow absolute http(s) URLs; otherwise fall back.
      const safe = (q.startsWith('http://') || q.startsWith('https://')) ? q : '#';
      document.getElementById('link').setAttribute('href', safe);
    </script>
    """


def run_server(port=5556):
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    print("Starting XSS matrix server on http://127.0.0.1:5556")
    run_server()
