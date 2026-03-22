#!/usr/bin/env python3
"""
Intentionally vulnerable web server for testing XSS detection.
DO NOT deploy this in production or expose to the internet.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

# Store "comments" for stored XSS simulation
comments = []


@app.route('/')
def index():
    return '''
    <html>
    <head><title>Vulnerable Test Server</title></head>
    <body>
        <h1>XSS Test Server</h1>
        <p>This server contains intentional vulnerabilities for testing.</p>
        <ul>
            <li><a href="/search?q=test">Search (Reflected XSS)</a></li>
            <li><a href="/user/john">User Profile (Reflected XSS)</a></li>
            <li><a href="/comments">Comments (Stored XSS)</a></li>
        </ul>
    </body>
    </html>
    '''


@app.route('/search')
def search():
    query = request.args.get('q', '')
    # VULNERABILITY: Reflected XSS - no sanitization
    html = f'''
    <html>
    <head><title>Search Results</title></head>
    <body>
        <h1>Search Results for: {query}</h1>
        <p>No results found.</p>
        <a href="/">Back</a>
    </body>
    </html>
    '''
    return html


@app.route('/user/<username>')
def user_profile(username):
    # VULNERABILITY: Reflected XSS in URL path
    html = f'''
    <html>
    <head><title>User Profile</title></head>
    <body>
        <h1>Profile: {username}</h1>
        <p>User information would go here.</p>
        <a href="/">Back</a>
    </body>
    </html>
    '''
    return html


@app.route('/comments', methods=['GET', 'POST'])
def comments_page():
    if request.method == 'POST':
        comment = request.form.get('comment', '')
        comments.append(comment)
    
    # VULNERABILITY: Stored XSS - comments not sanitized
    comments_html = '<br>'.join(comments)
    
    html = f'''
    <html>
    <head><title>Comments</title></head>
    <body>
        <h1>Comments</h1>
        <form method="POST">
            <textarea name="comment" placeholder="Enter comment"></textarea>
            <button type="submit">Submit</button>
        </form>
        <h2>All Comments:</h2>
        <div>{comments_html}</div>
        <a href="/">Back</a>
    </body>
    </html>
    '''
    return html


def run_server(port=5555):
    """Run the vulnerable server."""
    app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False)


if __name__ == '__main__':
    print("Starting vulnerable test server on http://127.0.0.1:5555")
    print("WARNING: This server contains intentional vulnerabilities!")
    run_server()
