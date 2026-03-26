"""
Vulnerable API for Aegis demo.
A simple user management API with a destructive DELETE endpoint.
"""

import json
from http.server import HTTPServer, BaseHTTPRequestHandler

USERS = {
    "1": {"id": "1", "name": "Alice", "email": "alice@acme.com", "role": "admin"},
    "2": {"id": "2", "name": "Bob", "email": "bob@acme.com", "role": "user"},
    "3": {"id": "3", "name": "Charlie", "email": "charlie@acme.com", "role": "user"},
    "4": {"id": "4", "name": "Diana", "email": "diana@acme.com", "role": "manager"},
}


class VulnHandler(BaseHTTPRequestHandler):
    def _send_json(self, code, data):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/users":
            self._send_json(200, {"users": list(USERS.values())})
        elif self.path.startswith("/api/users/"):
            uid = self.path.split("/")[-1]
            if uid in USERS:
                self._send_json(200, USERS[uid])
            else:
                self._send_json(404, {"error": "User not found"})
        elif self.path == "/api/health":
            self._send_json(200, {"status": "ok"})
        elif self.path == "/api/echo":
            self._send_json(200, {"headers": dict(self.headers)})
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length else ""
        if self.path == "/api/search":
            # Vulnerable to SQL injection (simulated)
            self._send_json(200, {"query": body, "results": list(USERS.values())})
        else:
            self._send_json(404, {"error": "Not found"})

    def do_DELETE(self):
        if self.path.startswith("/api/users/"):
            uid = self.path.split("/")[-1]
            if uid in USERS:
                deleted = USERS.pop(uid)
                self._send_json(200, {"deleted": deleted, "remaining": len(USERS)})
                print(f"\n  !!! USER {deleted['name']} (id={uid}) WAS DELETED !!!\n")
            else:
                self._send_json(404, {"error": "User not found"})
        else:
            self._send_json(404, {"error": "Not found"})

    def log_message(self, format, *args):
        print(f"  [{self.command}] {self.path} -> {args[1] if len(args) > 1 else ''}")


if __name__ == "__main__":
    port = 8888
    server = HTTPServer(("127.0.0.1", port), VulnHandler)
    print(f"Vulnerable API running on http://127.0.0.1:{port}")
    print(f"  GET  /api/users       - List all users")
    print(f"  GET  /api/users/:id   - Get user by ID")
    print(f"  POST /api/search      - Search (vuln to SQLi)")
    print(f"  DELETE /api/users/:id  - DELETE a user (destructive!)")
    print()
    server.serve_forever()
