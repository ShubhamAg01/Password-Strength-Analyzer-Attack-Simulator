import http.server
import socketserver
import json
import os
import urllib.parse
from typing import Any
from src.entropy_analyzer import PasswordStrengthAnalyzer
from src.attack_simulator import AttackSimulator

# Bind to localhost only: this is an isolated lab tool and must not be
# reachable from other machines on the network.
HOST = "127.0.0.1"
PORT = 5050
STATIC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "static"))
GRAPHS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "results_and_graphs"))
WORDLIST_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "wordlists", "common_passwords.txt"))
TESTCASES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "wordlists", "test_hashes.json"))

_WORDLIST = []
if os.path.exists(WORDLIST_PATH):
    with open(WORDLIST_PATH, "r", encoding="utf-8") as f:
        _WORDLIST = [line.strip() for line in f if line.strip()]


class AppRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            self.serve_file(os.path.join(STATIC_DIR, "index.html"), "text/html")
        elif path == "/style.css":
            self.serve_file(os.path.join(STATIC_DIR, "style.css"), "text/css")
        elif path == "/app.js":
            self.serve_file(os.path.join(STATIC_DIR, "app.js"), "application/javascript")
        elif path.startswith("/graphs/"):
            img_name = os.path.basename(path)
            img_path = os.path.join(GRAPHS_DIR, img_name)
            self.serve_file(img_path, "image/png")
        elif path == "/api/testcases":
            if os.path.exists(TESTCASES_PATH):
                with open(TESTCASES_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.send_json(data)
            else:
                self.send_json([], status=404)
        elif path == "/api/benchmarks":
            b_path = os.path.join(GRAPHS_DIR, "benchmark_metrics.json")
            if os.path.exists(b_path):
                with open(b_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.send_json(data)
            else:
                self.send_json({}, status=404)
        else:
            self.send_error(404, "File Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        try:
            payload = json.loads(body) if body else {}
        except Exception:
            payload = {}

        if path == "/api/analyze":
            pwd = payload.get("password", "")
            # Full 1,500-entry corpus: pattern detection must see every
            # curated dictionary term (a small slice would miss 'password').
            res = PasswordStrengthAnalyzer.analyze(pwd, set(_WORDLIST))
            self.send_json(res)

        elif path == "/api/hash":
            pwd = payload.get("password", "")
            cost = int(payload.get("bcrypt_rounds", 8))
            md5_h = AttackSimulator.generate_hash(pwd, "md5")
            sha1_h = AttackSimulator.generate_hash(pwd, "sha1")
            bcrypt_h = AttackSimulator.generate_hash(pwd, "bcrypt", bcrypt_rounds=cost)
            self.send_json({
                "plaintext": pwd,
                "md5": md5_h,
                "sha1": sha1_h,
                "bcrypt": bcrypt_h
            })

        elif path == "/api/attack":
            target_hash = payload.get("target_hash", "").strip()
            algorithm = payload.get("algorithm", "md5").strip().lower()
            attack_type = payload.get("attack_type", "dictionary")
            enable_rules = bool(payload.get("enable_rules", False))

            if attack_type == "dictionary":
                # bcrypt is deliberately slow (~44 ms per candidate at cost 8),
                # so the candidate space is capped to keep the live demo bounded.
                if algorithm == "bcrypt":
                    active_wl = _WORDLIST[:20] if enable_rules else _WORDLIST[:50]
                else:
                    active_wl = _WORDLIST
                res = AttackSimulator.run_dictionary_attack(
                    target_hash, algorithm, active_wl, enable_rules=enable_rules
                )
            elif attack_type == "brute_force":
                max_len = int(payload.get("max_length", 3))
                res = AttackSimulator.run_brute_force_attack(
                    target_hash, algorithm, max_length=max_len
                )
            else:
                res = {"error": f"Unknown attack type {attack_type}"}
            self.send_json(res)

        else:
            self.send_error(404, "Unknown API Route")

    def serve_file(self, filepath: str, content_type: str):
        if not os.path.exists(filepath):
            self.send_error(404, f"File not found: {os.path.basename(filepath)}")
            return
        with open(filepath, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def send_json(self, data: Any, status: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def run_web_server(port: int = PORT):
    # ThreadingHTTPServer keeps the dashboard responsive while a slow
    # bcrypt candidate search is running in another browser request.
    httpd = http.server.ThreadingHTTPServer((HOST, port), AppRequestHandler)
    print(f"Server listening on http://{HOST}:{port} (localhost only)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    run_web_server()
