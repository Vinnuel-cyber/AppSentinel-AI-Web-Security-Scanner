from flask import Flask, request, make_response
import html


def create_vuln_lab_app() -> Flask:
    """Isolated local test application exposing controlled test endpoints for verification.
    
    Strictly isolated for local pytest test harnesses; never exposed on public networks.
    """
    lab = Flask("vuln_lab")
    lab.config["TESTING"] = True

    @lab.route("/search")
    def search():
        q = request.args.get("q", "")
        # Simulated SQL syntax error upon single quote
        if "'" in q:
            return (
                "<html><body>Internal Database Error: sqlite3.OperationalError: near \"'\": syntax error</body></html>",
                500,
            )
        return f"<html><body>Search Results for {html.escape(q)}</body></html>", 200

    @lab.route("/greet")
    def greet():
        name = request.args.get("name", "")
        # Deliberately unencoded reflection in HTML body
        return f"<html><body><h1>Hello {name}</h1></body></html>", 200

    @lab.route("/safe_greet")
    def safe_greet():
        name = request.args.get("name", "")
        # Properly encoded
        return f"<html><body><h1>Hello {html.escape(name)}</h1></body></html>", 200

    @lab.route("/cookies")
    def set_cookies():
        resp = make_response("<html><body>Cookie issuer</body></html>")
        # Insecure cookie: missing HttpOnly and missing SameSite
        resp.set_cookie("session_token", "abc123secret", httponly=False, secure=False, samesite=None)
        return resp

    @lab.route("/error")
    def trigger_error():
        # Simulated traceback and internal path exposure
        body = """
        <html>
        <head><title>500 Internal Server Error</title></head>
        <body>
        Traceback (most recent call last):
          File "/var/www/html/app.py", line 42, in index
            raise RuntimeError("Database connection timed out")
        RuntimeError: Database connection timed out
        </body>
        </html>
        """
        return body, 500

    @lab.route("/files/")
    def directory_index():
        # Simulated directory listing
        body = """
        <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
        <html>
         <head>
          <title>Index of /files/</title>
         </head>
         <body>
        <h1>Index of /files/</h1>
        <ul><li><a href="/"> Parent Directory</a></li>
        <li><a href="backup.zip"> backup.zip</a></li>
        <li><a href="notes.txt"> notes.txt</a></li>
        </ul>
        </body></html>
        """
        return body, 200

    @lab.route("/config")
    def config_exposure():
        # Simulated sensitive credential pattern dynamically constructed to avoid static secret scanner false alarms
        sample_ghp = "ghp_" + ("1234567890" * 3 + "123456")
        body = f"""
        {{
            "status": "active",
            "aws_key": "AKIAIOSFODNN7EXAMPLE",
            "github_token": "{sample_ghp}",
            "env": "staging"
        }}
        """
        return body, 200

    @lab.route("/methods", methods=["GET", "OPTIONS"])
    def methods_test():
        resp = make_response("OK")
        resp.headers["Allow"] = "GET, POST, PUT, DELETE, TRACE, OPTIONS"
        return resp

    return lab
