import os
import logging
import click
from flask import Flask, jsonify, render_template, request, current_app
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect, CSRFError
from config import config_by_name
from app.models import db, User

login_manager = LoginManager()
csrf = CSRFProtect()


def create_app(config_name: str = "default") -> Flask:
    """Application factory for AppSentinel."""
    app = Flask(__name__, instance_relative_config=True)

    # Load configuration
    config_class = config_by_name.get(config_name, config_by_name["default"])
    app.config.from_object(config_class)

    # Ensure required instance and report folders exist
    os.makedirs(app.config.get("INSTANCE_PATH", app.instance_path), exist_ok=True)
    os.makedirs(app.config.get("REPORT_FOLDER", app.root_path + "/../reports"), exist_ok=True)

    # Configure logging
    logging.basicConfig(
        level=logging.INFO if not app.config.get("DEBUG") else logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "warning"
    csrf.init_app(app)

    # Auto-run safe migrations on startup for persistent storage
    if config_name != "testing":
        try:
            from app.models.migrations import run_database_migrations
            run_database_migrations(app)
        except Exception as exc:
            app.logger.warning("Could not auto-run schema migrations on startup: %s", exc)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Register blueprints
    from app.routes.health import health_bp
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.targets import targets_bp
    from app.routes.scanner import scanner_bp
    from app.routes.recon import recon_bp
    from app.routes.owasp import owasp_bp
    from app.routes.risk import risk_bp
    from app.routes.reports import reports_bp
    from app.routes.ai import ai_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(targets_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(recon_bp)
    app.register_blueprint(owasp_bp)
    app.register_blueprint(risk_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(ai_bp)

    # Security Headers Hook
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
            "img-src 'self' data: https:;"
        )
        return response

    # Error Handlers
    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        current_app.logger.warning("CSRF validation failure from IP %s on %s: %s", request.remote_addr, request.path, error.description)
        if request.is_json:
            return jsonify({"error": "CSRF Error", "message": error.description}), 400
        return jsonify({"error": "CSRF Validation Failed", "message": "The form session or CSRF token is invalid or expired. Please refresh and try again."}), 400

    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({"error": "Bad Request", "message": str(error)}), 400

    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({"error": "Forbidden", "message": "Access denied. Insufficient privileges."}), 403

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Not Found", "message": "The requested resource was not found"}), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred"}), 500

    # Register CLI commands
    @app.cli.command("init-db")
    def init_db_command():
        """Initialize the database schema."""
        with app.app_context():
            db.create_all()
            print("AppSentinel database tables created successfully.")

    @app.cli.command("create-admin")
    @click.option("--username", prompt="Admin Username", help="Admin username")
    @click.option("--email", prompt="Admin Email", help="Admin email address")
    @click.option("--password", prompt="Admin Password", hide_input=True, confirmation_prompt=True, help="Admin password")
    @click.option("--full-name", default="System Administrator", help="Admin full name")
    def create_admin_command(username, email, password, full_name):
        """Bootstrap an administrative user safely without hardcoded secrets."""
        with app.app_context():
            existing = User.query.filter(
                (User.username.ilike(username.strip())) | (User.email.ilike(email.strip()))
            ).first()
            if existing:
                print(f"Error: A user with username '{username}' or email '{email}' already exists.")
                return

            valid, err = User.validate_password_strength(password)
            if not valid:
                print(f"Error: {err}")
                return

            admin = User(
                username=username.strip(),
                email=email.strip().lower(),
                full_name=full_name.strip(),
                role="ADMIN",
                is_active=True,
            )
            admin.set_password(password, enforce_complexity=True)
            db.session.add(admin)
            db.session.commit()
            print(f"Administrator '{username}' created successfully.")

    return app
