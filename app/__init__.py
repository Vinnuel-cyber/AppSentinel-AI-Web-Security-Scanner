import os
import logging
from flask import Flask, jsonify
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
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

    # Initialize CSRF (disabled in testing config)
    if not app.config.get("TESTING", False):
        csrf.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Register blueprints
    from app.routes.health import health_bp
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.targets import targets_bp
    from app.routes.scanner import scanner_bp
    from app.routes.reports import reports_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(targets_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(reports_bp)

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
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "font-src 'self' https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https:;"
        )
        return response

    # Error Handlers
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({"error": "Bad Request", "message": str(error)}), 400

    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({"error": "Forbidden", "message": "Access denied"}), 403

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

    return app
