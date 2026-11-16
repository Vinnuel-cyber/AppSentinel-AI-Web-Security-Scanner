import os
from app import create_app
from app.models import db
from app.models.migrations import run_database_migrations

env_name = os.getenv("FLASK_ENV", "development")
app = create_app(env_name)


def init_database():
    """Ensure database tables exist and migrations run on startup."""
    with app.app_context():
        try:
            db.create_all()
            run_database_migrations(app)
            app.logger.info("Database tables and migrations initialized successfully.")
        except Exception as exc:
            app.logger.warning("Could not auto-initialize tables: %s", exc)


if __name__ == "__main__":
    init_database()
    host = os.getenv("FLASK_RUN_HOST", "127.0.0.1")
    port = int(os.getenv("FLASK_RUN_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "1").lower() in ("1", "true", "yes")
    app.run(host=host, port=port, debug=debug)
