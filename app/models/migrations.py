from sqlalchemy import inspect, text
from . import db


def run_database_migrations(app) -> None:
    """Safely apply schema migrations to preserve existing records without data loss."""
    with app.app_context():
        try:
            inspector = inspect(db.engine)
            table_names = inspector.get_table_names()
            
            if "users" in table_names:
                existing_cols = {col["name"] for col in inspector.get_columns("users")}
                
                # Check and add full_name column if missing
                if "full_name" not in existing_cols:
                    app.logger.info("Migrating schema: adding full_name column to users table.")
                    db.session.execute(text("ALTER TABLE users ADD COLUMN full_name VARCHAR(120)"))
                    db.session.commit()
                    
                # Check and add last_login column if missing
                if "last_login" not in existing_cols:
                    app.logger.info("Migrating schema: adding last_login column to users table.")
                    db.session.execute(text("ALTER TABLE users ADD COLUMN last_login DATETIME"))
                    db.session.commit()
                    
            db.create_all()
        except Exception as exc:
            db.session.rollback()
            app.logger.warning("Database schema check / migration note: %s", exc)
