from sqlalchemy import inspect, text
from . import db


def run_database_migrations(app) -> None:
    """Safely apply schema migrations to preserve existing records without data loss."""
    with app.app_context():
        try:
            inspector = inspect(db.engine)
            table_names = inspector.get_table_names()

            # 1. Users table migrations
            if "users" in table_names:
                existing_cols = {col["name"] for col in inspector.get_columns("users")}
                if "full_name" not in existing_cols:
                    app.logger.info("Migrating schema: adding full_name column to users table.")
                    db.session.execute(text("ALTER TABLE users ADD COLUMN full_name VARCHAR(120)"))
                    db.session.commit()
                if "last_login" not in existing_cols:
                    app.logger.info("Migrating schema: adding last_login column to users table.")
                    db.session.execute(text("ALTER TABLE users ADD COLUMN last_login DATETIME"))
                    db.session.commit()

            # 2. Targets table migrations
            if "targets" in table_names:
                target_cols = {col["name"] for col in inspector.get_columns("targets")}
                if "environment" not in target_cols:
                    app.logger.info("Migrating schema: adding environment column to targets table.")
                    db.session.execute(text("ALTER TABLE targets ADD COLUMN environment VARCHAR(32) DEFAULT 'Production'"))
                    db.session.commit()
                if "verification_token_hash" not in target_cols:
                    app.logger.info("Migrating schema: adding verification_token_hash column to targets table.")
                    db.session.execute(text("ALTER TABLE targets ADD COLUMN verification_token_hash VARCHAR(64)"))
                    db.session.commit()
                if "verification_status" not in target_cols:
                    app.logger.info("Migrating schema: adding verification_status column to targets table.")
                    db.session.execute(text("ALTER TABLE targets ADD COLUMN verification_status VARCHAR(32) DEFAULT 'PENDING_VERIFICATION'"))
                    db.session.commit()
                if "verification_expires_at" not in target_cols:
                    app.logger.info("Migrating schema: adding verification_expires_at column to targets table.")
                    db.session.execute(text("ALTER TABLE targets ADD COLUMN verification_expires_at DATETIME"))
                    db.session.commit()
                if "is_active" not in target_cols:
                    app.logger.info("Migrating schema: adding is_active column to targets table.")
                    db.session.execute(text("ALTER TABLE targets ADD COLUMN is_active BOOLEAN DEFAULT 1"))
                    db.session.commit()
                if "deleted_at" not in target_cols:
                    app.logger.info("Migrating schema: adding deleted_at column to targets table.")
                    db.session.execute(text("ALTER TABLE targets ADD COLUMN deleted_at DATETIME"))
                    db.session.commit()

            # 3. Vulnerabilities table migrations
            if "vulnerabilities" in table_names:
                vuln_cols = {col["name"] for col in inspector.get_columns("vulnerabilities")}
                if "target_id" not in vuln_cols:
                    app.logger.info("Migrating schema: adding target_id column to vulnerabilities table.")
                    db.session.execute(text("ALTER TABLE vulnerabilities ADD COLUMN target_id INTEGER"))
                    db.session.commit()
                if "confidence" not in vuln_cols:
                    app.logger.info("Migrating schema: adding confidence column to vulnerabilities table.")
                    db.session.execute(text("ALTER TABLE vulnerabilities ADD COLUMN confidence VARCHAR(20) DEFAULT 'MEDIUM'"))
                    db.session.commit()
                if "scanner_module" not in vuln_cols:
                    app.logger.info("Migrating schema: adding scanner_module column to vulnerabilities table.")
                    db.session.execute(text("ALTER TABLE vulnerabilities ADD COLUMN scanner_module VARCHAR(64) DEFAULT 'vulnerability_manager'"))
                    db.session.commit()

            # Create any newly introduced tables (such as target_audit_logs, recon tables)
            db.create_all()
        except Exception as exc:
            db.session.rollback()
            app.logger.warning("Database schema check / migration note: %s", exc)
