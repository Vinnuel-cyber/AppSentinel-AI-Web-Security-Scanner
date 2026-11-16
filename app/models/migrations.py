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

            # 4. OWASP Assessment table migrations
            if "owasp_assessments" in table_names:
                owasp_cols = {col["name"] for col in inspector.get_columns("owasp_assessments")}
                if "framework_version" not in owasp_cols:
                    app.logger.info("Migrating schema: adding framework_version column to owasp_assessments table.")
                    db.session.execute(text("ALTER TABLE owasp_assessments ADD COLUMN framework_version VARCHAR(32) DEFAULT '2025'"))
                    db.session.commit()

            if "owasp_finding_mappings" in table_names:
                map_cols = {col["name"] for col in inspector.get_columns("owasp_finding_mappings")}
                if "framework_version" not in map_cols:
                    app.logger.info("Migrating schema: adding framework_version column to owasp_finding_mappings table.")
                    db.session.execute(text("ALTER TABLE owasp_finding_mappings ADD COLUMN framework_version VARCHAR(32) DEFAULT '2025'"))
                    db.session.commit()

            # 5. Reports table migrations (V9 report metadata & integrity)
            if "reports" in table_names:
                report_cols = {col["name"] for col in inspector.get_columns("reports")}
                if "target_id" not in report_cols:
                    app.logger.info("Migrating schema: adding target_id column to reports table.")
                    db.session.execute(text("ALTER TABLE reports ADD COLUMN target_id INTEGER"))
                    db.session.commit()
                if "report_type" not in report_cols:
                    app.logger.info("Migrating schema: adding report_type column to reports table.")
                    db.session.execute(text("ALTER TABLE reports ADD COLUMN report_type VARCHAR(50) DEFAULT 'COMPLETE'"))
                    db.session.commit()
                if "report_filename" not in report_cols:
                    app.logger.info("Migrating schema: adding report_filename column to reports table.")
                    db.session.execute(text("ALTER TABLE reports ADD COLUMN report_filename VARCHAR(255)"))
                    db.session.commit()
                if "report_status" not in report_cols:
                    app.logger.info("Migrating schema: adding report_status column to reports table.")
                    db.session.execute(text("ALTER TABLE reports ADD COLUMN report_status VARCHAR(30) DEFAULT 'COMPLETED'"))
                    db.session.commit()
                if "file_hash" not in report_cols:
                    app.logger.info("Migrating schema: adding file_hash column to reports table.")
                    db.session.execute(text("ALTER TABLE reports ADD COLUMN file_hash VARCHAR(64)"))
                    db.session.commit()
                if "file_size_bytes" not in report_cols:
                    app.logger.info("Migrating schema: adding file_size_bytes column to reports table.")
                    db.session.execute(text("ALTER TABLE reports ADD COLUMN file_size_bytes INTEGER DEFAULT 0"))
                    db.session.commit()
                if "meta_json" not in report_cols:
                    app.logger.info("Migrating schema: adding meta_json column to reports table.")
                    db.session.execute(text("ALTER TABLE reports ADD COLUMN meta_json TEXT"))
                    db.session.commit()

            # 6. AI Analysis table migrations (V8 analyst metadata & telemetry)
            if "ai_analysis" in table_names:
                ai_cols = {col["name"] for col in inspector.get_columns("ai_analysis")}
                if "target_id" not in ai_cols:
                    app.logger.info("Migrating schema: adding target_id column to ai_analysis table.")
                    db.session.execute(text("ALTER TABLE ai_analysis ADD COLUMN target_id INTEGER"))
                    db.session.commit()
                if "user_id" not in ai_cols:
                    app.logger.info("Migrating schema: adding user_id column to ai_analysis table.")
                    db.session.execute(text("ALTER TABLE ai_analysis ADD COLUMN user_id INTEGER"))
                    db.session.commit()
                if "analysis_type" not in ai_cols:
                    app.logger.info("Migrating schema: adding analysis_type column to ai_analysis table.")
                    db.session.execute(text("ALTER TABLE ai_analysis ADD COLUMN analysis_type VARCHAR(64) DEFAULT 'vulnerability_explanation'"))
                    db.session.commit()
                if "provider" not in ai_cols:
                    app.logger.info("Migrating schema: adding provider column to ai_analysis table.")
                    db.session.execute(text("ALTER TABLE ai_analysis ADD COLUMN provider VARCHAR(50) DEFAULT 'deterministic-fallback'"))
                    db.session.commit()
                if "status" not in ai_cols:
                    app.logger.info("Migrating schema: adding status column to ai_analysis table.")
                    db.session.execute(text("ALTER TABLE ai_analysis ADD COLUMN status VARCHAR(30) DEFAULT 'COMPLETED'"))
                    db.session.commit()
                if "ai_confidence" not in ai_cols:
                    app.logger.info("Migrating schema: adding ai_confidence column to ai_analysis table.")
                    db.session.execute(text("ALTER TABLE ai_analysis ADD COLUMN ai_confidence VARCHAR(20) DEFAULT 'MEDIUM'"))
                    db.session.commit()
                if "evidence_assessment" not in ai_cols:
                    app.logger.info("Migrating schema: adding evidence_assessment column to ai_analysis table.")
                    db.session.execute(text("ALTER TABLE ai_analysis ADD COLUMN evidence_assessment TEXT"))
                    db.session.commit()
                if "evidence_limitations" not in ai_cols:
                    app.logger.info("Migrating schema: adding evidence_limitations column to ai_analysis table.")
                    db.session.execute(text("ALTER TABLE ai_analysis ADD COLUMN evidence_limitations TEXT"))
                    db.session.commit()
                if "structured_result" not in ai_cols:
                    app.logger.info("Migrating schema: adding structured_result column to ai_analysis table.")
                    db.session.execute(text("ALTER TABLE ai_analysis ADD COLUMN structured_result TEXT"))
                    db.session.commit()

            # Create any newly introduced tables (such as target_audit_logs, recon tables)
            db.create_all()
        except Exception as exc:
            db.session.rollback()
            app.logger.warning("Database schema check / migration note: %s", exc)
