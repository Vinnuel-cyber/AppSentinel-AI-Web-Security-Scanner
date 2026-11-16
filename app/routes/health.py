from datetime import datetime, timezone
import time
from flask import Blueprint, jsonify, current_app
from sqlalchemy import text
from app.models import db

health_bp = Blueprint("health", __name__)
_START_TIME = time.time()


@health_bp.route("/", methods=["GET"])
def index():
    return jsonify({
        "app": "AppSentinel",
        "name": "AI-Powered Web Application Security Scanner",
        "version": "1.0.0-V1",
        "status": "operational",
        "health_check": "/api/health",
    })


@health_bp.route("/api/health", methods=["GET"])
def health_check():
    db_status = "disconnected"
    db_engine = "unknown"
    db_latency_ms = 0
    error_detail = None
    
    t0 = time.time()
    try:
        # Probe database with lightweight ping query
        db.session.execute(text("SELECT 1"))
        db_latency_ms = round((time.time() - t0) * 1000, 2)
        db_status = "connected"
        bind = db.session.get_bind()
        db_engine = bind.dialect.name if bind else "unknown"
    except Exception as exc:
        error_detail = str(exc)
        current_app.logger.warning("Database health-check probe failed: %s", exc)

    uptime_seconds = int(time.time() - _START_TIME)

    response = {
        "status": "healthy" if db_status == "connected" else "degraded",
        "application": "AppSentinel",
        "version": "1.0.0-V1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": uptime_seconds,
        "database": {
            "status": db_status,
            "engine": db_engine,
            "latency_ms": db_latency_ms,
        },
    }
    
    if error_detail:
        response["database"]["error"] = error_detail

    status_code = 200 if db_status == "connected" else 503
    return jsonify(response), status_code
