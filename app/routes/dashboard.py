from flask import Blueprint, jsonify

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")


@dashboard_bp.route("/status", methods=["GET"])
def dashboard_status():
    return jsonify({
        "module": "Security Dashboard",
        "version_target": "V3",
        "status": "ready_for_implementation",
    })
