from flask import Blueprint, jsonify

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/status", methods=["GET"])
def auth_status():
    return jsonify({
        "module": "Authentication",
        "version_target": "V2",
        "status": "ready_for_implementation",
    })
