from datetime import datetime, timezone
from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    jsonify,
    current_app,
    abort,
)
from flask_login import login_required, current_user
from app.models import db, Target, TargetAuditLog, Scan
from app.security.forms import AddTargetForm, EditTargetForm, VerifyTargetForm, DeleteTargetForm
from app.security.target_validator import TargetValidator, TargetValidationError

targets_bp = Blueprint("targets", __name__, url_prefix="/targets")


def get_target_or_404(target_id: int) -> Target:
    """Fetch active target and enforce ownership or admin authorization."""
    target = Target.query.filter_by(id=target_id, is_active=True).first_or_404()
    
    # Ownership authorization check
    if target.owner_id != current_user.id and not current_user.is_admin():
        current_app.logger.warning(
            "Access violation: User %s attempted unauthorized access to Target %s owned by %s",
            current_user.id, target.id, target.owner_id
        )
        if request.is_json:
            abort(403)
        abort(403)
    return target


@targets_bp.route("", methods=["GET"])
@login_required
def index():
    """List registered targets with search and filtering."""
    query = Target.query.filter_by(is_active=True)
    
    # Non-admin users can only view their own targets
    if not current_user.is_admin():
        query = query.filter_by(owner_id=current_user.id)

    # Search filter
    search_term = request.args.get("q", "").strip()
    if search_term:
        query = query.filter(
            (Target.name.ilike(f"%{search_term}%")) | (Target.domain.ilike(f"%{search_term}%"))
        )

    # Status filter
    status_filter = request.args.get("status", "").strip()
    if status_filter == "verified":
        query = query.filter_by(is_verified=True)
    elif status_filter == "pending":
        query = query.filter_by(is_verified=False)

    # Environment filter
    env_filter = request.args.get("environment", "").strip()
    if env_filter in ("Development", "Staging", "Production"):
        query = query.filter_by(environment=env_filter)

    targets = query.order_by(Target.created_at.desc()).all()

    if request.is_json:
        return jsonify({
            "total_targets": len(targets),
            "targets": [t.to_dict() for t in targets],
        }), 200

    delete_form = DeleteTargetForm()
    return render_template(
        "targets/index.html",
        targets=targets,
        search_term=search_term,
        status_filter=status_filter,
        env_filter=env_filter,
        delete_form=delete_form,
    )


@targets_bp.route("/add", methods=["GET", "POST"])
@login_required
def add():
    """Register a new web application target."""
    form = AddTargetForm()

    if request.is_json:
        data = request.get_json() or {}
        form.name.data = data.get("name")
        form.target_url.data = data.get("target_url") or data.get("url")
        form.description.data = data.get("description", "")
        form.environment.data = data.get("environment", "Production")
        form.authorization_confirmed.data = data.get("authorization_confirmed", False)

    if form.validate_on_submit():
        raw_url = form.target_url.data.strip()
        allow_private = current_app.config.get("SCANNER_ALLOW_PRIVATE_IPS", False)

        try:
            # 1. Centralized target security validation & SSRF prevention
            normalized_url, domain, resolved_ips = TargetValidator.validate_target_url(
                raw_url, allow_private=allow_private
            )
        except TargetValidationError as exc:
            msg = str(exc)
            if request.is_json:
                return jsonify({"error": "Security Validation Error", "message": msg}), 400
            flash(f"Target URL rejected by security validator: {msg}", "danger")
            return render_template("targets/add.html", form=form), 400

        # 2. Check for duplicate target for the same owner
        existing = Target.query.filter_by(
            owner_id=current_user.id,
            domain=domain,
            is_active=True,
        ).first()

        if existing:
            err_msg = f"You have already registered an active target for domain '{domain}' (Target #{existing.id})."
            if request.is_json:
                return jsonify({"error": "Duplicate Target", "message": err_msg}), 400
            flash(err_msg, "warning")
            return render_template("targets/add.html", form=form), 400

        # 3. Create Target record with PENDING_VERIFICATION status
        target = Target(
            owner_id=current_user.id,
            name=form.name.data.strip(),
            target_url=normalized_url,
            domain=domain,
            description=form.description.data.strip() if form.description.data else None,
            environment=form.environment.data,
            verification_status="PENDING_VERIFICATION",
            is_verified=False,
            is_active=True,
        )
        db.session.add(target)
        db.session.flush()

        # 4. Audit Log
        audit = TargetAuditLog(
            target_id=target.id,
            user_id=current_user.id,
            action="CREATED",
            details=f"Target registered: {target.name} ({target.domain}, {target.environment})",
        )
        db.session.add(audit)
        db.session.commit()

        current_app.logger.info("Target registered: id=%s domain=%s by user=%s", target.id, target.domain, current_user.id)

        if request.is_json:
            return jsonify({
                "status": "success",
                "message": "Target registered successfully. Please complete ownership verification.",
                "target": target.to_dict(),
            }), 201

        flash("Target created successfully! Please verify ownership before launching active scans.", "success")
        return redirect(url_for("targets.verification_instructions", target_id=target.id))

    if request.is_json and form.errors:
        return jsonify({"error": "Validation Error", "errors": form.errors}), 400

    return render_template("targets/add.html", form=form)


@targets_bp.route("/<int:target_id>", methods=["GET"])
@login_required
def details(target_id: int):
    """View comprehensive target details and scan history."""
    target = get_target_or_404(target_id)
    verify_form = VerifyTargetForm()
    delete_form = DeleteTargetForm()
    logs = target.audit_logs.order_by(TargetAuditLog.timestamp.desc()).limit(20).all()
    scans = target.scans.order_by(Scan.created_at.desc()).limit(10).all()

    if request.is_json:
        return jsonify({
            "target": target.to_dict(),
            "audit_logs": [l.to_dict() for l in logs],
            "total_scans": target.scans.count(),
        }), 200

    return render_template(
        "targets/details.html",
        target=target,
        verify_form=verify_form,
        delete_form=delete_form,
        audit_logs=logs,
        scans=scans,
    )


@targets_bp.route("/<int:target_id>/edit", methods=["GET", "POST"])
@login_required
def edit(target_id: int):
    """Edit target metadata (Name, Description, Environment)."""
    target = get_target_or_404(target_id)
    form = EditTargetForm(obj=target)

    if request.is_json:
        data = request.get_json() or {}
        form.name.data = data.get("name", target.name)
        form.description.data = data.get("description", target.description)
        form.environment.data = data.get("environment", target.environment)

    if form.validate_on_submit():
        target.name = form.name.data.strip()
        target.description = form.description.data.strip() if form.description.data else None
        target.environment = form.environment.data
        target.updated_at = datetime.now(timezone.utc)

        audit = TargetAuditLog(
            target_id=target.id,
            user_id=current_user.id,
            action="UPDATED",
            details=f"Metadata updated: Name='{target.name}', Env='{target.environment}'",
        )
        db.session.add(audit)
        db.session.commit()

        if request.is_json:
            return jsonify({"status": "success", "message": "Target updated.", "target": target.to_dict()}), 200

        flash("Target settings updated successfully.", "success")
        return redirect(url_for("targets.details", target_id=target.id))

    if request.is_json and form.errors:
        return jsonify({"error": "Validation Error", "errors": form.errors}), 400

    return render_template("targets/edit.html", target=target, form=form)


@targets_bp.route("/<int:target_id>/delete", methods=["POST"])
@login_required
def delete(target_id: int):
    """Soft-delete target while preserving historical scan records."""
    target = get_target_or_404(target_id)
    form = DeleteTargetForm()

    if not request.is_json and not form.validate_on_submit():
        flash("CSRF validation failed for target deletion.", "danger")
        return redirect(url_for("targets.details", target_id=target.id))

    target.soft_delete()

    audit = TargetAuditLog(
        target_id=target.id,
        user_id=current_user.id,
        action="DELETED",
        details=f"Target '{target.name}' ({target.domain}) was soft-deleted by user {current_user.username}",
    )
    db.session.add(audit)
    db.session.commit()

    current_app.logger.info("Target soft-deleted: id=%s by user=%s", target.id, current_user.id)

    if request.is_json:
        return jsonify({"status": "success", "message": f"Target #{target.id} was successfully deleted."}), 200

    flash(f"Target '{target.name}' has been deleted.", "info")
    return redirect(url_for("targets.index"))


@targets_bp.route("/<int:target_id>/verify", methods=["POST"])
@login_required
def verify(target_id: int):
    """Attempt ownership verification via DNS TXT or HTTP well-known file."""
    target = get_target_or_404(target_id)
    form = VerifyTargetForm()

    method = form.method.data if form.method.data else "http_well_known"
    if request.is_json:
        data = request.get_json() or {}
        method = data.get("method", "http_well_known")

    if target.is_token_expired():
        new_token = target.regenerate_verification_token()
        msg = "The verification token had expired. A new token has been generated. Please update your verification record."
        audit = TargetAuditLog(
            target_id=target.id,
            user_id=current_user.id,
            action="VERIFY_FAILED",
            details="Token expired; regenerated new token.",
        )
        db.session.add(audit)
        db.session.commit()

        if request.is_json:
            return jsonify({"status": "expired", "message": msg, "new_token": new_token}), 400
        flash(msg, "warning")
        return redirect(url_for("targets.verification_instructions", target_id=target.id))

    # Perform verification
    success = False
    details_msg = ""

    if method == "http_well_known":
        success, details_msg = TargetValidator.verify_ownership_via_http(
            target.domain, target.verification_token
        )
    elif method == "dns_txt":
        success, details_msg = TargetValidator.verify_ownership_via_dns(
            target.domain, target.verification_token
        )
    else:
        details_msg = "Unknown verification method specified."

    if success:
        target.mark_verified(method=method)
        audit = TargetAuditLog(
            target_id=target.id,
            user_id=current_user.id,
            action="VERIFY_SUCCESS",
            details=f"Ownership verified via {method}. Details: {details_msg}",
        )
        db.session.add(audit)
        db.session.commit()
        current_app.logger.info("Target ownership verified: id=%s domain=%s", target.id, target.domain)

        if request.is_json:
            return jsonify({"status": "verified", "message": details_msg, "target": target.to_dict()}), 200

        flash(f"Success! {details_msg}", "success")
        return redirect(url_for("targets.details", target_id=target.id))
    else:
        audit = TargetAuditLog(
            target_id=target.id,
            user_id=current_user.id,
            action="VERIFY_FAILED",
            details=f"Verification failed using {method}. Reason: {details_msg}",
        )
        db.session.add(audit)
        db.session.commit()

        if request.is_json:
            return jsonify({"status": "failed", "message": details_msg}), 400

        flash(f"Verification failed: {details_msg}", "danger")
        return redirect(url_for("targets.verification_instructions", target_id=target.id))


@targets_bp.route("/<int:target_id>/verification-instructions", methods=["GET"])
@login_required
def verification_instructions(target_id: int):
    """Provide detailed, actionable instructions for DNS and HTTP token placement."""
    target = get_target_or_404(target_id)
    verify_form = VerifyTargetForm()
    return render_template(
        "targets/verification_instructions.html",
        target=target,
        verify_form=verify_form,
    )
