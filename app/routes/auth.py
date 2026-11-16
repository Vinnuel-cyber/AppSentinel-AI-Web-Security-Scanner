from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    session,
    jsonify,
    current_app,
    abort,
)
from flask_login import login_user, logout_user, login_required, current_user
from app.models import db, User
from app.security.forms import RegistrationForm, LoginForm, LogoutForm
from app.security.access_control import login_rate_limiter, admin_required

auth_bp = Blueprint("auth", __name__)


def is_safe_redirect_url(target: str) -> bool:
    """Prevent Open Redirect vulnerabilities by verifying relative URL."""
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


@auth_bp.route("/auth/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("auth.profile"))

    form = RegistrationForm()

    if request.is_json:
        data = request.get_json() or {}
        form.full_name.data = data.get("full_name")
        form.username.data = data.get("username")
        form.email.data = data.get("email")
        form.password.data = data.get("password")
        form.confirm_password.data = data.get("confirm_password")

    if form.validate_on_submit():
        user = User(
            full_name=form.full_name.data.strip(),
            username=form.username.data.strip(),
            email=form.email.data.strip().lower(),
            role="USER",  # Strict: registration always creates standard USER
            is_active=True,
        )
        try:
            user.set_password(form.password.data, enforce_complexity=True)
            db.session.add(user)
            db.session.commit()
            current_app.logger.info("New user registered: username=%s email=%s", user.username, user.email)
            
            if request.is_json:
                return jsonify({"status": "success", "message": "Registration successful.", "user": user.to_dict()}), 201

            flash("Registration successful! Please log in with your credentials.", "success")
            return redirect(url_for("auth.login"))
        except Exception as exc:
            db.session.rollback()
            current_app.logger.error("Registration error: %s", exc)
            if request.is_json:
                return jsonify({"error": "Registration Error", "message": str(exc)}), 400
            flash(f"Error creating account: {exc}", "danger")

    if request.is_json and form.errors:
        return jsonify({"error": "Validation Error", "errors": form.errors}), 400

    return render_template("auth/register.html", form=form)


@auth_bp.route("/auth/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("auth.profile"))

    form = LoginForm()
    ip_key = request.remote_addr or "127.0.0.1"

    if request.is_json:
        data = request.get_json() or {}
        form.login_id.data = data.get("login_id") or data.get("username") or data.get("email")
        form.password.data = data.get("password")
        form.remember_me.data = data.get("remember_me", False)

    if form.validate_on_submit():
        login_input = form.login_id.data.strip()
        limiter_key = f"{ip_key}:{login_input.lower()}"

        if login_rate_limiter.is_rate_limited(limiter_key):
            retry_after = login_rate_limiter.retry_after(limiter_key)
            msg = f"Too many failed login attempts. Please try again in {retry_after} seconds."
            if request.is_json:
                return jsonify({"error": "Rate Limited", "message": msg, "retry_after": retry_after}), 429
            flash(msg, "danger")
            return render_template("auth/login.html", form=form), 429

        # Case-insensitive search on username or email
        user = User.query.filter(
            (User.username.ilike(login_input)) | (User.email.ilike(login_input))
        ).first()

        # Generic authentication failure message to prevent user enumeration
        generic_error = "Invalid username/email or password."

        if not user or not user.check_password(form.password.data):
            login_rate_limiter.record_attempt(limiter_key)
            current_app.logger.warning("Failed login attempt for identifier=%s from ip=%s", login_input, ip_key)
            if request.is_json:
                return jsonify({"error": "Authentication Failed", "message": generic_error}), 401
            flash(generic_error, "danger")
            return render_template("auth/login.html", form=form), 401

        if not user.is_active:
            current_app.logger.warning("Login attempt on inactive account user_id=%s", user.id)
            inactive_msg = "Your account is disabled. Please contact the administrator."
            if request.is_json:
                return jsonify({"error": "Account Inactive", "message": inactive_msg}), 403
            flash(inactive_msg, "warning")
            return render_template("auth/login.html", form=form), 403

        # Success: reset rate limiter, regenerate session, login user
        login_rate_limiter.reset(limiter_key)
        session.clear()
        login_user(user, remember=form.remember_me.data)
        user.record_login()
        current_app.logger.info("User logged in successfully: user_id=%s role=%s", user.id, user.role)

        next_page = request.args.get("next")
        if not is_safe_redirect_url(next_page):
            next_page = url_for("auth.profile")

        if request.is_json:
            return jsonify({"status": "success", "message": "Login successful.", "user": user.to_dict(), "next": next_page}), 200

        flash(f"Welcome back, {user.full_name or user.username}!", "success")
        return redirect(next_page)

    if request.is_json and form.errors:
        return jsonify({"error": "Validation Error", "errors": form.errors}), 400

    return render_template("auth/login.html", form=form)


@auth_bp.route("/auth/logout", methods=["POST"])
@login_required
def logout():
    """Secure logout requiring POST and CSRF validation."""
    current_app.logger.info("User logged out: user_id=%s", current_user.id)
    logout_user()
    session.clear()

    if request.is_json:
        return jsonify({"status": "success", "message": "Successfully logged out."}), 200

    flash("You have been signed out safely.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/profile", methods=["GET"])
@login_required
def profile():
    """Display authenticated user profile."""
    if request.is_json:
        return jsonify({"user": current_user.to_dict()}), 200
    logout_form = LogoutForm()
    return render_template("profile.html", user=current_user, logout_form=logout_form)


@auth_bp.route("/admin/users", methods=["GET"])
@admin_required
def admin_users():
    """Administrative user management endpoint."""
    users = User.query.order_by(User.created_at.desc()).all()
    if request.is_json:
        return jsonify({"total_users": len(users), "users": [u.to_dict() for u in users]}), 200
    logout_form = LogoutForm()
    return render_template("admin/users.html", users=users, logout_form=logout_form)
