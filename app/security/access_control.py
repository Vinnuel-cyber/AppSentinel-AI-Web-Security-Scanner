import time
from functools import wraps
from collections import defaultdict
from flask import abort, flash, redirect, url_for, request, current_app, jsonify
from flask_login import current_user, login_required


class LoginRateLimiter:
    """Sliding-window rate limiter for authentication attempts."""
    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.attempts = defaultdict(list)

    def _clean_old(self, key: str, now: float):
        self.attempts[key] = [t for t in self.attempts[key] if now - t < self.window_seconds]

    def is_rate_limited(self, key: str) -> bool:
        now = time.time()
        self._clean_old(key, now)
        return len(self.attempts[key]) >= self.max_attempts

    def record_attempt(self, key: str) -> None:
        now = time.time()
        self._clean_old(key, now)
        self.attempts[key].append(now)

    def reset(self, key: str) -> None:
        self.attempts.pop(key, None)

    def retry_after(self, key: str) -> int:
        now = time.time()
        self._clean_old(key, now)
        if not self.attempts[key]:
            return 0
        oldest = min(self.attempts[key])
        return max(1, int(self.window_seconds - (now - oldest)))


login_rate_limiter = LoginRateLimiter(max_attempts=5, window_seconds=300)


def role_required(*allowed_roles: str):
    """Decorator to enforce role-based access control (RBAC)."""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for("auth.login", next=request.url))
            
            user_role = (current_user.role or "").upper()
            normalized_allowed = [r.upper() for r in allowed_roles]
            
            if user_role not in normalized_allowed:
                current_app.logger.warning(
                    "Unauthorized RBAC access attempt by user_id=%s (role=%s) on endpoint=%s",
                    current_user.id,
                    user_role,
                    request.endpoint,
                )
                if request.is_json:
                    return jsonify({"error": "Forbidden", "message": "You do not have permission to access this resource."}), 403
                abort(403)
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    """Convenience decorator restricting access strictly to ADMIN users."""
    return role_required("ADMIN")(f)
