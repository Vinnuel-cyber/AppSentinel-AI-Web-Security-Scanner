import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Regexp
from app.models.user import User


class RegistrationForm(FlaskForm):
    full_name = StringField(
        "Full Name",
        validators=[
            DataRequired(message="Full name is required."),
            Length(min=2, max=120, message="Full name must be between 2 and 120 characters."),
        ],
    )
    username = StringField(
        "Username",
        validators=[
            DataRequired(message="Username is required."),
            Length(min=3, max=64, message="Username must be between 3 and 64 characters."),
            Regexp(r"^[A-Za-z0-9_.-]+$", message="Username may only contain letters, numbers, dots, hyphens, and underscores."),
        ],
    )
    email = StringField(
        "Email Address",
        validators=[
            DataRequired(message="Email address is required."),
            Email(message="Please provide a valid email address."),
            Length(max=120, message="Email must not exceed 120 characters."),
        ],
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(message="Password is required."),
            Length(min=8, max=128, message="Password must be at least 8 characters long."),
        ],
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(message="Please confirm your password."),
            EqualTo("password", message="Passwords must match."),
        ],
    )
    submit = SubmitField("Create Account")

    def validate_username(self, field):
        user = User.query.filter(User.username.ilike(field.data.strip())).first()
        if user:
            raise ValidationError("This username is already taken. Please choose another.")

    def validate_email(self, field):
        user = User.query.filter(User.email.ilike(field.data.strip())).first()
        if user:
            raise ValidationError("An account with this email address already exists.")

    def validate_password(self, field):
        valid, msg = User.validate_password_strength(field.data)
        if not valid:
            raise ValidationError(msg)


class LoginForm(FlaskForm):
    login_id = StringField(
        "Username or Email",
        validators=[
            DataRequired(message="Username or email is required."),
            Length(min=3, max=120, message="Input length is invalid."),
        ],
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(message="Password is required."),
        ],
    )
    remember_me = BooleanField("Remember this device")
    submit = SubmitField("Sign In")


class LogoutForm(FlaskForm):
    """CSRF-protected logout form."""
    pass
