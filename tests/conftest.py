import pytest
from app import create_app
from app.models import db, User, Target, ScanSetting


@pytest.fixture(scope="session")
def app():
    """Create and configure a clean testing Flask app."""
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture(scope="function")
def client(app):
    """A test client for the app with transaction rollback per test."""
    with app.app_context():
        # Clean state per test
        db.drop_all()
        db.create_all()
        yield app.test_client()
        db.session.remove()


@pytest.fixture
def runner(app):
    """A test CLI runner for the app."""
    return app.test_cli_runner()
