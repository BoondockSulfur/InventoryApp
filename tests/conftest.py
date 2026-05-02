import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app as flask_app, db as _db
from app import User, Item, Loan, Role, Permission


@pytest.fixture(scope='session')
def app():
    """Create application for the tests."""
    flask_app.config['TESTING'] = True
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    flask_app.config['WTF_CSRF_ENABLED'] = False
    flask_app.config['SECRET_KEY'] = 'test-secret-key'

    ctx = flask_app.app_context()
    ctx.push()

    yield flask_app

    ctx.pop()


@pytest.fixture(scope='session')
def db(app):
    """Create database for the tests."""
    _db.create_all()

    # Create roles
    roles = [
        Role(name='admin'),
        Role(name='verwaltung'),
        Role(name='mitarbeiter'),
        Role(name='kunde')
    ]
    for role in roles:
        _db.session.add(role)

    # Create permissions
    permissions = [
        Permission(name='manage_items', description='Manage items'),
        Permission(name='manage_users', description='Manage users'),
        Permission(name='view_logs', description='View audit logs'),
        Permission(name='manage_settings', description='Manage settings'),
    ]
    for perm in permissions:
        _db.session.add(perm)

    _db.session.commit()

    yield _db

    _db.drop_all()


@pytest.fixture(scope='function')
def session(db):
    """Create a new database session for a test."""
    connection = db.engine.connect()
    transaction = connection.begin()

    session = db.session
    session.begin_nested()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def admin_user(db):
    """Create admin user for tests."""
    user = User(username='admin', email='admin@test.com', role='admin')
    user.set_password('AdminPass123!')
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def regular_user(db):
    """Create regular user for tests."""
    user = User(username='user', email='user@test.com', role='kunde')
    user.set_password('UserPass123!')
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def test_item(db):
    """Create test item."""
    item = Item(
        name='Test Laptop',
        serial='TEST123',
        location='Office',
        category='laptop',
        is_borrowed=False,
        defective=False
    )
    db.session.add(item)
    db.session.commit()
    return item
