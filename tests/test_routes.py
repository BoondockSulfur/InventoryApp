import pytest
from flask import url_for


class TestAuthRoutes:
    def test_login_page_loads(self, client):
        """Test that login page loads successfully."""
        response = client.get('/login')
        assert response.status_code == 200
        assert b'Benutzername' in response.data or b'Login' in response.data

    def test_login_with_valid_credentials(self, client, admin_user):
        """Test login with valid credentials."""
        response = client.post('/login', data={
            'username': 'admin',
            'password': 'AdminPass123!'
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_login_with_invalid_credentials(self, client, admin_user):
        """Test login with invalid credentials."""
        response = client.post('/login', data={
            'username': 'admin',
            'password': 'wrongpassword'
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'Ung' in response.data or b'Invalid' in response.data

    def test_logout(self, client, admin_user):
        """Test logout functionality."""
        # Login first
        client.post('/login', data={
            'username': 'admin',
            'password': 'AdminPass123!'
        })

        # Then logout
        response = client.get('/logout', follow_redirects=True)
        assert response.status_code == 200


class TestItemRoutes:
    def test_items_page_requires_auth(self, client):
        """Test that items page requires authentication."""
        response = client.get('/items')
        assert response.status_code == 302  # Redirect to login

    def test_items_page_with_auth(self, client, admin_user):
        """Test items page with authentication."""
        # Login
        client.post('/login', data={
            'username': 'admin',
            'password': 'AdminPass123!'
        })

        response = client.get('/items')
        assert response.status_code == 200

    def test_item_detail_requires_auth(self, client, test_item):
        """Test that item detail page requires authentication."""
        response = client.get(f'/item/{test_item.id}')
        assert response.status_code == 302  # Redirect to login


class TestDashboard:
    def test_dashboard_requires_auth(self, client):
        """Test that dashboard requires authentication."""
        response = client.get('/dashboard')
        assert response.status_code == 302  # Redirect to login

    def test_dashboard_with_auth(self, client, admin_user):
        """Test dashboard with authentication."""
        # Login
        client.post('/login', data={
            'username': 'admin',
            'password': 'AdminPass123!'
        })

        response = client.get('/dashboard')
        assert response.status_code == 200


class TestErrorHandlers:
    def test_404_error(self, client):
        """Test 404 error handler."""
        response = client.get('/nonexistent-page')
        assert response.status_code == 404
