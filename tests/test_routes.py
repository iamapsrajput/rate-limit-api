import unittest
import base64
import json
from app import create_app
from datetime import datetime, timedelta
from flask_jwt_extended import create_access_token
from app.utils.token_utils import generate_expired_token
import requests


class RoutesTestCase(unittest.TestCase):
    def setUp(self):
        # Create a test client for the Flask app
        self.app = create_app().test_client()
        self.app.testing = True  # Enable testing mode
        self.base_url = 'http://localhost:4000/api' # Base URL for API endpoints

    def test_random_route_within_limit(self):
        # Authenticate and get an access token
        login_data = {"username": "user1", "password": "password1"}
        login_response = requests.post(f"{self.base_url}/login", json=login_data)
        self.assertEqual(login_response.status_code, 200)
        access_token = login_response.json().get('access_token')

        # Send GET request to /random with the Bearer token
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(f"{self.base_url}/random", headers=headers)
        self.assertEqual(response.status_code, 200)

    # Test case to ensure rate limit exceeded when requesting random data
    def test_random_route_exceed_limit(self):
        # Authenticate and get an access token
        login_data = {"username": "user1", "password": "password1"}
        login_response = requests.post(f"{self.base_url}/login", json=login_data)
        self.assertEqual(login_response.status_code, 200)
        access_token = login_response.json().get('access_token')

        # Send GET request to /random?len=2048 with the Bearer token
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(f"{self.base_url}/random?len=2048", headers=headers)
        self.assertEqual(response.status_code, 429)
        self.assertIn('X-Rate-Limit', response.headers)

    def test_successful_login(self):
        response = self.app.post(
            '/api/login', json={'username': 'user1', 'password': 'password1'}
        )
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertIn('access_token', response_data)

    def test_wrong_credentials_login(self):
        response = self.app.post(
            '/api/login', json={'username': 'user1', 'password': 'wrong_password'}
        )
        self.assertEqual(response.status_code, 401)

    def test_missing_data_login(self):
        response = self.app.post('/api/login')
        self.assertEqual(response.status_code, 400)

    def test_missing_json_login(self):
        response = self.app.post(
            '/api/login', data={'username': 'user1', 'password': 'password1'}
        )
        self.assertEqual(response.status_code, 400)

    def test_random_data_with_token(self):
        with create_app().app_context():
            valid_token = create_access_token(identity='user1')
            response = self.app.get('/api/random', headers={"Authorization": f"Bearer {valid_token}"})
            # Verify that the response returns a rate limit exceeded error (status code 429)
            self.assertEqual(response.status_code, 429)

    def test_random_data_without_token(self):
        response = self.app.get('/api/random')
        self.assertEqual(response.status_code, 401)

    def test_random_data_with_expired_token(self):
        with create_app().app_context():
            expired_token = generate_expired_token('user1')
            headers = {"Authorization": f"Bearer {expired_token}"}
            response = self.app.get('/api/random', headers=headers)
            self.assertEqual(response.status_code, 401)

    def test_random_data_with_invalid_token(self):
        # Perform a request to request random data with an invalid token
        response = self.app.get('/api/random', headers={"Authorization": "Bearer invalid_token"})

        # Verify that the response returns an unprocessable entity error (status code 422)
        self.assertEqual(response.status_code, 422)

    def test_random_data_with_invalid_len(self):
        with create_app().app_context():
            # Generate an access token for a user
            user_access_token = create_access_token(identity='user1')
            headers = {
                "Authorization": f"Bearer {user_access_token}"
            }

            # Perform a request to request random data with an invalid length
            response = self.app.get('/api/random?len=100000000', headers=headers)

            # Verify that the response returns a rate limit exceeded error (status code 429)
            self.assertEqual(response.status_code, 429)

    def test_random_data_with_excessive_len(self):
        with create_app().app_context():
            user_access_token = create_access_token(identity='user1')
            headers = {
                "Authorization": f"Bearer {user_access_token}"
            }

            # Perform a request to get random data with an excessive length
            response = self.app.get('/api/random?len=5000', headers=headers)

            # Verify that the response returns a rate limit exceeded error (status code 429)
            self.assertEqual(response.status_code, 429)

    def test_admin_reset_rate_limit(self):
        with create_app().app_context():
            access_token = create_access_token(identity='admin')
            headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
            payload = {"client_username": "user1", "reset": True}
            response = self.app.post('/api/admin/rate-limit', headers=headers, data=json.dumps(payload))
            self.assertEqual(response.status_code, 200)

    def test_admin_set_new_rate_limit(self):
        with create_app().app_context():
            access_token = create_access_token(identity='admin')
            headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
            payload = {"client_username": "user1", "new_limit": 2048}
            response = self.app.post('/api/admin/rate-limit', headers=headers, data=json.dumps(payload))
            self.assertEqual(response.status_code, 200)

    def test_admin_reset_limit_without_token(self):
        response = self.app.post(
            '/api/admin/rate-limit', json={'client_username': 'user1', 'reset': True})
        self.assertEqual(response.status_code, 401)

    def test_admin_set_limit_without_token(self):
        response = self.app.post(
            '/api/admin/rate-limit', json={'client_username': 'user1', 'new_limit': 512})
        self.assertEqual(response.status_code, 401)

    def get_access_token(self, username, password):
        response = self.app.post(
            '/api/login', json={'username': username, 'password': password}
        )
        response_data = json.loads(response.data)
        return response_data.get('access_token', '')

    def test_access_with_expired_token(self):
        with create_app().app_context():
            expired_token = generate_expired_token('user1')
            headers = {"Authorization": f"Bearer {expired_token}"}
            response = self.app.get('/api/random', headers=headers)
            self.assertEqual(response.status_code, 401)

    def test_invalid_admin_reset_rate_limit(self):
        with create_app().app_context():
            # Generate an access token for a regular user (non-admin)
            user_access_token = create_access_token(identity='user1')
            headers = {
                "Authorization": f"Bearer {user_access_token}"
            }

            # Perform a request to reset the rate limit as a non-admin user
            response = self.app.post('/api/admin/rate-limit', json={"client_username": "user1", "reset": True}, headers=headers)

            # Verify that the response returns a forbidden error (status code 403)
            self.assertEqual(response.status_code, 403)

    def test_invalid_admin_set_new_rate_limit(self):
        with create_app().app_context():
            # Generate an access token for a regular user (non-admin)
            user_access_token = create_access_token(identity='user1')
            headers = {
                "Authorization": f"Bearer {user_access_token}"
            }

            # Perform a request to set a new rate limit as a non-admin user
            response = self.app.post('/api/admin/rate-limit', json={"client_username": "user1", "new_limit": 2048}, headers=headers)

            # Verify that the response returns a forbidden error (status code 403)
            self.assertEqual(response.status_code, 403)

    def test_exceed_rate_limit(self):
        with create_app().app_context():
            access_token = create_access_token(identity='user1')
            headers = {"Authorization": f"Bearer {access_token}"}

            # Perform requests that exceed the rate limit
            response1 = self.app.get('/api/random?len=512', headers=headers)
            response2 = self.app.get('/api/random?len=512', headers=headers)
            response3 = self.app.get('/api/random?len=512', headers=headers)

            # Verify that the last response returns a rate limit exceeded error (status code 429)
            self.assertEqual(response3.status_code, 429)

    def test_invalid_json_payload_admin_reset_limit(self):
        with create_app().app_context():
            admin_access_token = create_access_token(identity='admin')
            headers = {
                "Authorization": f"Bearer {admin_access_token}",
                "Content-Type": "application/json"
            }

            # Perform a request to reset the rate limit with an invalid JSON payload
            response = self.app.post('/api/admin/rate-limit', data="invalid json", headers=headers)

            # Verify that the response returns a bad request error (status code 400)
            self.assertEqual(response.status_code, 400)

    # Test case to ensure invalid content type is handled when resetting rate limit
    def test_invalid_content_type_admin_reset_limit(self):
        with create_app().app_context():
            # Generate an access token for an admin user
            admin_access_token = create_access_token(identity='admin')
            headers = {
                "Authorization": f"Bearer {admin_access_token}",
                "Content-Type": "application/xml"  # Use an invalid content type here
            }

            # Perform a request to reset the rate limit with an invalid content type
            response = self.app.post('/api/admin/rate-limit', headers=headers)

            # Verify that the response returns a bad request error (status code 400)
            self.assertEqual(response.status_code, 400)


if __name__ == '__main__':
    unittest.main()
