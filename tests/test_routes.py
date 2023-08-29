import unittest
import json
from app import create_app
from flask_jwt_extended import create_access_token
from app.utils.token_utils import generate_expired_token
import requests


class RoutesTestCase(unittest.TestCase):
    def setUp(self):
        # Create a test client for the Flask app
        self.app = create_app().test_client()
        self.app.testing = True  # Enable testing mode
        self.base_url = 'http://localhost:4000/api'  # Base URL for API endpoints

    # Test case to verify random data is returned when requesting random data within the rate limit
    def test_random_route_within_limit(self):
        # Authenticate and get an access token
        login_data = {"username": "user1", "password": "password1"}
        login_response = requests.post(
            f"{self.base_url}/login", json=login_data)
        self.assertEqual(login_response.status_code, 200)
        access_token = login_response.json().get('access_token')

        # Send GET request to /random with the Bearer token
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(f"{self.base_url}/random", headers=headers)
        self.assertEqual(response.status_code, 200)

    # Test case to verify rate limit exceeded when requesting random data with excessive length
    def test_random_route_exceed_limit(self):
        # Authenticate and get an access token
        login_data = {"username": "user1", "password": "password1"}
        login_response = requests.post(
            f"{self.base_url}/login", json=login_data)
        self.assertEqual(login_response.status_code, 200)
        access_token = login_response.json().get('access_token')

        # Send GET request to /random?len=2048 with the Bearer token
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(
            f"{self.base_url}/random?len=2048", headers=headers)
        self.assertEqual(response.status_code, 429)
        self.assertIn('X-Rate-Limit', response.headers)

    # Test case to verify the successful login with status code for valid credentials
    def test_successful_login(self):
        response = self.app.post(
            '/api/login', json={'username': 'user1', 'password': 'password1'}
        )
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertIn('access_token', response_data)

    # Test case to verify the unsuccessful login with status code for invalid credentials
    def test_wrong_credentials_login(self):
        response = self.app.post(
            '/api/login', json={'username': 'user1', 'password': 'wrong_password'}
        )
        self.assertEqual(response.status_code, 401)

    # Test case to verify the unsuccessful login with status code for missing credentials
    def test_missing_data_login(self):
        response = self.app.post('/api/login')
        self.assertEqual(response.status_code, 400)

    # Test case to verify the unsuccessful login with status code for missing JSON data
    def test_missing_json_login(self):
        response = self.app.post(
            '/api/login', data={'username': 'user1', 'password': 'password1'}
        )
        self.assertEqual(response.status_code, 400)

    # Test case to verify the rate limit exceeded error status code for random data with token
    def test_random_data_with_token(self):
        with create_app().app_context():
            valid_token = create_access_token(identity='user1')
            response = self.app.get(
                '/api/random', headers={"Authorization": f"Bearer {valid_token}"})
            self.assertEqual(response.status_code, 429)

    # Test case to verify the unauthorized error status code for random data without token
    def test_random_data_without_token(self):
        response = self.app.get('/api/random')
        self.assertEqual(response.status_code, 401)

    # Test case to verify the unauthorized error status code for random data with expired token
    def test_random_data_with_expired_token(self):
        with create_app().app_context():
            expired_token = generate_expired_token('user1')
            headers = {"Authorization": f"Bearer {expired_token}"}
            response = self.app.get('/api/random', headers=headers)
            self.assertEqual(response.status_code, 401)

    # Test case to verify the unproc­essable entity error status code for random data with invalid token
    def test_random_data_with_invalid_token(self):
        response = self.app.get(
            '/api/random', headers={"Authorization": "Bearer invalid_token"})
        self.assertEqual(response.status_code, 422)

    # Test case to verify the rate limit exceeded error status code for random data with invalid length
    def test_random_data_with_invalid_len(self):
        with create_app().app_context():
            # Generate an access token for a user
            user_access_token = create_access_token(identity='user1')
            headers = {
                "Authorization": f"Bearer {user_access_token}"
            }

            response = self.app.get(
                '/api/random?len=100000000', headers=headers)
            self.assertEqual(response.status_code, 429)

    # Test case to verify the rate limit exceeded error status code for random data with invalid length
    def test_random_data_with_excessive_len(self):
        with create_app().app_context():
            user_access_token = create_access_token(identity='user1')
            headers = {
                "Authorization": f"Bearer {user_access_token}"
            }

            response = self.app.get('/api/random?len=5000', headers=headers)
            self.assertEqual(response.status_code, 429)

    # Test case to verify the success status code for admin reset rate limit
    def test_admin_reset_rate_limit(self):
        with create_app().app_context():
            access_token = create_access_token(identity='admin')
            headers = {"Authorization": f"Bearer {access_token}",
                       "Content-Type": "application/json"}
            payload = {"client_username": "user1", "reset": True}
            response = self.app.post(
                '/api/admin/rate-limit', headers=headers, data=json.dumps(payload))
            self.assertEqual(response.status_code, 200)

    # Test case to verify the success status code for admin set new rate limit
    def test_admin_set_new_rate_limit(self):
        with create_app().app_context():
            access_token = create_access_token(identity='admin')
            headers = {"Authorization": f"Bearer {access_token}",
                       "Content-Type": "application/json"}
            payload = {"client_username": "user1", "new_limit": 2048}
            response = self.app.post(
                '/api/admin/rate-limit', headers=headers, data=json.dumps(payload))
            self.assertEqual(response.status_code, 200)

    # Test case to verify the unauthorized error status code for admin reset rate limit without token
    def test_admin_reset_limit_without_token(self):
        response = self.app.post(
            '/api/admin/rate-limit', json={'client_username': 'user1', 'reset': True})
        self.assertEqual(response.status_code, 401)

    # Test case to verify the unauthorized error status code for admin set new rate limit without token
    def test_admin_set_limit_without_token(self):
        response = self.app.post(
            '/api/admin/rate-limit', json={'client_username': 'user1', 'new_limit': 512})
        self.assertEqual(response.status_code, 401)

    # Test case to verify the successful generation of valid access token
    def get_access_token(self, username, password):
        response = self.app.post(
            '/api/login', json={'username': username, 'password': password}
        )
        response_data = json.loads(response.data)
        return response_data.get('access_token', '')

    # Test case to verify the unauthorized error status code for accessing random data with expired token
    def test_access_with_expired_token(self):
        with create_app().app_context():
            expired_token = generate_expired_token('user1')
            headers = {"Authorization": f"Bearer {expired_token}"}
            response = self.app.get('/api/random', headers=headers)
            self.assertEqual(response.status_code, 401)

    # Test case to verify the forbidden error status code for accessing admin reset rate limit with invalid token
    def test_invalid_admin_reset_rate_limit(self):
        with create_app().app_context():
            # Generate an access token for a regular user (non-admin)
            user_access_token = create_access_token(identity='user1')
            headers = {
                "Authorization": f"Bearer {user_access_token}"
            }

            response = self.app.post(
                '/api/admin/rate-limit', json={"client_username": "user1", "reset": True}, headers=headers)
            self.assertEqual(response.status_code, 403)

    # Test case to verify the forbidden error status code for accessing admin set new rate limit with invalid token
    def test_invalid_admin_set_new_rate_limit(self):
        with create_app().app_context():
            # Generate an access token for a regular user (non-admin)
            user_access_token = create_access_token(identity='user1')
            headers = {
                "Authorization": f"Bearer {user_access_token}"
            }

            response = self.app.post(
                '/api/admin/rate-limit', json={"client_username": "user1", "new_limit": 2048}, headers=headers)
            self.assertEqual(response.status_code, 403)

    # Test case to verify the rate limit exceeded error status code for exceeding rate limit
    def test_exceed_rate_limit(self):
        with create_app().app_context():
            access_token = create_access_token(identity='user1')
            headers = {"Authorization": f"Bearer {access_token}"}

            # Perform requests that exceed the rate limit
            response1 = self.app.get('/api/random?len=512', headers=headers)
            response2 = self.app.get('/api/random?len=512', headers=headers)
            response3 = self.app.get('/api/random?len=512', headers=headers)
            self.assertEqual(response3.status_code, 429)

    # Test case to verify the bad request error status code for invalid JSON payload
    def test_invalid_json_payload_admin_reset_limit(self):
        with create_app().app_context():
            admin_access_token = create_access_token(identity='admin')
            headers = {
                "Authorization": f"Bearer {admin_access_token}",
                "Content-Type": "application/json"
            }

            # Perform a request to reset the rate limit with an invalid JSON payload
            response = self.app.post(
                '/api/admin/rate-limit', data="invalid json", headers=headers)
            self.assertEqual(response.status_code, 400)

    # Test case to verify the bad request error status code for invalid content type
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
            self.assertEqual(response.status_code, 400)


if __name__ == '__main__':
    unittest.main()
