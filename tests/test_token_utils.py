import unittest
from jwt.exceptions import ExpiredSignatureError
from app.utils.token_utils import generate_valid_token, generate_expired_token
from flask_jwt_extended import decode_token
from app import create_app

class TokenUtilsTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app().test_client()
        self.app.testing = True  # Enable testing mode

    # Test case to generate a valid JWT token and verify its content
    def test_generate_valid_token(self):
        with create_app().app_context():
            # Generate a valid token for user 'user1'
            token = generate_valid_token('user1')
            self.assertTrue(isinstance(token, str) and len(token) > 0)

            # Verify the token's validity by decoding it
            decoded_token = decode_token(token)
            self.assertEqual(decoded_token['sub'], 'user1')  # Check the 'sub' claim

    # Test case to generate an expired JWT token and verify the exception
    def test_generate_expired_token(self):
        with create_app().app_context():
            # Generate an expired token for user 'user1'
            token = generate_expired_token('user1')
            self.assertTrue(isinstance(token, str) and len(token) > 0)

            # Verify that an ExpiredSignatureError is raised when decoding the token
            try:
                decoded_token = decode_token(token)
                self.fail("Expected ExpiredSignatureError but got no exception.")
            except ExpiredSignatureError:
                pass  # This is expected

if __name__ == '__main__':
    unittest.main()
