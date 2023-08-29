Till now we implemented this structure with your help

/rate_limiting_api
    /app
        __init__.py
        /api
            __init__.py
            routes.py
            /services
                __init__.py
                random_data_service.py
        /common
            __init__.py
            config.py
        /utils
            rate_limiter.py
            token_utils.py
    /tests
        __init__.py
        test_routes.py
        test_token_utils.py
    run.py
    Dockerfile
    requirements.txt
    README.md
    generate_password_hashes.py

Test modules also need to implemented, we just have sample case in that as of now. we will write when the api building is done.
generate_password_hashes.py is used to generate password hashes for the users.
Dockerfile is used to build docker image for the application. But we need to finish that file also.
requirements.txt contains all the dependencies required for the application
README.md contains the instructions to run the application

Code Written on those files are as follows
/app/__init__.py
import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from flask_jwt_extended import JWTManager

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.common.config')
    jwt = JWTManager(app)

    # Register blueprints or any extensions here
    from app.api.routes import bp as api_bp  # Assuming the routes are directly inside the app folder
    app.register_blueprint(api_bp, url_prefix='/api')

    if not app.debug:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/randomapi.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('RandomAPI startup')

    return app

/app/api/__init__.py
from .routes import bp

/app/api/routes.py
import base64
from flask import Blueprint, jsonify, request, current_app as app  # added current_app for logging
from werkzeug.security import check_password_hash
from app.common.config import USERS_DB
from app.api.services.random_data_service import get_random_data
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity

bp = Blueprint('api', __name__)

@bp.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400

    user = USERS_DB.get(username, None)
    if user and check_password_hash(user, password):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200

    app.logger.warning(f'Failed login attempt for user {username}.')
    return jsonify({"msg": "Bad username or password"}), 401

@bp.route('/random', methods=['GET'])
@jwt_required()
def random_data():
    byte_size = request.args.get('len', default=32, type=int)
    current_user = get_jwt_identity()
    app.logger.info(f'User {current_user} requested random data of size {byte_size}.')
    return get_random_data(current_user, byte_size)

@bp.route('/admin/rate-limit', methods=['POST'])
@jwt_required()
def manage_rate_limit():
    # Ensure only admin can access this route
    current_user = get_jwt_identity()
    if current_user != "admin":  # Assuming 'admin' is the username for the admin
        app.logger.warning(f'Unauthorized admin access attempt by {current_user}.')
        return jsonify({"msg": "Admin access only!"}), 403

    client_username = request.json.get('client_username', None)
    new_limit = request.json.get('new_limit', None)
    reset_limit = request.json.get('reset', False)  # Boolean: True if resetting, False otherwise

    if not client_username:
        return jsonify({"msg": "Specify the client's username!"}), 400

    if reset_limit:
        app.logger.info(f'Admin {current_user} reset rate limit for client {client_username}.')
        # Call the function to reset the rate limit for client_username
        # Note: reset_rate_limit_for_client() is not yet implemented.
        reset_rate_limit_for_client(client_username)
        return jsonify({"msg": f"Rate limit for {client_username} has been reset."}), 200

    if new_limit:
        app.logger.info(f'Admin {current_user} set a new rate limit of {new_limit} bytes/10 seconds for client {client_username}.')
        # Call the function to set a new rate limit for client_username
        # Note: set_rate_limit_for_client() is not yet implemented.
        set_rate_limit_for_client(client_username, new_limit)
        return jsonify({"msg": f"Rate limit for {client_username} has been set to {new_limit} bytes per 10 seconds."}), 200

    return jsonify({"msg": "Specify either a new limit or request a reset!"}), 400

# Health check endpoint
@bp.route('/health', methods=['GET'])
def health_check():
    return jsonify(status="Healthy"), 200

# Handle 404 - Not Found errors
@bp.app_errorhandler(404)
def not_found_error(error):
    app.logger.warning('404 error encountered.')
    return jsonify(error="Not Found"), 404

# Handle 500 - Internal Server Error
@bp.app_errorhandler(500)
def internal_error(error):
    app.logger.error('500 error encountered.')
    return jsonify(error="Internal Server Error"), 500

/app/api/services/__init__.py
Empty file

/app/api/services/random_data_service.py
from app.utils.rate_limiter import is_within_rate_limit, reset_rate_limit_for_client, set_new_limit_for_client

def get_random_data(username, byte_size=32):
    # Check if user's request is within rate limit
    within_limit, remaining_quota = is_within_rate_limit(username, byte_size)

    if not within_limit:
        return {
            "error": "Rate limit exceeded.",
            "remaining_quota": remaining_quota
        }, 429, {'X-Rate-Limit': remaining_quota}

    # If within limit, generate random data
    random_data = generate_random_data(byte_size)

    return {
        "random": random_data
    }, 200, {'X-Rate-Limit': remaining_quota}

def generate_random_data(byte_size):
    import os
    import base64
    return base64.b64encode(os.urandom(byte_size)).decode('utf-8')

/app/common/__init__.py
Empty file

/app/common/config.py
# Rate limiting configurations
RATE_LIMIT = 1024  # bytes per 10 seconds
RATE_LIMIT_TIME_SPAN = 10  # seconds

# This is a simplistic representation of a user database with plaintext passwords.
# IMPORTANT: Never use plaintext passwords in a real-world scenario.
USERS_DB = {
    "user1": "pbkdf2:sha256:600000$pfNkDROVjt6c1mjp$dc7ba8112b36d8263347e2ab31079aa369fc927421831f469cc20377e29c65a6",
    "user2": "pbkdf2:sha256:600000$G2KbXdwh3VPJOyIW$1d856448fc843493f39b1d04b5d58f2d3c3e189a4f022142d3f176cf9ba9b68d",
}

SECRET_KEY = 'your_secret_key'  # Ideally, generate a random secret key
JWT_SECRET_KEY = 'jwt_secret_key'  # This should be kept secret and random

/app/models/__init__.py
Empty file

/app/utils/rate_limiter.py
import time
from app.common.config import RATE_LIMIT, RATE_LIMIT_TIME_SPAN

# This rate limiter is a simple in-memory solution which won't scale horizontally
# across multiple server instances. In production, consider using a distributed rate
# limiter like Redis.


# In-memory dictionary to track rate limit data for each user
_rate_limit_store = {}

def reset_rate_limit_for_client(username):
    if username in _rate_limit_store:
        _rate_limit_store[username]["bytes_consumed"] = 0
        _rate_limit_store[username]["last_request_time"] = time.time()

def set_rate_limit_for_client(username, new_limit):
    _rate_limit_store[username] = {
        "last_request_time": time.time(),
        "bytes_consumed": 0,
        "rate_limit": new_limit
    }

def is_within_rate_limit(username, requested_bytes):
    """
    Check if the user is within their rate limit.

    Args:
    - username (str): The username of the authenticated user.
    - requested_bytes (int): The number of bytes the user is requesting.

    Returns:
    - bool: True if within rate limit, False otherwise.
    - int: Remaining bytes user can request in the current window.
    """
    current_time = time.time()

    # Get the user's rate limit data
    user_data = _rate_limit_store.get(username, {
        "last_request_time": current_time,
        "bytes_consumed": 0
    })

    # Check if we're in a new rate limit window
    if current_time - user_data["last_request_time"] > RATE_LIMIT_TIME_SPAN:
        user_data = {
            "last_request_time": current_time,
            "bytes_consumed": 0
        }

    remaining_bytes = RATE_LIMIT - user_data["bytes_consumed"]

    # Check if user can make the requested amount of randomness
    if requested_bytes <= remaining_bytes:
        user_data["bytes_consumed"] += requested_bytes
        user_data["last_request_time"] = current_time
        _rate_limit_store[username] = user_data
        return True, remaining_bytes - requested_bytes
    else:
        return False, remaining_bytes

/tests/__init__.py
Empty file

/tests/test_routes.py
import unittest
from app import app


class RoutesTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()

    def test_random_route(self):
        response = self.app.get(
            '/random', headers={"Authorization": "Basic " + base64.b64encode(b"user:pass").decode("utf-8")})
        self.assertEqual(response.status_code, 200)

/run.py
from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=4000)

/Dockerfile
# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set an environment variable with the directory where we'll be running the app
WORKDIR /usr/src/app

# Copy the current directory contents into the container at /usr/src/app
COPY . /usr/src/app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Define environment variable
ENV NAME World

# Run the app when the container launches
CMD ["python", "run.py"]

/requirements.txt
Flask==2.0.1
Flask-HTTPAuth==4.2.0
Flask-JWT-Extended

/README.md
Need to be written

/generate_password_hashes.py
from werkzeug.security import generate_password_hash

passwords = {
    "user1": "password1",
    "user2": "password2"
}

for user, password in passwords.items():
    print(f'"{user}": "{generate_password_hash(password)}",')
