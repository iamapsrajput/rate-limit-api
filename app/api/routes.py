import base64
# added current_app for logging
from flask import Blueprint, jsonify, request, current_app as app
from werkzeug.security import check_password_hash
from app.common.config import USERS_DB
from app.api.services.random_data_service import get_random_data
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from app.utils.rate_limiter import set_rate_limit_for_client, reset_rate_limit_for_client

bp = Blueprint('api', __name__)

# Define the Blueprint for API routes.
# This module includes all the API endpoints' routes and their logic.
# It can be registered with the Flask app to make the API endpoints accessible.


@bp.route('/login', methods=['POST'])
def login():
    """
    Authenticate the user and provide an access token upon successful login.

    Returns:
    - tuple: A tuple containing a dictionary with an access token if authentication is successful,
             or an "error" message if authentication fails, the HTTP status code, and the response headers.
    """
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    stored_hash = USERS_DB.get(username, None)
    if stored_hash and check_password_hash(stored_hash, password):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200

    app.logger.warning(f'Failed login attempt for user {username}.')
    return jsonify({"error": "Bad username or password"}), 401


@bp.route('/random', methods=['GET'])
@jwt_required()
def random_data():
    """
    Provide random data to the authenticated user within rate limit.

    Returns:
    - tuple: A tuple containing a dictionary with "random" data if within rate limit,
             the HTTP status code, and the response headers.
    """
    try:
        byte_size = request.args.get('len', default=32, type=int)
    except ValueError:
        return jsonify({"error": "Invalid value for len parameter"}), 400

    current_user = get_jwt_identity()
    app.logger.info(
        f'User {current_user} requested random data of size {byte_size}.')
    return get_random_data(current_user, byte_size)


@bp.route('/admin/rate-limit', methods=['POST'])
@jwt_required()
def manage_rate_limit():
    """
    Manage rate limit settings for clients.

    Returns:
    - tuple: A tuple containing a dictionary with a response message,
             the HTTP status code, and the response headers.
    """
    current_user = get_jwt_identity()
    if current_user != "admin":
        app.logger.warning(f'Unauthorized admin access attempt by {current_user}.')
        return jsonify({"msg": "Admin access only!"}), 403

    try:
        request_data = request.get_json(force=True)
    except:
        return jsonify({"msg": "Invalid JSON data"}), 400

    client_username = request_data.get('client_username')
    new_limit = request_data.get('new_limit')
    reset_limit = request_data.get('reset', False)

    if not client_username:
        return jsonify({"msg": "Specify the client's username!"}), 400

    if reset_limit:
        app.logger.info(f'Admin {current_user} reset rate limit for client {client_username}.')
        reset_rate_limit_for_client(client_username)
        return jsonify({"msg": f"Rate limit for {client_username} has been reset."}), 200

    if new_limit is not None:
        if not isinstance(new_limit, int) or new_limit <= 0:
            return jsonify({"msg": "New limit must be a positive integer!"}), 400

        app.logger.info(f'Admin {current_user} set a new rate limit of {new_limit} bytes/10 seconds for client {client_username}.')
        set_rate_limit_for_client(client_username, new_limit)
        return jsonify({"msg": f"Rate limit for {client_username} has been set to {new_limit} bytes per 10 seconds."}), 200

    return jsonify({"msg": "Specify either a new limit or request a reset!"}), 400


# Health check endpoint

@bp.route('/health', methods=['GET'])
def health_check():
    """
    Perform a health check on the application.

    Returns:
    - tuple: A tuple containing a dictionary with a status message,
             the HTTP status code, and the response headers.
    """
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
