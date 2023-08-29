from flask import Blueprint, jsonify, request, current_app as app # added current_app for logging
from werkzeug.security import check_password_hash
from app.common.config import USERS_DB
from app.api.services.random_data_service import get_random_data
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from app.utils.rate_limiter import set_rate_limit_for_client, reset_rate_limit_for_client

bp = Blueprint('api', __name__)

"""
Define the Blueprint for API routes.
This module includes all the API endpoints' routes and their logic.
It can be registered with the Flask app to make the API endpoints accessible.
"""

@bp.route('/login', methods=['POST'])
def login():
    """
    This function authenticates the user and returns an access token if the login is successful.

    Returns:
    - tuple: The function returns a tuple of three values:
           * The access token, if the login is successful.
           * An error message, if the login fails.
           * The HTTP status code.
           * The response headers.
    """
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400

    stored_hash = USERS_DB.get(username, None)
    if stored_hash and check_password_hash(stored_hash, password):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200

    app.logger.warning(f'Failed login attempt for user {username}.')
    return jsonify({"msg": "Bad username or password"}), 401


@bp.route('/random', methods=['GET'])
@jwt_required()
def random_data():
    """
    This function provides random data to the authenticated user within the rate limit.

    Returns:
    - tuple: The function returns a tuple of three values:
           * "random" data if within rate limit.
           * The HTTP status code.
           * The response headers.
    """
    try:
        byte_size = request.args.get('len', default=32, type=int)
    except ValueError:
        return jsonify({"msg": "Invalid value for len parameter"}), 400

    current_user = get_jwt_identity()
    app.logger.info(
        f'User {current_user} requested random data of size {byte_size}.')
    return get_random_data(current_user, byte_size)


@bp.route('/admin/rate-limit', methods=['POST'])
@jwt_required()
def manage_rate_limit():
    """
    This function manages rate limit settings for clients.

    Returns:
    - tuple: The function returns a tuple of three values:
           * A response message.
           * The HTTP status code.
           * The response headers.
    """
    current_user = get_jwt_identity()
    if current_user != "admin":
        app.logger.warning(
            f'Unauthorized admin access attempt by {current_user}.')
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
        app.logger.info(
            f'Admin {current_user} reset rate limit for client {client_username}.')
        reset_rate_limit_for_client(client_username)
        return jsonify({"msg": f"Rate limit for {client_username} has been reset."}), 200

    if new_limit is not None:
        if not isinstance(new_limit, int) or new_limit <= 0:
            return jsonify({"msg": "New limit must be a positive integer!"}), 400

        app.logger.info(
            f'Admin {current_user} set a new rate limit of {new_limit} bytes/10 seconds for client {client_username}.')
        set_rate_limit_for_client(client_username, new_limit)
        return jsonify({"msg": f"Rate limit for {client_username} has been set to {new_limit} bytes per 10 seconds."}), 200

    return jsonify({"msg": "Specify either a new limit or request a reset!"}), 400


# Health check endpoint

@bp.route('/health', methods=['GET'])
def health_check():
    """
    This function performs a health check on the application.

    Returns:
    - tuple: The function returns a tuple of three values:
           * A status message.
           * The HTTP status code.
           * The response headers.
    """
    return jsonify(status="Healthy"), 200


# Handle 400 - Bad Request errors

@bp.app_errorhandler(400)
def bad_request_error(error):
    app.logger.warning('400 error encountered. Bad request.')
    return jsonify(error="Bad Request"), 400


# Handle 401 - Unauthorized errors

@bp.app_errorhandler(401)
def unauthorized_access(error):
    app.logger.warning('401 Unauthorized access attempt.')
    return jsonify(msg="Unauthorized"), 401


# Handle 403 - Forbidden errors

@bp.app_errorhandler(403)
def forbidden_access(error):
    app.logger.warning('403 Forbidden access attempt.')
    return jsonify(msg="Forbidden"), 403


# Handle 404 - Not Found errors

@bp.app_errorhandler(404)
def not_found_error(error):
    app.logger.warning('404 error encountered.')
    return jsonify(msg="Not Found"), 404


# Handle 405 - Method Not Allowed errors

@bp.app_errorhandler(405)
def method_not_allowed_error(error):
    app.logger.warning('405 error encountered. Method not allowed.')
    return jsonify(error="Method Not Allowed"), 405


# Handle 500 - Internal Server Error

@bp.app_errorhandler(500)
def internal_error(error):
    app.logger.error('500 error encountered.')
    return jsonify(msg="Internal Server Error"), 500
