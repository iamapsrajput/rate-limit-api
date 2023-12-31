from datetime import timedelta
from flask_jwt_extended import create_access_token

"""
This token utility module provides functions to generate valid and expired JWT tokens for testing purposes.
"""

def generate_valid_token(username):
    """
    This function generates a valid JWT token for the given username.

    Args:
    - username (str): The username for which the token is generated.

    Returns:
    - str: The valid JWT token.
    """

    token = create_access_token(identity=username)

    return token


def generate_expired_token(username):
    """
    This function generates an expired JWT token for the given username.

    Args:
    - username (str): The username for which the token is generated.

    Returns:
    - str: The expired JWT token.
    """

    # Calculate the expiration time (set expiration time to be in the past)
    expiration = timedelta(seconds=-1)

    # Generate an expired JWT token
    token = create_access_token(identity=username, expires_delta=expiration)

    return token
