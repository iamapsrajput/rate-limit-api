import os
import base64
from app.utils.rate_limiter import is_within_rate_limit


def get_random_data(username, byte_size=32):
    """
    This function gets random data for the given user if within the rate limit.

    Args:
    - username (str): The username of the authenticated user.
    - byte_size (int): The size of random data to generate (default: 32 bytes).

    Returns:
    - tuple: The function returns a tuple of three values:
           * "random" data if within limit.
           * "error" data if rate limit exceeded.
           * The HTTP status code.
           * The response headers.
    """
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
    """
    This function generate random data of the specified byte size.

    Args:
    - byte_size (int): The size of random data to generate.

    Returns:
    - str: Base64 encoded random data.
    """

    return base64.b64encode(os.urandom(byte_size)).decode('utf-8')
