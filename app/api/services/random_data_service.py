from app.utils.rate_limiter import is_within_rate_limit

def get_random_data(username, byte_size=32):
    """
    Get random data for the given user if within rate limit.

    Args:
    - username (str): The username of the authenticated user.
    - byte_size (int): The size of random data to generate (default: 32 bytes).

    Returns:
    - tuple: A tuple containing a dictionary with "random" data if within limit, or "error" data if rate limit exceeded,
             the HTTP status code, and the response headers.
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
    Generate random data of the specified byte size.

    Args:
    - byte_size (int): The size of random data to generate.

    Returns:
    - str: Base64 encoded random data.
    """
    import os
    import base64
    return base64.b64encode(os.urandom(byte_size)).decode('utf-8')
