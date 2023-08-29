import time
from app.common.config import RATE_LIMIT, RATE_LIMIT_TIME_SPAN

"""
This module provides basic rate limiting functionality using an in-memory dictionary.
"""

"""
In-memory dictionary to track rate limit data for each user
"""
_rate_limit_store = {}


def reset_rate_limit_for_client(username):
    """
    This function resets the rate limit counters for a specific user.

    Args:
    - username (str): The username of the client whose rate limit needs to be reset.

    Returns:
    - None
    """

    if username in _rate_limit_store:
        _rate_limit_store[username]["bytes_consumed"] = 0
        _rate_limit_store[username]["last_request_time"] = time.time()


def set_rate_limit_for_client(username, new_limit):
    """
    This function sets a new rate limit for a specific user.

    Args:
    - username (str): The username of the client for whom the rate limit is being set.
    - new_limit (int): The new rate limit in bytes per 10 seconds.

    Returns:
    - None
    """

    _rate_limit_store[username] = {
        "last_request_time": time.time(),
        "bytes_consumed": 0,
        "rate_limit": new_limit
    }


def is_within_rate_limit(username, requested_bytes):
    """
    This function checks if the user is within their rate limit for the requested bytes.

    Args:
    - username (str): The username of the authenticated user.
    - requested_bytes (int): The number of bytes the user is requesting.

    Returns:
    - bool: True if within rate limit, False otherwise.
    - int: Remaining bytes user can request in the current rate limit window.
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
