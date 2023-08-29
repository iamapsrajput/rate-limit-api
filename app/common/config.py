"""
This file contains the configuration settings for the Rate Limiting API.
"""

"""
The following settings define the rate limiting configurations:
"""
RATE_LIMIT = 1024  # Maximum bytes allowed per 10 seconds
RATE_LIMIT_TIME_SPAN = 10  # Time span for rate limiting window in seconds

"""
User database for authentication
IMPORTANT: In production, use a secure and scalable authentication solution.
"""
USERS_DB = {
    "user1": "pbkdf2:sha256:260000$bzBmJLAAmokMtf4T$a04b4453d0407c3640fccc7d2aeea8454f25b89bda8daa90e32c7c6ca6098ce6",
    "user2": "pbkdf2:sha256:260000$JdmGBApGxEAjL0ie$c975cd6d18bc5335a1e7e5e549b39a33f8d747766e620910e6d35793aa251bce",
}

"""
Secret keys for security
IMPORTANT: Protect these keys from unauthorized access and leakage.
Added for future upgrades.
"""
SECRET_KEY = 'your_secret_key'  # A secret key used to encrypt and decrypt data.
JWT_SECRET_KEY = 'jwt_secret_key' # A secret key used to create and verify JSON Web Tokens (JWTs).
