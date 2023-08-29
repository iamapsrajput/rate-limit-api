from werkzeug.security import generate_password_hash

"""
This dictionary contains sample usernames and passwords.
"""
passwords = {
    "user1": "password1",
    "user2": "password2"
}

"""
The passwords are hashed using the `generate_password_hash()` function for each user.
"""
for user, password in passwords.items():
    hash = generate_password_hash(password)
    print(f'"{user}": "{hash}",')
