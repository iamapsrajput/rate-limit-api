from werkzeug.security import generate_password_hash

# Dictionary of usernames and passwords
passwords = {
    "user1": "password1",
    "user2": "password2"
}

# Generate and print password hashes for each user
for user, password in passwords.items():
    hash = generate_password_hash(password)
    print(f'"{user}": "{hash}",')
