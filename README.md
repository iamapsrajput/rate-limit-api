# Rate Limiting API

Rate Limiting API is a Flask-based RESTful API that provides endpoints to generate random data and manage rate limits for users.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Running the API](#running-the-api)
- [API Endpoints](#api-endpoints)
  - [Login](#login)
  - [Generate Random Data](#generate-random-data)
  - [Admin Rate Limit Management](#admin-rate-limit-management)
- [Testing](#testing)
- [Assumptions and Design Decisions](#assumptions-and-design-decisions)
- [How to Build, Run, and Test](#how-to-build-run-and-test)
- [Rate Reset and Parallel Requests](#rate-reset-and-parallel-requests)
- [State Management and Design Patterns](#state-management-and-design-patterns)
- [Docker Containerization](#docker-containerization)
- [Contributing](#contributing)
- [License](#license)

## Introduction

Rate Limiting API is designed to showcase the implementation of a Flask-based RESTful API. It allows users to generate random data of varying lengths and provides rate-limiting mechanisms to ensure fair usage. The API also includes authentication using JWT tokens for secure access.

## Features

- User authentication and JWT-based Authorization for secure API access.
- Generate random data of custom lengths for various use cases.
- Rate limiting to prevent abuse and ensure fair usage of the API.
- Admin functionality to manage rate limits for users, maintaining control.
- Dockerized application for easy deployment and consistent environment setup.

## Getting Started

### Prerequisites

- Python 3.9
- Docker (optional)

### Dependencies

- Flask==2.0.1
- Flask-HTTPAuth==4.2.0
- Flask-JWT-Extended
- Werkzeug==2.0.1
- certifi

### Installation

1. Clone this repository to your local machine.
2. Navigate to the project directory:
   ```bash
   cd RateLimitingAPI
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the API

To run the API locally, follow these steps:

1. Make sure you're in the project directory.
2. Start the API server using the following command:
   ```bash
   python run.py
   ```
   The API will be accessible at `http://localhost:4000`.

### API Endpoints

#### Login

Endpoint: `POST /api/login`

This endpoint allows users to authenticate and obtain an access token for API access.

Request:
```json
{
  "username": "user1",
  "password": "password1"
}
```

Response:
```json
{
  "access_token": "your_access_token"
}
```

#### Generate Random Data

Endpoint: `GET /api/random`

This endpoint generates random data of the specified length.

Query Parameter:
- `len` (optional): Length of random data (default is 32)

Response:
```json
{
  "random": "generated_random_data"
}
```

#### Admin Rate Limit Management

Endpoint: `POST /api/admin/rate-limit`

This endpoint allows administrators to manage rate limits for users.

Request (Reset Rate Limit):
```json
{
  "client_username": "user1",
  "reset": true
}
```

Request (Set New Rate Limit):
```json
{
  "client_username": "user1",
  "new_limit": 2048
}
```

## Testing

To run the automated tests, execute the following command:

```bash
python3 -m unittest discover tests
```

## Assumptions and Design Decisions

- **JWT-Based Authorization:** I used JSON Web Tokens (JWT) for user authentication and Authorization due to their stateless nature and support for claims like user roles and permissions.

- **Rate Limiting Strategy:** To simplify the implementation, I used an in-memory dictionary for rate limiting. However, this solution won't scale horizontally across multiple instances and recommends a distributed solution like Redis in production.

- **Logging and Error Handling:** I implemented logging to record important events such as login attempts and access to restricted routes. Error handling is comprehensive to provide users with meaningful error messages.

- The passwords in the `USERS_DB` are hashed using PBKDF2 for security.
- In-memory rate limiting is implemented for simplicity, but a distributed solution like Redis would be better for scalability.
- Users authenticate via the login endpoint to obtain a JWT token.
- Admin access is restricted using a predefined username (admin) in the JWT token.
- Rate limit management endpoints (/api/admin/rate-limit) are only accessible to the admin user.

## How to Build, Run, and Test

1. Clone the repository.
2. Install required dependencies (`pip3 install -r requirements.txt`).
3. Run the API using `python3 run.py`.
4. Test endpoints using tools like `curl` or the `requests` library.

## Rate Reset and Parallel Requests

- The rate limit resets every 10 seconds.
- Parallel requests from the same user share the rate limit window.
- Rate limits are enforced per user.

## State Management and Design Patterns

- In-memory `_rate_limit_store` is used to manage rate limit data.
- Singleton pattern is followed for the Flask app instance.
- JWT tokens are used to manage user sessions securely.

## Docker Containerization

The application can also be run within a Docker container. To build and run the container, follow these steps:

1. Make sure Docker is installed on your system.
2. Navigate to the project directory:
   ```bash
   cd RateLimitingAPI
   ```
3. Build the Docker image:
   ```bash
   docker build -t ratelimitingapi:latest .
   ```
4. Run the Docker container:
   ```bash
   docker run -p 4000:4000 ratelimitingapi:latest
   ```
   The API will be accessible at `http://localhost:4000`.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
