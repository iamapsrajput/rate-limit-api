import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from flask_jwt_extended import JWTManager

def create_app():
    """
    Create and configure the Flask application.

    Returns:
    - Flask: The configured Flask application.
    """
    app = Flask(__name__)
    app.config.from_object('app.common.config')
    jwt = JWTManager(app)

    # Register blueprints or any extensions here
    from app.api.routes import bp as api_bp  # Assuming the routes are directly inside the app folder
    app.register_blueprint(api_bp, url_prefix='/api')

    # Set up logging for the application
    if not app.debug:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/randomapi.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('RandomAPI startup')

    return app
