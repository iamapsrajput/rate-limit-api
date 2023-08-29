from app import create_app

"""
This file creates a Flask app using the create_app function and
runs it in debug mode, accessible externally on all interfaces, and on port 4000.
"""
# Create the Flask app using the create_app function
app = create_app()

"""
Check if the script is being run directly. If so, run the app in debug mode,
accessible externally on all interfaces, and on port 4000.
"""
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=4000)
