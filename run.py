from app import create_app

# Create the Flask app using the create_app function
app = create_app()

# Check if the script is being run directly
if __name__ == '__main__':
    # Run the app in debug mode, accessible externally on all interfaces, and on port 4000
    app.run(debug=True, host='0.0.0.0', port=4000)
