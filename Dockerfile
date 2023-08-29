# This Dockerfile uses the official Python image as the base image.
# The Python image is a lightweight image that contains the Python programming language and its dependencies.

# Use the official Python lightweight image as the base image
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the application code and other necessary files to the container
COPY . /app

# Install the required dependencies from the requirements.txt file
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port on which the application will run
EXPOSE 4000

# Command to run the application
CMD ["python", "run.py"]
