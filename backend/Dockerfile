# Use a Python base image
FROM python:3.11-slim

# Install ImageMagick
RUN apt-get update && apt-get install -y imagemagick

# Set the working directory
WORKDIR /app

# Copy requirements and install them
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Command to run your application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]
