# Use the official Python image as the base image
FROM python:3.11

# Set the working directory
WORKDIR /app

# Install ImageMagick
RUN apt-get update && apt-get install -y imagemagick

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code
COPY . .

# Command to run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000"]
