FROM python:3.11-slim
WORKDIR /app

# Install Python dependencies
COPY build/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY build/ ./
ENV FLASK_APP=app.py

# Expose application port
EXPOSE 3206

# Start the Flask application
ENV PORT=3206
# No healthcheck to keep image minimal
CMD ["python", "app.py"]