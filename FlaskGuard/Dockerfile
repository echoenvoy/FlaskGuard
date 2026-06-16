FROM python:3.11-slim

WORKDIR /app

# LightGBM needs the OpenMP runtime provided by libgomp.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Install package dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --retries 5 --timeout 120 -r requirements.txt

# Copy FlaskGuard application package and config file
COPY flaskguard/ ./flaskguard/
COPY config.yml .

# Pre-train the ML model during build so it starts immediately
RUN python -c "from flaskguard.ml_classifier import train_model; train_model()"

# Expose proxy port
EXPOSE 80

ENV FLASK_APP=flaskguard.app:app
ENV PYTHONUNBUFFERED=1

# Start the reverse proxy using gunicorn.
# Threads handle browser parallel/idle connections better than a single sync worker.
CMD ["gunicorn", "--bind", "0.0.0.0:80", "--workers", "1", "--threads", "8", "--timeout", "120", "--graceful-timeout", "30", "--access-logfile", "-", "--error-logfile", "-", "flaskguard.app:app"]
