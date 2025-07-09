#!/usr/bin/env bash
# startup.sh — for production on Azure

# Get port from environment variable, fallback to 8000
PORT=${PORT:-8000}

# Launch Gunicorn + Uvicorn workers
gunicorn main:app \
  --chdir app \
  --bind 0.0.0.0:8080 \
  --workers 1 \
  --worker-class uvicorn.workers.UvicornWorker \
  --timeout 300
