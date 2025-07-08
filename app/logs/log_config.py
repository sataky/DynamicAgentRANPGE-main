from datetime import datetime
import logging
import sys
import os

"""
Configures logging for the FastAPI application.

This setup defines how logging messages are handled within the application. It specifies the logging level, the format of log messages, and the output destinations for these messages.

- The logging level is set based on the LOG_LEVEL environment variable, defaulting to INFO if not set.
- The log message format includes:
  - Timestamp of when the log entry was created
  - Name of the logger
  - Level of the log entry (e.g., INFO, ERROR)
  - The actual log message
- Log messages are directed to stdout, which is captured by Azure's logging system.

This logging configuration is essential for tracking the application's behavior and diagnosing issues effectively in Azure deployments.
"""

# Get log level from environment variable, default to INFO
log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()

logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# Log the start of the application
logger.info(f"Application starting with log level: {log_level}")