"""
This module initializes the logging configuration for the application.

It imports the logger instance from the log_config module to provide a centralized logging mechanism.

Attributes:
    logger (Logger): An instance of the logger used for logging application events and errors.
"""

from .log_config import logger

logger = logger