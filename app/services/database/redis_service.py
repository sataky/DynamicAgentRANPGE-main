import os
import json
import redis
from redis.backoff import ExponentialBackoff
from redis.retry import Retry
from redis.exceptions import (BusyLoadingError,RedisError,)
import threading
import time
from typing import Optional, Any
from azure.identity import DefaultAzureCredential
from app.logs import logger
from dotenv import load_dotenv

load_dotenv()

class RedisService:
    """
    Centralized Redis service for handling all Redis operations across the application.
    Provides a singleton instance with Azure authentication and automatic token refresh.
    Thread-safe for multiworker environments.
    """
    
    _instance = None
    _client = None
    _lock = threading.Lock()
    _token_refresh_lock = threading.Lock()
    
    def __new__(cls):
        """Thread-safe singleton pattern to ensure only one Redis connection."""
        if cls._instance is None:
            with cls._lock:
                # Double-check locking pattern
                if cls._instance is None:
                    cls._instance = super(RedisService, cls).__new__(cls)
                    cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize Redis connection with Azure authentication."""
        if self._client is not None:
            return
            
        # Redis configuration from environment
        self.redis_host = os.getenv("REDIS_HOST")
        self.redis_port = int(os.getenv("REDIS_PORT"))
        self.redis_username = os.getenv("REDIS_USERNAME")  
        
        if not self.redis_username:
            raise ValueError("REDIS_USERNAME (Object ID) must be set in environment variables")

        self.credential = DefaultAzureCredential()
        self.token_expiry = 0
        self.current_token = None
        
        try:
            logger.info(f"🌐 RedisService connecting to Azure Redis: {self.redis_host}:{self.redis_port}")
            self._connect_with_fresh_token()
            logger.info("✅ RedisService Azure Redis connection successful")

        except Exception as e:
            logger.error(f"❌ RedisService Azure Redis connection failed: {str(e)}")
            self._client = None
            raise Exception(f"Redis connection failed: {str(e)}")
    
    def _get_fresh_token(self) -> str:
        """Get a fresh Azure token for Redis authentication."""
        try:
            token_response = self.credential.get_token("https://redis.azure.com/.default")
            self.current_token = token_response.token
            self.token_expiry = token_response.expires_on
            logger.debug("🔄 Redis token refreshed successfully")
            return self.current_token
        except Exception as e:
            logger.error(f"❌ Failed to get Redis token: {str(e)}")
            raise
    
    def _connect_with_fresh_token(self):
        """Connect to Redis with a fresh token."""
        token = self._get_fresh_token()
        retry = Retry(ExponentialBackoff(), 3)
        self._client = redis.Redis(
            host=self.redis_host,
            port=self.redis_port,
            ssl=True,
            decode_responses=True,
            username=self.redis_username,
            password=token,
            socket_keepalive=True,
            socket_keepalive_options={},
            retry_on_timeout=True,
            retry_on_error=[BusyLoadingError, RedisError],
            retry=retry
        )
        
        # Test connection
        self._client.ping()
    
    def _is_token_expired(self) -> bool:
        """Check if the current token will expire soon (within 3 minutes)."""
        if not self.token_expiry:
            return True
        
        current_time = time.time()
        # Check if token expires within 3 minutes (180 seconds)
        return (self.token_expiry - current_time) <= 180
    
    def _refresh_auth_if_needed(self):
        """Refresh authentication if token is about to expire."""
        if self._is_token_expired():
            with self._token_refresh_lock:
                # Double-check after acquiring lock
                if self._is_token_expired():
                    try:
                        logger.info("🔄 Refreshing Redis authentication...")
                        fresh_token = self._get_fresh_token()
                        
                        # Send AUTH command with fresh token
                        # Add small random delay to stagger AUTH commands
                        import random
                        time.sleep(random.uniform(0.1, 0.5))
                        
                        self._client.execute_command("AUTH", self.redis_username, fresh_token)
                        logger.info("✅ Redis authentication refreshed successfully")
                        
                    except Exception as e:
                        logger.error(f"❌ Failed to refresh Redis authentication: {str(e)}")
                        # Try to reconnect with fresh token
                        try:
                            self._connect_with_fresh_token()
                        except Exception as reconnect_error:
                            logger.error(f"❌ Failed to reconnect to Redis: {str(reconnect_error)}")
                            raise
    
    @property
    def client(self) -> Optional[redis.Redis]:
        """Get the Redis client instance with automatic token refresh."""
        self._refresh_auth_if_needed()
        return self._client
    
    def is_connected(self) -> bool:
        """Check if Redis connection is active."""
        try:
            if self._client:
                self._refresh_auth_if_needed()
                self._client.ping()
                return True
        except Exception as e:
            logger.warning(f"Redis connection check failed: {str(e)}")
            return False
        return False
    
    def set_with_ttl(self, key: str, value: Any, ttl_seconds: int) -> bool:
        """
        Store a value in Redis with TTL.
        
        Args:
            key: Redis key
            value: Value to store (will be JSON serialized if it's a dict)
            ttl_seconds: Time to live in seconds
            
        Returns:
            True if successful, False otherwise
        """
        try:
            client = self.client
            if not client:
                return False
                
            # Serialize value if it's a dict/object
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            
            return client.set(key, value, ex=ttl_seconds) is not False
            
        except Exception as e:
            logger.error(f"Error setting Redis key {key}: {str(e)}")
            return False
    
    def get(self, key: str, deserialize_json: bool = False) -> Optional[Any]:
        """
        Get a value from Redis.
        
        Args:
            key: Redis key
            deserialize_json: Whether to deserialize JSON strings
            
        Returns:
            The value or None if not found
        """
        try:
            client = self.client
            if not client:
                return None
                
            value = client.get(key)
            if value and deserialize_json:
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    return value
            return value
            
        except Exception as e:
            logger.error(f"Error getting Redis key {key}: {str(e)}")
            return None
    
    def delete(self, key: str) -> bool:
        """
        Delete a key from Redis.
        
        Args:
            key: Redis key to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            client = self.client
            if not client:
                return False
            return client.delete(key) > 0
        except Exception as e:
            logger.error(f"Error deleting Redis key {key}: {str(e)}")
            return False
    
    def exists(self, key: str) -> bool:
        """
        Check if a key exists in Redis.
        
        Args:
            key: Redis key
            
        Returns:
            True if key exists, False otherwise
        """
        try:
            client = self.client
            if not client:
                return False
            return client.exists(key) > 0
        except Exception as e:
            logger.error(f"Error checking Redis key existence {key}: {str(e)}")
            return False
    
    def sadd(self, key: str, *values) -> int:
        """
        Add values to a Redis set.
        
        Args:
            key: Redis set key
            values: Values to add to the set
            
        Returns:
            Number of values added
        """
        try:
            client = self.client
            if not client:
                return 0
            return client.sadd(key, *values)
        except Exception as e:
            logger.error(f"Error adding to Redis set {key}: {str(e)}")
            return 0
    
    def smembers(self, key: str) -> set:
        """
        Get all members of a Redis set.
        
        Args:
            key: Redis set key
            
        Returns:
            Set of members
        """
        try:
            client = self.client
            if not client:
                return set()
            return client.smembers(key)
        except Exception as e:
            logger.error(f"Error getting Redis set members {key}: {str(e)}")
            return set()
    
    def expire(self, key: str, seconds: int) -> bool:
        """
        Set expiration for a key.
        
        Args:
            key: Redis key
            seconds: Expiration time in seconds
            
        Returns:
            True if successful, False otherwise
        """
        try:
            client = self.client
            if not client:
                return False
            return client.expire(key, seconds)
        except Exception as e:
            logger.error(f"Error setting expiration for Redis key {key}: {str(e)}")
            return False
    
    def pipeline(self):
        """
        Get a Redis pipeline for batch operations.
        
        Returns:
            Redis pipeline object or None if not connected
        """
        try:
            client = self.client
            if not client:
                return None
            return client.pipeline()
        except Exception as e:
            logger.error(f"Error creating Redis pipeline: {str(e)}")
            return None

# Global singleton instance
redis_service = RedisService()
