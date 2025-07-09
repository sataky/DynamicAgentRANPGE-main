import os
import json
import redis
from redis.backoff import ExponentialBackoff
from redis.retry import Retry
from redis.exceptions import (BusyLoadingError, RedisError, AuthenticationError)
import threading
import time
from typing import Optional, Any
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.core.exceptions import ClientAuthenticationError
from app.logs import logger
from dotenv import load_dotenv

load_dotenv()

class RedisService:
    """
    Redis service for Private Endpoint + Entra Authentication
    Uses System-Assigned Managed Identity from environment variables
    """
    
    _instance = None
    _client = None
    _lock = threading.Lock()
    _token_refresh_lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(RedisService, cls).__new__(cls)
                    cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize Redis connection with Private Endpoint + Entra Auth"""
        if self._client is not None:
            return
            
        # Configuration via variables d'environnement uniquement
        self.redis_host = os.getenv("REDIS_HOST")
        self.redis_port = int(os.getenv("REDIS_PORT", "6380"))
        self.redis_username = os.getenv("REDIS_USERNAME")
        
        if not all([self.redis_host, self.redis_username]):
            raise ValueError("REDIS_HOST and REDIS_USERNAME must be set in environment variables")
        
        logger.info(f"🔐 Using Entra Authentication for Redis")
        logger.info(f"🌐 Redis Host (Private): {self.redis_host}:{self.redis_port}")
        logger.info(f"👤 Redis Username: {self.redis_username}")
        
        # Azure credentials pour Entra Auth
        self.credential = self._get_azure_credential()
        self.token_expiry = 0
        self.current_token = None
        
        try:
            logger.info("🔗 Connecting to Redis via Private Endpoint...")
            self._connect_with_fresh_token()
            logger.info("✅ Redis Private Endpoint + Entra Auth connection successful")

        except Exception as e:
            logger.error(f"❌ Redis connection failed: {str(e)}")
            self._client = None
            raise Exception(f"Redis connection failed: {str(e)}")
    
    def _get_azure_credential(self):
        """Get Azure credential using System-Assigned Managed Identity"""
        logger.info("🔑 Using System-Assigned Managed Identity for Entra Auth")
        
        # DefaultAzureCredential détecte automatiquement l'identité managée
        return DefaultAzureCredential()
    
    def _get_fresh_token(self) -> str:
        """Get fresh Azure token for Redis Entra authentication"""
        try:
            logger.debug("🔄 Getting Redis Entra token...")
            
            # Scope pour Azure Redis avec Entra Auth
            token_response = self.credential.get_token("https://redis.azure.com/.default")
            self.current_token = token_response.token
            self.token_expiry = token_response.expires_on
            
            logger.debug("✅ Redis Entra token acquired")
            return self.current_token
            
        except ClientAuthenticationError as e:
            logger.error(f"❌ Entra authentication failed: {str(e)}")
            logger.error("💡 Verify Azure AD permissions for Redis")
            raise
        except Exception as e:
            logger.error(f"❌ Failed to get Entra token: {str(e)}")
            raise
    
    def _connect_with_fresh_token(self):
        """Connect to Redis via Private Endpoint with Entra token"""
        token = self._get_fresh_token()
        retry = Retry(ExponentialBackoff(), 3)
        
        self._client = redis.Redis(
            host=self.redis_host,
            port=self.redis_port,
            ssl=True,
            ssl_cert_reqs=None,
            decode_responses=True,
            username=self.redis_username,  # Object ID
            password=token,  # Entra token
            socket_keepalive=True,
            socket_keepalive_options={},
            retry_on_timeout=True,
            retry_on_error=[BusyLoadingError, RedisError],
            retry=retry,
            socket_timeout=10,
            socket_connect_timeout=10
        )
        
        # Test connection
        try:
            result = self._client.ping()
            logger.info(f"✅ Redis PING via Private Endpoint: {result}")
            
            # Test permissions
            test_key = f"test:private-endpoint:{int(time.time())}"
            self._client.set(test_key, "private_endpoint_test", ex=60)
            self._client.delete(test_key)
            logger.info("✅ Private Endpoint permissions verified")
            
        except AuthenticationError as e:
            logger.error(f"❌ Entra authentication failed: {str(e)}")
            logger.error(f"💡 Check Redis Data Owner permissions for: {self.redis_username}")
            raise
        except Exception as e:
            logger.error(f"❌ Private Endpoint connection failed: {str(e)}")
            logger.error("💡 Check VNet configuration and private endpoint")
            raise
    
    def _is_token_expired(self) -> bool:
        """Check if Entra token expires within 3 minutes"""
        if not self.token_expiry:
            return True
        return (self.token_expiry - time.time()) <= 180
    
    def _refresh_auth_if_needed(self):
        """Refresh Entra authentication if needed"""
        if self._is_token_expired():
            with self._token_refresh_lock:
                if self._is_token_expired():
                    try:
                        logger.info("🔄 Refreshing Entra authentication...")
                        fresh_token = self._get_fresh_token()
                        
                        import random
                        time.sleep(random.uniform(0.1, 0.5))
                        
                        self._client.execute_command("AUTH", self.redis_username, fresh_token)
                        logger.info("✅ Entra authentication refreshed")
                        
                    except Exception as e:
                        logger.error(f"❌ Failed to refresh Entra auth: {str(e)}")
                        try:
                            self._connect_with_fresh_token()
                        except Exception as reconnect_error:
                            logger.error(f"❌ Failed to reconnect: {str(reconnect_error)}")
                            raise
    
    @property
    def client(self) -> Optional[redis.Redis]:
        """Get Redis client with automatic Entra token refresh"""
        try:
            self._refresh_auth_if_needed()
            return self._client
        except Exception as e:
            logger.error(f"❌ Error getting Redis client: {str(e)}")
            return None
    
    def is_connected(self) -> bool:
        """Check if Redis Private Endpoint connection is active"""
        try:
            if self._client:
                self._refresh_auth_if_needed()
                self._client.ping()
                return True
        except Exception as e:
            logger.warning(f"Redis Private Endpoint connection check failed: {str(e)}")
            return False
        return False
    
    def get_connection_info(self) -> dict:
        """Get connection information for debugging"""
        return {
            "auth_type": "Entra (Azure AD)",
            "endpoint_type": "Private Endpoint",
            "redis_host": self.redis_host,
            "redis_port": self.redis_port,
            "redis_username": self.redis_username,
            "has_token": self.current_token is not None,
            "token_expires": time.ctime(self.token_expiry) if self.token_expiry else "Unknown",
            "is_connected": self.is_connected()
        }
    
    # Toutes les autres méthodes restent identiques
    def set_with_ttl(self, key: str, value: Any, ttl_seconds: int) -> bool:
        try:
            client = self.client
            if not client:
                return False
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            return client.set(key, value, ex=ttl_seconds) is not False
        except Exception as e:
            logger.error(f"Error setting Redis key {key}: {str(e)}")
            return False
    
    def get(self, key: str, deserialize_json: bool = False) -> Optional[Any]:
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
        try:
            client = self.client
            if not client:
                return False
            return client.delete(key) > 0
        except Exception as e:
            logger.error(f"Error deleting Redis key {key}: {str(e)}")
            return False
    
    def exists(self, key: str) -> bool:
        try:
            client = self.client
            if not client:
                return False
            return client.exists(key) > 0
        except Exception as e:
            logger.error(f"Error checking Redis key existence {key}: {str(e)}")
            return False
    
    def sadd(self, key: str, *values) -> int:
        try:
            client = self.client
            if not client:
                return 0
            return client.sadd(key, *values)
        except Exception as e:
            logger.error(f"Error adding to Redis set {key}: {str(e)}")
            return 0
    
    def smembers(self, key: str) -> set:
        try:
            client = self.client
            if not client:
                return set()
            return client.smembers(key)
        except Exception as e:
            logger.error(f"Error getting Redis set members {key}: {str(e)}")
            return set()
    
    def expire(self, key: str, seconds: int) -> bool:
        try:
            client = self.client
            if not client:
                return False
            return client.expire(key, seconds)
        except Exception as e:
            logger.error(f"Error setting expiration for Redis key {key}: {str(e)}")
            return False
    
    def pipeline(self):
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
