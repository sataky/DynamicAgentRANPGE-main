from datetime import datetime, timedelta, timezone
import json
from typing import Optional, Dict
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.logs import logger
from app.services.database.redis_service import redis_service
from app.services.external.progression_service import ProgressionService
from app.config import (
    JWT_SECRET_KEY,
    JWT_REFRESH_SECRET_KEY
)

security = HTTPBearer()

class AuthService:
    """
    A service class for handling JWT token operations including creation, verification, 
    refresh, and revocation using Redis as storage backend.
    """
    
    def __init__(self):
        """Initialize the AuthService with Redis and JWT configuration."""
        # JWT configuration
        self.SECRET_KEY = JWT_SECRET_KEY
        self.REFRESH_SECRET_KEY = JWT_REFRESH_SECRET_KEY
        self.ALGORITHM = "HS256"
        self.ACCESS_TOKEN_EXPIRE_MINUTES = 2 * 60
        self.REFRESH_TOKEN_EXPIRE_DAYS = 7
        
        # Use the centralized Redis service
        self.redis_service = redis_service
        
        # Initialize progression service
        self.progression_service = ProgressionService()
        
        if not self.redis_service.is_connected():
            logger.error("❌ AuthService: Redis connection not available")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Database connection failed"
            )

    def create_tokens(self, user_id: str) -> Dict[str, str]:
        """
        Create a new pair of access and refresh tokens for a given user.
        
        Args:
            user_id (str): The unique identifier of the user
            
        Returns:
            Dict[str, str]: A dictionary containing access token, refresh token, 
                           token type, and expiration timestamps, or None if creation fails
        """
        try:
            access_token_expires = datetime.now(timezone.utc) + timedelta(minutes=self.ACCESS_TOKEN_EXPIRE_MINUTES)
            refresh_token_expires = datetime.now(timezone.utc) + timedelta(days=self.REFRESH_TOKEN_EXPIRE_DAYS)

            access_token = jwt.encode(
                {"sub": str(user_id), "exp": access_token_expires},
                self.SECRET_KEY,
                algorithm=self.ALGORITHM
            )

            refresh_token = jwt.encode(
                {"sub": str(user_id), "exp": refresh_token_expires},
                self.REFRESH_SECRET_KEY,
                algorithm=self.ALGORITHM
            )
            
            token_data = {
                "user_id": str(user_id),
                "access_token": access_token,
                "refresh_token": refresh_token,
                "access_token_expires": access_token_expires.isoformat(),
                "refresh_token_expires": refresh_token_expires.isoformat(),
                "is_revoked": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Use Redis service for storage
            access_ttl = int(timedelta(minutes=self.ACCESS_TOKEN_EXPIRE_MINUTES).total_seconds())
            refresh_ttl = int(timedelta(days=self.REFRESH_TOKEN_EXPIRE_DAYS).total_seconds())
            
            # Store tokens using Redis service
            self.redis_service.set_with_ttl(f"token:{access_token}", token_data, access_ttl)
            self.redis_service.set_with_ttl(f"refresh:{refresh_token}", token_data, refresh_ttl)
            
            # Store user tokens set
            self.redis_service.sadd(f"user_tokens:{user_id}", access_token)
            self.redis_service.expire(f"user_tokens:{user_id}", refresh_ttl)
            
            logger.info(f"Tokens created successfully for user: {user_id}")
            
            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "access_token_expires": access_token_expires.timestamp(),
                "refresh_token_expires": refresh_token_expires.timestamp()
            }
        except Exception as e:
            logger.error(f"Error creating tokens: {str(e)}")
            return None

    def refresh_access_token(self, refresh_token: str) -> Optional[Dict[str, str]]:
        """Generate a new access token using a valid refresh token."""
        try:
            # Get token data from Redis
            token_data = self.redis_service.get(f"refresh:{refresh_token}", deserialize_json=True)
            if not token_data:
                logger.warning("No valid refresh token found in Redis")
                return None
                
            if token_data.get("is_revoked"):
                logger.warning("Refresh token has been revoked")
                return None

            refresh_expires = datetime.fromisoformat(token_data["refresh_token_expires"])
            if refresh_expires < datetime.now(timezone.utc):
                logger.warning("Refresh token has expired")
                return None

            try:
                payload = jwt.decode(refresh_token, self.REFRESH_SECRET_KEY, algorithms=[self.ALGORITHM])
            except jwt.InvalidTokenError:
                logger.warning("Invalid refresh token signature")
                return None

            user_id = payload.get("sub")
            if not user_id:
                logger.warning("No user ID found in refresh token")
                return None

            access_token_expires = datetime.now(timezone.utc) + timedelta(minutes=self.ACCESS_TOKEN_EXPIRE_MINUTES)
            new_access_token = jwt.encode(
                {"sub": user_id, "exp": access_token_expires},
                self.SECRET_KEY,
                algorithm=self.ALGORITHM
            )

            token_data.update({
                "access_token": new_access_token,
                "access_token_expires": access_token_expires.isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat()
            })

            # Store new access token
            access_ttl = int(timedelta(minutes=self.ACCESS_TOKEN_EXPIRE_MINUTES).total_seconds())
            self.redis_service.set_with_ttl(f"token:{new_access_token}", token_data, access_ttl)
            self.redis_service.sadd(f"user_tokens:{user_id}", new_access_token)

            logger.info(f"Access token refreshed successfully for user: {user_id}")

            return {
                "access_token": new_access_token,
                "token_type": "bearer",
                "access_token_expires": access_token_expires.timestamp()
            }

        except Exception as e:
            logger.error(f"Error refreshing token: {str(e)}")
            return None

    def verify_token(self, token: str) -> Optional[str]:
        """Verify the validity of an access token and return the associated user ID."""
        try:
            token_data = self.redis_service.get(f"token:{token}", deserialize_json=True)
            if not token_data:
                logger.warning("Token not found in Redis")
                return None

            if token_data.get("is_revoked"):
                logger.warning("Token has been revoked")
                return None

            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            user_id = payload.get("sub")
            
            if user_id:
                logger.debug(f"Token verified successfully for user: {user_id}")
            
            return user_id

        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error verifying token: {str(e)}")
            return None

    def revoke_all_tokens(self, user_id: str) -> bool:
        """Revoke all tokens associated with a specific user."""
        try:
            token_keys = self.redis_service.smembers(f"user_tokens:{user_id}")
            
            if not token_keys:
                logger.info(f"No tokens found for user: {user_id}")
                return False

            # Revoke all tokens
            pipeline = self.redis_service.pipeline()
            if pipeline:
                for token in token_keys:
                    token_data = self.redis_service.get(f"token:{token}", deserialize_json=True)
                    if token_data:
                        token_data["is_revoked"] = True
                        pipeline.set(f"token:{token}", json.dumps(token_data))

                pipeline.delete(f"user_tokens:{user_id}")
                pipeline.execute()
            else:
                # Fallback without pipeline
                for token in token_keys:
                    token_data = self.redis_service.get(f"token:{token}", deserialize_json=True)
                    if token_data:
                        token_data["is_revoked"] = True
                        self.redis_service.set_with_ttl(f"token:{token}", token_data, 3600)  # Keep for 1 hour
                
                self.redis_service.delete(f"user_tokens:{user_id}")
            
            logger.info(f"All tokens revoked successfully for user: {user_id}")
            return True

        except Exception as e:
            logger.error(f"Error revoking tokens: {str(e)}")
            return False
    
    async def get_current_user(self, credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
        """FastAPI dependency function to extract and verify the current user."""
        try:
            token = credentials.credentials
            user_id = self.verify_token(token)
            if user_id is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired token"
                )
            return user_id
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error in token verification: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed"
            )

    async def get_current_user_id(self, credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
        """Alias for get_current_user method for clarity when only user ID is needed"""
        return await self.get_current_user(credentials)
    
    def cleanup_expired_tokens(self) -> int:
        """Clean up expired tokens - Redis handles this automatically with TTL."""
        logger.debug("Token cleanup not needed - Redis handles TTL automatically")
        return 0

    async def initialize_user_progression(self, user_id: str, program: str = "MM", level: str = "M1") -> Optional[Dict]:
        """
        Initialize course progression for a new user
        
        Args:
            user_id: User ID
            program: Program name (default: 'MM')
            level: Level name (default: 'M1')
            
        Returns:
            Initialized course progression data or None if failed
        """
        try:
            course_progress = await self.progression_service.initialize_user_progression(program, level)
            
            if course_progress:
                logger.info(f"Initialized progression for user {user_id} with {len(course_progress)} courses")
                return course_progress
            else:
                logger.warning(f"No progression data initialized for user {user_id}")
                return None
                
        except Exception as e:
            logger.error(f"Error initializing user progression for {user_id}: {str(e)}")
            return None

# Lazy singleton for multiworker compatibility
_auth_service_instance = None

def get_auth_service() -> AuthService:
    """
    Get the global AuthService instance using lazy singleton pattern.
    Thread-safe for multiworker environments.
    """
    global _auth_service_instance
    if _auth_service_instance is None:
        _auth_service_instance = AuthService()
    return _auth_service_instance

auth_service = get_auth_service()