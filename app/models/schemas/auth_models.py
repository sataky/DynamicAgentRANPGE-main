from pydantic import BaseModel, EmailStr
from typing import Optional


class RefreshTokenRequest(BaseModel):
    """Request model for refreshing access token."""
    refresh_token: str

class TokenResponse(BaseModel):
    """Response model for token operations."""
    access_token: str
    token_type: str
    access_token_expires: float

class LogoutResponse(BaseModel):
    """Response model for logout operation."""
    message: str
    status: bool

class AuthErrorResponse(BaseModel):
    """Response model for authentication errors."""
    message: str
    status: bool
    detail: Optional[str] = None