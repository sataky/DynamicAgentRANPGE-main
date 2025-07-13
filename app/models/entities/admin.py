from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, EmailStr, field_validator
from bson import ObjectId


class AdminModel(BaseModel):
    """
    Complete admin model for database storage.
    """
    id: Optional[str] = Field(None, alias="_id")
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    role: str = Field(default="admin")
    created_at: datetime = Field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    is_active: bool = Field(default=True)
    
    @field_validator('email')
    @classmethod
    def validate_skema_email(cls, v):
        """
        Validate that email belongs to skema.edu domain.
        """
        if not v.endswith('@skema.edu'):
            raise ValueError('Admin email must be from @skema.edu domain')
        return v
    
    @field_validator('role')
    @classmethod
    def validate_role(cls, v):
        """
        Validate admin role.
        """
        allowed_roles = ['admin', 'super_admin']
        if v not in allowed_roles:
            raise ValueError(f'Role must be one of: {allowed_roles}')
        return v
    
    class Config:
        populate_by_name = True
        json_encoders = {
            ObjectId: str,
            datetime: lambda v: v.isoformat()
        }


class AdminCreate(BaseModel):
    """
    Admin creation model for new admin registration.
    """
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    role: str = Field(default="admin")
    
    @field_validator('email')
    @classmethod
    def validate_skema_email(cls, v):
        """
        Validate that email belongs to skema.edu domain.
        """
        if not v.endswith('@skema.edu'):
            raise ValueError('Admin email must be from @skema.edu domain')
        return v
    
    @field_validator('role')
    @classmethod
    def validate_role(cls, v):
        """
        Validate admin role.
        """
        allowed_roles = ['admin', 'super_admin']
        if v not in allowed_roles:
            raise ValueError(f'Role must be one of: {allowed_roles}')
        return v


class AdminUpdate(BaseModel):
    """
    Admin update model for partial updates.
    """
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    last_login: Optional[datetime] = None
    
    @field_validator('email')
    @classmethod
    def validate_skema_email(cls, v):
        """
        Validate that email belongs to skema.edu domain.
        """
        if v and not v.endswith('@skema.edu'):
            raise ValueError('Admin email must be from @skema.edu domain')
        return v
    
    @field_validator('role')
    @classmethod
    def validate_role(cls, v):
        """
        Validate admin role.
        """
        if v:
            allowed_roles = ['admin', 'super_admin']
            if v not in allowed_roles:
                raise ValueError(f'Role must be one of: {allowed_roles}')
        return v


class AdminResponse(BaseModel):
    """
    Admin response model for API responses.
    """
    id: str
    username: str
    email: str
    role: str
    created_at: datetime
    last_login: Optional[datetime]
    is_active: bool
    
    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class AdminLoginRequest(BaseModel):
    """
    Admin login request model.
    """
    email: EmailStr
    
    @field_validator('email')
    @classmethod
    def validate_skema_email(cls, v):
        """
        Validate that email belongs to skema.edu domain.
        """
        if not v.endswith('@skema.edu'):
            raise ValueError('Admin email must be from @skema.edu domain')
        return v


class AdminLoginResponse(BaseModel):
    """
    Admin login response model.
    """
    access_token: str
    token_type: str = "bearer"
    admin: AdminResponse
    expires_in: int
