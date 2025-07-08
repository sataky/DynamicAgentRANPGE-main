from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from bson import ObjectId
from .user import PyObjectId
import uuid

def generate_conversation_id() -> str:
    """Generate a conversation ID standard UUID format"""
    return str(uuid.uuid4())

class ConversationModel(BaseModel):
    id: Optional[PyObjectId] = Field(default_factory=PyObjectId, alias="_id")
    conversation_id: str = Field(default_factory=generate_conversation_id)  
    user_id: PyObjectId
    title: str
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    is_active: bool = True
    is_deleted: bool = False
    is_pinned: bool = False
    memory_key: str
    memory_summary: str = ""
    memory_token_count: int = 0
    memory_last_updated: Optional[datetime] = None

    class Config:
        validate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str,
            datetime: lambda dt: dt.isoformat()
        }

class ConversationCreate(BaseModel):
    user_id: str
    title: str = "New conversation"
    is_pinned: bool = False

class ConversationUpdate(BaseModel):
    title: Optional[str] = None
    is_active: Optional[bool] = None
    is_deleted: Optional[bool] = None
    is_pinned: Optional[bool] = None
    memory_summary: Optional[str] = None
    memory_token_count: Optional[int] = None

class ConversationSummary(BaseModel):
    id: str 
    title: str
    updated_at: datetime
    is_active: bool
    is_pinned: bool
    memory_summary: str
    message_count: Optional[int] = 0

    class Config:
        from_attributes = True

class ConversationResponse(BaseModel):
    id: str  
    user_id: str
    title: str
    created_at: datetime
    updated_at: datetime
    is_active: bool
    is_deleted: bool
    is_pinned: bool
    memory_key: str
    memory_summary: str
    memory_token_count: int
    memory_last_updated: Optional[datetime] = None
    messages: Optional[List] = None  

    class Config:
        from_attributes = True

class UserConversations(BaseModel):
    user_id: str
    conversations: List[ConversationSummary]