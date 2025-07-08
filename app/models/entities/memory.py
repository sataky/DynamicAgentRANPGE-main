from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from bson import ObjectId
from .user import PyObjectId

class MemorySnapshot(BaseModel):
    id: Optional[PyObjectId] = Field(default_factory=PyObjectId, alias="_id")
    conversation_id: PyObjectId
    user_id: PyObjectId
    memory_key: str
    summary: str
    token_count: int = 0
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)

    class Config:
        validate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str,
            datetime: lambda dt: dt.isoformat()
        }

class MemorySnapshotCreate(BaseModel):
    conversation_id: str
    user_id: str
    memory_key: str
    summary: str
    token_count: int = 0

class MemorySnapshotUpdate(BaseModel):
    summary: Optional[str] = None
    token_count: Optional[int] = None

class MemoryStats(BaseModel):
    conversation_id: str
    user_id: str
    memory_key: str
    summary_size: int
    message_count: int
    last_updated: datetime
    token_count: int

    class Config:
        from_attributes = True