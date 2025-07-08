from pydantic import BaseModel, Field
from typing import Optional, List, Literal
from datetime import datetime
from bson import ObjectId
from .user import PyObjectId

class Reference(BaseModel):
    """
    Model for references/sources from documents
    """
    file_name: str
    page_label: str
    upload_date: str

class MessageModel(BaseModel):
    id: Optional[PyObjectId] = Field(default_factory=PyObjectId, alias="_id")
    conversation_id: PyObjectId
    role: Literal["user", "assistant", "system"]
    content: str
    timestamp: datetime = Field(default_factory=datetime.now)
    input_type: Literal["text", "audio"] = "text"
    in_summary: bool = False
    references: Optional[List[Reference]] = None

    class Config:
        validate_by_name = True
        json_schema_extra = {
            "example": {
                "conversation_id": "5f9c8a7b2d1f2e3b4c5d6e7f",
                "role": "user",
                "content": "Hello, how are you?",
                "input_type": "text",
                "created_at": "2023-01-01T12:00:00Z",
                "in_summary": False
            }
        }

class MessageCreate(BaseModel):
    conversation_id: str
    role: Literal["user", "assistant", "system"]
    content: str
    input_type: Literal["text", "audio"] = "text"
    references: Optional[List[Reference]] = None

class MessageUpdate(BaseModel):
    content: Optional[str] = None
    in_summary: Optional[bool] = None
    references: Optional[List[Reference]] = None

class MessageResponse(BaseModel):
    id: str
    conversation_id: str
    role: str
    content: str
    timestamp: datetime
    input_type: str
    references: Optional[List[Reference]] = None

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "5f9c8a7b2d1f2e3b4c5d6e7f",
                "conversation_id": "5f9c8a7b2d1f2e3b4c5d6e7f",
                "role": "user",
                "content": "Hello, how are you?",
                "input_type": "text",
                "created_at": "2023-01-01T12:00:00Z",
                "in_summary": False
            }
        }

class ConversationMessages(BaseModel):
    conversation_id: str
    messages: List[MessageResponse]

class UserMessageRequest(BaseModel):
    content: str
    input_type: Literal["text", "audio"] = "text"

class AssistantStreamResponse(BaseModel):
    conversation_id: str
    content: str
    done: bool = False
    error: Optional[str] = None