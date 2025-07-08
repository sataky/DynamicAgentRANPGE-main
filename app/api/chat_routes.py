from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any
from bson.objectid import ObjectId
import asyncio
import logging
import uuid
import re
import json
from fastapi.responses import JSONResponse

from app.models.entities.conversation import ConversationUpdate
from app.repositories.conversation_repository import ConversationCollection
from app.repositories.message_repository import MessageCollection
from app.repositories.user_repository import UserCollection
from app.services.chat.chat_service import get_chat_service
from app.models.schemas.evaluation_models import UserQuery
from app.services.chat.chat_service import handle_chat_request
from app.services.external.auth_service import auth_service

logger = logging.getLogger(__name__)


router = APIRouter(
    prefix="/api",
    tags=["chat"],
    dependencies=[Depends(auth_service.get_current_user)]
)

def is_valid_uuid(uuid_string: str) -> bool:
    """
    Validate if string is a valid UUID format (with dashes)
    Compatible with Claude/ChatGPT UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    """
    uuid_pattern = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        re.IGNORECASE
    )
    return bool(uuid_pattern.match(uuid_string))

def json_serializer(obj):
    """
    Custom JSON serializer for datetime and ObjectId objects
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, ObjectId):
        return str(obj)
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

def safe_json_dumps(data):
    """
    Safely serialize data to JSON with datetime and ObjectId support
    """
    return json.dumps(data, default=json_serializer)

def serialize_mongo_data(data):
    """
    Convert MongoDB data with ObjectIds to serializable format
    """
    if isinstance(data, list):
        return [serialize_mongo_data(item) for item in data]
    elif isinstance(data, dict):
        serialized = {}
        for key, value in data.items():
            if isinstance(value, ObjectId):
                serialized[key] = str(value)
            elif isinstance(value, datetime):
                serialized[key] = value.isoformat()
            elif isinstance(value, (dict, list)):
                serialized[key] = serialize_mongo_data(value)
            else:
                serialized[key] = value
        return serialized
    elif isinstance(data, ObjectId):
        return str(data)
    elif isinstance(data, datetime):
        return data.isoformat()
    else:
        return data

async def get_conversation_collection():
    return ConversationCollection()

async def get_message_collection():
    return MessageCollection()

# ─── Chat endpoint ──────────────────────────────────────
@router.post("/process-data")
async def process_data(q: UserQuery) -> Dict[str, Any]:
    """
    Process user chat request with conversation history and reference extraction.
    """
    logger.info("process-data ➤ start")
    
    try:
        result = await handle_chat_request(q.session_id, q.question)
        logger.info("process-data ➤ success")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"process-data ➤ error: {e}")
        raise HTTPException(500, f"Chat processing failed: {e}")


@router.post("/conversations/new-id", response_model=Dict[str, str])
async def generate_new_conversation_id():
    """
    Generate a new conversation ID without creating the conversation.
    The conversation will be created when the first message is sent.
    """
    conversation_id = str(uuid.uuid4())
    return {"conversation_id": conversation_id}

@router.get("/users/{user_id}/conversations")
async def get_user_conversations(
    user_id: str,
    limit: int = 50,
    conversation_collection: ConversationCollection = Depends(get_conversation_collection)
):
    """
    Get user conversations optimized for sidebar display.
    Returns conversations grouped by pinned/unpinned with metadata.
    """
    try:
        if not ObjectId.is_valid(user_id):
            raise HTTPException(status_code=400, detail="Invalid user ID format")
            
        user_object_id = ObjectId(user_id)
        
        all_conversations = await conversation_collection.list_user_conversations(
            user_id=user_object_id,
            active_only=True,
            include_deleted=False,
            limit=limit
        )
        
        pinned_conversations = [conv for conv in all_conversations if conv.is_pinned]
        unpinned_conversations = [conv for conv in all_conversations if not conv.is_pinned]
        
        pinned_conversations.sort(key=lambda x: x.updated_at, reverse=True)
        unpinned_conversations.sort(key=lambda x: x.updated_at, reverse=True)
        
        response_data = {
            "user_id": user_id,
            "total_count": len(all_conversations),
            "pinned_count": len(pinned_conversations),
            "unpinned_count": len(unpinned_conversations),
            "pinned_conversations": serialize_mongo_data([conv.__dict__ for conv in pinned_conversations]),
            "unpinned_conversations": serialize_mongo_data([conv.__dict__ for conv in unpinned_conversations]),
            "last_updated": max([conv.updated_at for conv in all_conversations]).isoformat() if all_conversations else None
        }
        
        return JSONResponse(content=response_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving sidebar conversations: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error retrieving sidebar conversations: {str(e)}")

@router.get("/chat/{conversation_id}")
async def get_conversation_with_messages(
    conversation_id: str,
    conversation_collection: ConversationCollection = Depends(get_conversation_collection)
):
    """
    Get a conversation with all its messages.
    """
    try:
        if not conversation_id or not is_valid_uuid(conversation_id):
            raise HTTPException(status_code=400, detail="Invalid conversation ID format (must be valid UUID)")
        
        conversation_with_messages = await conversation_collection.get_conversation_with_messages(conversation_id)
        
        if not conversation_with_messages:
            raise HTTPException(status_code=404, detail="Conversation not found")
        
        serialized_data = serialize_mongo_data(conversation_with_messages)
        return JSONResponse(content=serialized_data)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving conversation: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error retrieving conversation: {str(e)}")

@router.post("/chat")
async def chat(request: Dict[str, Any]):
    """
    Send a message and receive response using reactAgent with MongoDB persistence.
    Creates conversation automatically if conversation_id is not provided or doesn't exist.
    Tracks user activity for first message in conversation.
    """
    try:
        user_id = request.get("user_id")
        message = request.get("message")
        conversation_id = request.get("conversation_id")
        
        if not message or not user_id:
            raise HTTPException(status_code=400, detail="Message and user_id are required")
        
        chat_service = get_chat_service()
        result = await chat_service.process_chat_message(
            user_id=user_id,
            message=message,
            conversation_id=conversation_id
        )
        
        serialized_result = serialize_mongo_data(result)
        
        is_first_message = not conversation_id or not result.get("conversation_existed", True)
        if is_first_message:
            user_collection = UserCollection()
            asyncio.create_task(user_collection.add_activity_date(user_id))
        
        return JSONResponse(content=serialized_result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in chat endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Chat error: {str(e)}")

@router.patch("/chat/{conversation_id}")
async def update_conversation(
    conversation_id: str,
    update_data: ConversationUpdate,
    conversation_collection: ConversationCollection = Depends(get_conversation_collection)
):
    """
    Update conversation metadata (title, pinned status, etc.)
    """
    try:
        if not is_valid_uuid(conversation_id):
            raise HTTPException(status_code=400, detail="Invalid conversation ID format (must be valid UUID)")
        
        if not await conversation_collection.conversation_exists(conversation_id):
            raise HTTPException(status_code=404, detail="Conversation not found")
        
        update_dict = update_data.dict(exclude_unset=True)
        if update_dict:
            update_dict["updated_at"] = datetime.utcnow()
            updated_conversation = await conversation_collection.update_conversation(conversation_id, update_dict)
            serialized_data = serialize_mongo_data(updated_conversation.__dict__ if hasattr(updated_conversation, '__dict__') else updated_conversation)
            return JSONResponse(content=serialized_data)
        else:
            conversation = await conversation_collection.get_conversation(conversation_id)
            serialized_data = serialize_mongo_data(conversation.__dict__ if hasattr(conversation, '__dict__') else conversation)
            return JSONResponse(content=serialized_data)
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating conversation: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error updating conversation: {str(e)}")

@router.patch("/chat/{conversation_id}/pin")
async def toggle_pin_conversation(
    conversation_id: str,
    conversation_collection: ConversationCollection = Depends(get_conversation_collection)
):
    """
    Toggle the pinned status of a conversation
    """
    try:
        if not is_valid_uuid(conversation_id):
            raise HTTPException(status_code=400, detail="Invalid conversation ID format (must be valid UUID)")
        
        if not await conversation_collection.conversation_exists(conversation_id):
            raise HTTPException(status_code=404, detail="Conversation not found")
        
        new_pin_state = await conversation_collection.toggle_pin_conversation(conversation_id)
        return JSONResponse(content={"is_pinned": new_pin_state})
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error toggling pin status: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error toggling pin status: {str(e)}")

@router.delete("/chat/{conversation_id}", status_code=204)
async def delete_conversation(
    conversation_id: str,
    conversation_collection: ConversationCollection = Depends(get_conversation_collection)
):
    """
    Delete a conversation (soft delete)
    """
    try:
        if not is_valid_uuid(conversation_id):
            raise HTTPException(status_code=400, detail="Invalid conversation ID format (must be valid UUID)")
        
        if not await conversation_collection.conversation_exists(conversation_id, include_deleted=True):
            raise HTTPException(status_code=404, detail="Conversation not found")
        
        await conversation_collection.update_conversation(conversation_id, {
            "is_deleted": True,
            "updated_at": datetime.utcnow()
        }, include_deleted=True)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting conversation: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error deleting conversation: {str(e)}")

@router.post("/chat/{conversation_id}/regenerate")
async def regenerate_response(
    conversation_id: str,
    request: Dict[str, Any]
):
    """
    Regenerate the last assistant message in a conversation.
    Uses reactAgent and MongoDB persistence.
    """
    try:
        user_id = request.get("user_id")
        if not user_id:
            raise HTTPException(status_code=400, detail="user_id is required")
        
        if not is_valid_uuid(conversation_id):
            raise HTTPException(status_code=400, detail="Invalid conversation ID format")
        
        chat_service = get_chat_service()
        result = await chat_service.regenerate_last_message(
            conversation_id=conversation_id,
            user_id=user_id
        )
        
        serialized_result = serialize_mongo_data(result)
        return JSONResponse(content=serialized_result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error regenerating response: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error regenerating response: {str(e)}")