from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from bson import ObjectId
from app.services.database.mongo_utils import get_service

from app.models.entities.message import MessageCreate, MessageUpdate, MessageResponse, Reference

class MessageCollection:
    """Collection for managing message operations"""
    
    def __init__(self):
        """Initialize the messages collection"""
        pass
    
    async def create_message(self, data: Dict[str, Any]) -> ObjectId:
        """
        Create a new message in the database.
        
        Args:
            data: Message data dictionary
            
        Returns:
            ObjectId of the created message
        """
        service = await get_service()
        message_id = await service.add_message(data)
        return ObjectId(message_id)
    
    async def add_message(self, data: Union[MessageCreate, Dict[str, Any]]) -> str:
        """
        Add new message to conversation
        
        Args:
            data: Message data to create
            
        Returns:
            ID of created message
        """
        if isinstance(data, MessageCreate):
            message_data = data.model_dump()
        else:
            message_data = data.copy()
        
        service = await get_service()
        message_id = await service.add_message(message_data)
        return message_id
    
    async def get_message(self, message_id: str) -> Optional[MessageResponse]:
        """
        Get message by ID
        
        Args:
            message_id: Message ID
            
        Returns:
            MessageResponse or None if not found
        """
        service = await get_service()
        message = await service.get_message(message_id)
        if message:
            references = message.get("references", [])
            if references and isinstance(references[0], dict):
                message["references"] = [Reference(**ref) for ref in references]
            
            return MessageResponse(**message)
        return None
    
    async def get_conversation_messages(self, 
                                      conversation_id: str,
                                      skip: int = 0, 
                                      limit: Optional[int] = 50,
                                      include_summarized: bool = True) -> List[MessageResponse]:
        """
        Get messages for conversation
        
        Args:
            conversation_id: External conversation ID
            skip: Number of items to skip
            limit: Number of items to return (None for all)
            include_summarized: Include messages marked as summarized
            
        Returns:
            List of messages as MessageResponse
        """
        service = await get_service()
        messages = await service.get_conversation_messages_with_options(
            conversation_id, skip, limit, include_summarized
        )
        
        result = []
        for msg in messages:
            references = msg.get("references", [])
            if references and isinstance(references[0], dict):
                msg["references"] = [Reference(**ref) for ref in references]
            
            result.append(MessageResponse(**msg))
        
        return result
    
    async def get_conversation_messages_by_external_id(self, conversation_id: str) -> List[MessageResponse]:
        """
        Get all messages for conversation by external ID
        
        Args:
            conversation_id: External conversation ID
            
        Returns:
            List of all messages
        """
        service = await get_service()
        messages = await service.get_conversation_messages(conversation_id, limit=None)
        
        result = []
        for msg in messages:
            references = msg.get("references", [])
            if references and isinstance(references[0], dict):
                msg["references"] = [Reference(**ref) for ref in references]
            
            result.append(MessageResponse(**msg))
        
        return result
    
    async def count_messages(self, 
                          conversation_id: str,
                          include_summarized: bool = True) -> int:
        """
        Count messages in conversation
        
        Args:
            conversation_id: External conversation ID
            include_summarized: Include messages marked as summarized
            
        Returns:
            Number of messages
        """
        service = await get_service()
        return await service.count_messages(conversation_id, include_summarized)
    
    async def get_last_user_message(self, conversation_id: str) -> Optional[MessageResponse]:
        """
        Get last user message from conversation
        
        Args:
            conversation_id: External conversation ID
            
        Returns:
            Last user message or None
        """
        service = await get_service()
        message = await service.get_last_user_message(conversation_id)
        if message:
            return MessageResponse(**message)
        return None
    
    async def delete_last_assistant_message(self, conversation_id: str) -> bool:
        """
        Delete last assistant message from conversation
        
        Args:
            conversation_id: External conversation ID
            
        Returns:
            True if message was deleted
        """
        service = await get_service()
        return await service.delete_last_assistant_message(conversation_id)
    
    async def mark_messages_as_summarized(self, message_ids: List[str]) -> int:
        """
        Mark multiple messages as summarized
        
        Args:
            message_ids: List of message IDs to mark
            
        Returns:
            Number of messages updated
        """
        service = await get_service()
        return await service.mark_messages_as_summarized(message_ids)
    
    async def delete_conversation_messages(self, 
                                       conversation_id: str,
                                       soft_delete: bool = True) -> int:
        """
        Delete all messages for conversation
        
        Args:
            conversation_id: External conversation ID
            soft_delete: If True, mark messages as summarized instead of deleting
            
        Returns:
            Number of messages deleted or updated
        """
        service = await get_service()
        return await service.delete_conversation_messages(conversation_id, soft_delete)
    
    async def delete_message(self, message_id: str) -> bool:
        """
        Delete a specific message by ID.
        
        Args:
            message_id: Message ID to delete
            
        Returns:
            True if message was deleted, False otherwise
        """
        try:
            service = await get_service()
            
            result = await service.messages.delete_one({"_id": ObjectId(message_id)})
            return result.deleted_count > 0
            
        except Exception as e:
            print(f"Error deleting message {message_id}: {str(e)}")
            return False
    
    async def increment_message_count(self, conversation_id: str) -> bool:
        """
        Increment the message count for a conversation.
        
        Args:
            conversation_id: Conversation UUID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            service = await get_service()
            
            result = await service.conversations.update_one(
                {"conversation_id": conversation_id},
                {"$inc": {"message_count": 1}}
            )
            return result.modified_count > 0
            
        except Exception as e:
            print(f"Error incrementing message count for conversation {conversation_id}: {str(e)}")
            return False