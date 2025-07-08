from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from bson import ObjectId

from app.models.entities.conversation import ConversationCreate, ConversationUpdate, ConversationSummary, ConversationResponse
from app.services.database.mongo_utils import get_service, generate_conversation_id

class ConversationCollection:
    """Collection for managing conversation operations"""
    
    def __init__(self):
        """Initialize the conversations collection"""
        pass
    
    async def create_conversation(self, data: Union[ConversationCreate, Dict[str, Any]]) -> str:
        """
        Create new conversation
        
        Args:
            data: Conversation data to create
            
        Returns:
            External conversation ID
        """
        if isinstance(data, ConversationCreate):
            conversation_data = data.model_dump()
        else:
            conversation_data = data.copy()
        
        service = await get_service()
        conversation_id = await service.create_conversation(conversation_data)
        return conversation_id
    
    async def get_conversation(self, conversation_id: str, include_deleted: bool = False) -> Optional[ConversationResponse]:
        """
        Get conversation by external ID
        
        Args:
            conversation_id: External conversation ID
            include_deleted: Whether to include soft-deleted conversations
            
        Returns:
            ConversationResponse or None if not found
        """
        service = await get_service()
        conversation = await service.get_conversation(conversation_id, include_deleted)
        if conversation:
            return ConversationResponse(**conversation)
        return None
    
    async def get_conversation_with_messages(self, conversation_id: str, include_deleted: bool = False) -> Optional[Dict[str, Any]]:
        """
        Get conversation with its messages
        
        Args:
            conversation_id: External conversation ID
            include_deleted: Whether to include soft-deleted conversations
            
        Returns:
            Dictionary with conversation and messages
        """
        service = await get_service()
        return await service.get_conversation_with_messages(conversation_id)
    
    async def update_conversation(self, 
                                conversation_id: str, 
                                update_data: Union[ConversationUpdate, Dict[str, Any]],
                                include_deleted: bool = False) -> Optional[ConversationResponse]:
        """
        Update existing conversation
        
        Args:
            conversation_id: External conversation ID
            update_data: Data to update
            include_deleted: Whether to allow updating soft-deleted conversations
            
        Returns:
            Updated ConversationResponse or None if failed
        """
        if isinstance(update_data, ConversationUpdate):
            update_dict = {k: v for k, v in update_data.model_dump().items() if v is not None}
        else:
            update_dict = {k: v for k, v in update_data.items() if v is not None}
        
        service = await get_service()
        updated_conversation = await service.update_conversation(conversation_id, update_dict, include_deleted)
        if updated_conversation:
            return ConversationResponse(**updated_conversation)
        return None
    
    async def update_last_activity(self, conversation_id: str) -> bool:
        """
        Update conversation last activity date
        
        Args:
            conversation_id: External conversation ID
            
        Returns:
            True if successful, False otherwise
        """
        service = await get_service()
        return await service.update_last_activity(conversation_id)
    
    async def list_user_conversations(self, 
                                user_id: str, 
                                skip: int = 0, 
                                limit: int = 50,
                                include_deleted: bool = False,
                                active_only: bool = True) -> List[ConversationSummary]:
        """
        Get all conversations for user
        
        Args:
            user_id: User ID
            skip: Number of items to skip
            limit: Number of items to return
            include_deleted: Include deleted conversations
            active_only: Include only active conversations
            
        Returns:
            List of conversations as ConversationSummary
        """
        service = await get_service()
        conversations = await service.list_user_conversations(user_id, skip, limit, include_deleted, active_only)
        
        result = []
        for conv in conversations:
            result.append(ConversationSummary(**conv))
        
        return result
    
    async def mark_conversation_as_deleted(self, conversation_id: str) -> bool:
        """
        Mark conversation as deleted
        
        Args:
            conversation_id: External conversation ID
            
        Returns:
            True if successful, False otherwise
        """
        service = await get_service()
        return await service.delete_conversation(conversation_id)
    
    async def toggle_pin_conversation(self, conversation_id: str) -> bool:
        """
        Toggle conversation pinned state
        
        Args:
            conversation_id: External conversation ID
            
        Returns:
            New pinned state
        """
        service = await get_service()
        return await service.toggle_pin_conversation(conversation_id)

    async def conversation_exists(self, conversation_id: str, include_deleted: bool = False) -> bool:
        """
        Check if conversation exists
        
        Args:
            conversation_id: External conversation ID
            include_deleted: Whether to include soft-deleted conversations
            
        Returns:
            True if conversation exists
        """
        service = await get_service()
        return await service.conversation_exists(conversation_id, include_deleted)

    def generate_conversation_id(self) -> str:
        """
        Generate conversation ID in UUID format
        
        Returns:
            New conversation ID
        """
        return generate_conversation_id()