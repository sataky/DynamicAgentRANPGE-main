from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from llama_index.core.memory import ChatMemoryBuffer
from llama_index.core.base.llms.types import ChatMessage, MessageRole
from fastapi import HTTPException
import uuid

# Imports from our application
from app.services.database.mongo_utils import get_service
from app.utils import prompt_helpers
from app.services.external.azure_openai_service import AzureOpenAIService
from app.services.chat.user_context_service import UserContextService

class MemoryService:
    """Service for managing conversation memories with Llama Index"""

    def __init__(self):
        """Initialize the memory service"""
        self.active_memories = {}
        self.openai_service = AzureOpenAIService()
        self.user_context_service = UserContextService()
    
    async def create_memory(self, conversation_id: str, user_id: str) -> str:
        """
        Create new conversation memory
        
        Args:
            conversation_id: Conversation ID
            user_id: User ID
            
        Returns:
            memory_key: Unique key for the memory
        """
        try:
            memory_key = f"memory_{conversation_id}_{uuid.uuid4().hex[:8]}"
            
            memory = ChatMemoryBuffer.from_defaults(token_limit=4000)
            self.active_memories[memory_key] = memory
            
            memory_data = {
                "memory_key": memory_key,
                "conversation_id": conversation_id,
                "user_id": user_id,
                "created_at": datetime.now(timezone.utc),
                "summary": "",
                "messages_count": 0,
                "messages": []
            }
            
            service = await get_service()
            await service.store_memory(memory_data)
            return memory_key
            
        except Exception as e:
            print(f"Error creating memory: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Memory error: {str(e)}")
    
    async def get_memory(self, memory_key: str) -> ChatMemoryBuffer:
        """
        Retrieve existing memory by key
        
        Args:
            memory_key: Memory key
            
        Returns:
            The chat memory object
        """
        if memory_key in self.active_memories:
            return self.active_memories[memory_key]
        
        service = await get_service()
        memory_data = await service.get_memory(memory_key)
        if not memory_data:
            raise ValueError(f"Memory not found: {memory_key}")
        
        memory = ChatMemoryBuffer.from_defaults(token_limit=4000)
        
        messages = memory_data.get("messages", [])
        for msg in messages:
            memory.put_messages(ChatMessage(
                role=MessageRole.USER if msg["role"] == "user" else MessageRole.ASSISTANT,
                content=msg["content"]
            ))
        
        self.active_memories[memory_key] = memory
        return memory
    
    async def add_user_message(self, memory_key: str, message: str) -> None:
        """
        Add user message to memory
        
        Args:
            memory_key: Memory key
            message: Message content
        """
        memory = await self.get_memory(memory_key)
        memory.put_messages(ChatMessage(role=MessageRole.USER, content=message))
        
        service = await get_service()
        memory_data = await service.get_memory(memory_key)
        if memory_data:
            messages = memory_data.get("messages", [])
            messages.append({"role": "user", "content": message})
            
            update_data = {
                "messages": messages,
                "messages_count": memory_data.get("messages_count", 0) + 1
            }
            
            await service.update_conversation_memory(memory_data["conversation_id"], update_data)
    
    async def add_assistant_message(self, memory_key: str, message: str) -> None:
        """
        Add assistant message to memory
        
        Args:
            memory_key: Memory key
            message: Message content
        """
        memory = await self.get_memory(memory_key)
        memory.put_messages(ChatMessage(role=MessageRole.ASSISTANT, content=message))
        
        service = await get_service()
        memory_data = await service.get_memory(memory_key)
        if memory_data:
            messages = memory_data.get("messages", [])
            messages.append({"role": "assistant", "content": message})
            
            update_data = {
                "messages": messages,
                "messages_count": memory_data.get("messages_count", 0) + 1
            }
            
            await service.update_conversation_memory(memory_data["conversation_id"], update_data)
    
    async def get_chat_history(self, memory_key: str) -> List[Dict[str, str]]:
        """
        Retrieve complete message history for memory
        
        Args:
            memory_key: Memory key
            
        Returns:
            List of messages with their roles
        """
        memory = await self.get_memory(memory_key)
        return memory.get_all()
    
    async def get_memory_context(self, memory_key: str, user_id: str = None, include_user_profile: bool = False) -> str:
        """
        Get memory context as formatted string for LLM input
        
        Args:
            memory_key: Memory key
            user_id: User ID for enriched context
            include_user_profile: Whether to include user profile (first message only)
            
        Returns:
            Formatted memory context optionally enriched with user data
        """
        try:
            memory = await self.get_memory(memory_key)
            messages = memory.get_all()
            
            if len(messages) <= 12:
                messages_to_format = messages
                formatted_context = self._format_messages(messages_to_format)
                
            elif len(messages) <= 20:
                first_messages = messages[:3]
                recent_messages = messages[-10:]
                
                formatted_context = "Conversation start:\n"
                formatted_context += self._format_messages(first_messages)
                
                if len(messages) > 13:
                    formatted_context += "\n[... conversation continues ...]\n\n"
                
                formatted_context += "Recent discussion:\n"
                formatted_context += self._format_messages(recent_messages)
                
            else:
                first_messages = messages[:3]  
                last_messages = messages[-7:]  
                messages_to_format = first_messages + last_messages
                formatted_context = self._format_messages(messages_to_format)

            conversation_context = "Recent Messages:\n" + formatted_context
            
            if include_user_profile and user_id:
                user_context = await self.user_context_service.get_user_context_for_agent(user_id)
                if user_context:
                    return f"{user_context}\n\n{conversation_context}"
            
            return conversation_context
        except Exception as e:
            print(f"Error retrieving memory context: {str(e)}")
            return "No context available."
    
    def _format_messages(self, messages) -> str:
        """
        Format messages for context display
        
        Args:
            messages: List of messages to format
            
        Returns:
            Formatted message string
        """
        formatted_context = ""
        for msg in messages:
            role = msg.role.upper() if hasattr(msg, "role") else "SYSTEM"
            content = msg.content if hasattr(msg, "content") else str(msg)
            formatted_context += f"{role}: {content}\n"
        return formatted_context
        
    async def delete_memory(self, memory_key: str) -> bool:
        """
        Delete conversation memory
        
        Args:
            memory_key: Memory key
            
        Returns:
            True if deletion was successful, False otherwise
        """
        try:
            service = await get_service()
            success = await service.delete_memory(memory_key)
            
            if memory_key in self.active_memories:
                del self.active_memories[memory_key]
            
            return success
        except Exception as e:
            print(f"Error deleting memory: {str(e)}")
            return False
    
    async def update_memory_summary(self, memory_key: str, summary: str) -> bool:
        """
        Update memory summary
        
        Args:
            memory_key: Memory key
            summary: New summary
            
        Returns:
            True if successful, False otherwise
        """
        try:
            service = await get_service()
            memory_data = await service.get_memory(memory_key)
            if not memory_data:
                return False
            
            update_data = {"summary": summary}
            await service.update_conversation_memory(memory_data["conversation_id"], update_data)
            
            return True
        except Exception as e:
            print(f"Error updating memory summary: {str(e)}")
            return False
    
    async def get_memory_by_conversation(self, conversation_id: str) -> Optional[str]:
        """
        Get memory key for conversation
        
        Args:
            conversation_id: Conversation ID
            
        Returns:
            Memory key or None if not found
        """
        service = await get_service()
        memory_data = await service.get_conversation_memory(conversation_id)
        if memory_data:
            return memory_data.get("memory_key")
        return None
    
    async def initialize_conversation_memory(self, conversation_id: str, user_id: str) -> str:
        """
        Initialize memory for new conversation
        
        Args:
            conversation_id: Conversation ID
            user_id: User ID
            
        Returns:
            Memory key for the new memory
        """
        existing_memory_key = await self.get_memory_by_conversation(conversation_id)
        if existing_memory_key:
            return existing_memory_key
        
        return await self.create_memory(conversation_id, user_id)
    
    async def get_memory_stats(self, memory_key: str) -> Dict[str, Any]:
        """
        Get statistics about memory
        
        Args:
            memory_key: Memory key
            
        Returns:
            Dictionary with memory statistics
        """
        service = await get_service()
        memory_data = await service.get_memory(memory_key)
        if not memory_data:
            raise ValueError(f"Memory not found: {memory_key}")
        
        messages_count = memory_data.get("messages_count", 0)
        summary = memory_data.get("summary", "")
        summary_length = len(summary)
        estimated_tokens = summary_length // 4
        
        return {
            "memory_key": memory_key,
            "conversation_id": memory_data.get("conversation_id"),
            "user_id": memory_data.get("user_id"),
            "created_at": memory_data.get("created_at"),
            "messages_count": messages_count,
            "summary_length": summary_length,
            "estimated_tokens": estimated_tokens
        }
    
    async def clear_conversation_memory(self, conversation_id: str) -> bool:
        """
        Clear memory for conversation by creating new empty memory
        
        Args:
            conversation_id: Conversation ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            service = await get_service()
            memory_data = await service.get_conversation_memory(conversation_id)
            if not memory_data:
                return False
            
            memory_key = memory_data.get("memory_key")
            user_id = memory_data.get("user_id")
            
            if memory_key:
                await self.delete_memory(memory_key)
            
            if user_id:
                await self.create_memory(conversation_id, user_id)
                return True
            else:
                conversation = await service.get_conversation(conversation_id)
                if conversation and "user_id" in conversation:
                    user_id = conversation["user_id"]
                    await self.create_memory(conversation_id, user_id)
                    return True
            
            return False
        except Exception as e:
            print(f"Error clearing conversation memory: {str(e)}")
            return False
    
    async def generate_summary(self, conversation_text: str) -> str:
        """
        Generate a summary of conversation text using Azure OpenAI.
        
        Args:
            conversation_text: Text to summarize
            
        Returns:
            Generated summary
        """
        try:
            if not conversation_text.strip():
                return ""
            
            summary_prompt = prompt_helpers.conversation_summary_prompt(conversation_text)
            messages = [
                {"role": "system", "content": "You are an AI assistant that creates clear, concise summaries of conversations."},
                {"role": "user", "content": summary_prompt}
            ]
            
            completion = await self.openai_service.generate_completion(
                messages=messages,
                temperature=0.3,
                max_tokens=500,
                stream=False
            )
            
            summary = self.openai_service.extract_text_from_completion(completion)
            return summary.strip() if summary else ""
            
        except Exception as e:
            print(f"Error generating summary: {str(e)}")
            return ""
    
    async def generate_title(self, first_message: str) -> str:
        """
        Generate a conversation title based on the first message.
        
        Args:
            first_message: First message of the conversation
            
        Returns:
            Generated title
        """
        try:
            if not first_message.strip():
                return "New Conversation"
            
            title_prompt = prompt_helpers.conversation_title_prompt(first_message)
            messages = [
                {"role": "system", "content": "You generate short, relevant conversation titles."},
                {"role": "user", "content": title_prompt}
            ]
            
            completion = await self.openai_service.generate_completion(
                messages=messages,
                temperature=0.3,
                max_tokens=20,
                stream=False
            )
            
            title = self.openai_service.extract_text_from_completion(completion)
            
            if title:
                title = title.strip().strip('"\'').strip()
                if len(title) > 50:
                    title = title[:47] + "..."
                return title
            
            return "New Conversation"
            
        except Exception as e:
            print(f"Error generating title: {str(e)}")
            return "New Conversation"