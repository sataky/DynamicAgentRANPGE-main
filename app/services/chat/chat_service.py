# app/services/chat_service.py
import os
import asyncio
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from fastapi import HTTPException
from bson.objectid import ObjectId

import app.state as state
from app.repositories.conversation_repository import ConversationCollection
from app.repositories.message_repository import MessageCollection
from app.services.chat.memory_service import MemoryService
from app.logs import logger


class ChatService:
    """
    Chat service that integrates reactAgent with MongoDB persistence.
    Handles conversations, messages, and memory management using MemoryService.
    """
    
    def __init__(self):
        """
        Initialize the chat service with required dependencies.
        """
        self.conversation_collection = ConversationCollection()
        self.message_collection = MessageCollection()
        self.memory_service = MemoryService()
    
    async def process_chat_message(
        self, 
        user_id: str, 
        message: str, 
        conversation_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Process a chat message using reactAgent and persist to MongoDB with memory management.
        
        Args:
            user_id: ID of the user sending the message
            message: User's message content
            conversation_id: Optional conversation ID (creates new if None)
            
        Returns:
            Dictionary containing response, conversation_id, and references
        """
        try:
            # Validate user ID
            if not ObjectId.is_valid(user_id):
                raise HTTPException(status_code=400, detail="Invalid user ID format")
            
            user_object_id = ObjectId(user_id)
            is_new_conversation = False
            
            # Create or get conversation
            if conversation_id is None:
                conversation_id = str(uuid.uuid4())
                await self._create_new_conversation(conversation_id, user_object_id, message)
                is_new_conversation = True
            else:
                if not await self.conversation_collection.conversation_exists(conversation_id):
                    await self._create_new_conversation(conversation_id, user_object_id, message)
                    is_new_conversation = True
            
            # Initialize or get memory for conversation
            memory_key = await self.memory_service.initialize_conversation_memory(
                conversation_id, user_id
            )
            
            # Detect if this is the first message in the conversation
            memory = await self.memory_service.get_memory(memory_key)
            messages = memory.get_all()
            is_first_message = len(messages) == 0 or is_new_conversation
            
            # Add user message to memory
            await self.memory_service.add_user_message(memory_key, message)
            
            # Save user message to database
            user_message_id = await self._save_message(
                conversation_id, "user", message, user_object_id
            )
            
            # Get conversation context with user profile only for first message
            conversation_context = await self.memory_service.get_memory_context(
                memory_key, 
                user_id, 
                include_user_profile=is_first_message
            )
            
            # Process with reactAgent
            agent_response = await self._query_react_agent(message, conversation_context)
            
            # Add assistant response to memory
            await self.memory_service.add_assistant_message(memory_key, agent_response["response"])
            
            # Save assistant response to database
            assistant_message_id = await self._save_message(
                conversation_id, "assistant", agent_response["response"], user_object_id, agent_response["references"]
            )
            
            # Update conversation metadata
            await self._update_conversation_metadata(conversation_id, message)
            
            return {
                "conversation_id": conversation_id,
                "response": agent_response["response"],
                "references": agent_response["references"],
                "user_message_id": str(user_message_id),
                "assistant_message_id": str(assistant_message_id)
            }
            
        except Exception as e:
            logger.error(f"Error processing chat message: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Chat processing failed: {str(e)}")
    
    async def _create_new_conversation(
        self, 
        conversation_id: str, 
        user_id: ObjectId, 
        initial_message: str
    ) -> None:
        """
        Create a new conversation with generated title.
        
        Args:
            conversation_id: UUID for the conversation
            user_id: User's ObjectId
            initial_message: First message to generate title from
        """
        title = await self.memory_service.generate_title(initial_message)
        
        conversation_data = {
            "conversation_id": conversation_id,
            "user_id": user_id,
            "title": title,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "message_count": 0,
            "is_pinned": False,
            "is_deleted": False,
            "memory_summary": ""
        }
        
        await self.conversation_collection.create_conversation(conversation_data)
        logger.info(f"Created new conversation {conversation_id} with title: {title}")
    
    async def _save_message(
        self, 
        conversation_id: str, 
        role: str, 
        content: str, 
        user_id: ObjectId,
        references: Optional[List[Dict[str, Any]]] = None
    ) -> ObjectId:
        """
        Save a message to the database with optional references.
        
        Args:
            conversation_id: Conversation UUID
            role: Message role (user/assistant)
            content: Message content
            user_id: User's ObjectId
            references: Optional list of references for the message
            
        Returns:
            ObjectId of the saved message
        """
        message_data = {
            "conversation_id": conversation_id,
            "role": role,
            "content": content,
            "user_id": user_id,
            "timestamp": datetime.utcnow(),
            "input_type": "text"
        }
        
        # Add references if provided
        if references:
            message_data["references"] = references
        
        message_id = await self.message_collection.create_message(message_data)
        logger.info(f"Saved {role} message {message_id} to conversation {conversation_id} with {len(references) if references else 0} references")
        return message_id
    
    async def _query_react_agent(self, user_message: str, context: str) -> Dict[str, Any]:
        """
        Query the reactAgent with context and extract references.
        
        Args:
            user_message: User's message
            context: Conversation context from memory
            
        Returns:
            Dictionary with response text and references
        """
        # Check if agent is available
        agent = await state.get_agent_for_course(None)
        if agent is None:
            raise HTTPException(500, "ReactAgent not initialized. Please restart the server or upload a new document.")
        
        # Build prompt with context
        if context:
            full_prompt = f"{context}\n\nUser: {user_message}"
        else:
            full_prompt = user_message
        
        # Query agent
        loop = asyncio.get_running_loop()
        
        def do_agent_query():
            return agent.query(full_prompt)
        
        try:
            agent_result = await loop.run_in_executor(None, do_agent_query)
            
            # Extract references from source nodes
            references = self._extract_references(agent_result.source_nodes)
            
            return {
                "response": agent_result.response,
                "references": references
            }
            
        except Exception as e:
            logger.error(f"ReactAgent query failed: {str(e)}")
            raise HTTPException(500, f"Agent error: {str(e)}")
    
    def _extract_references(self, source_nodes) -> List[Dict[str, Any]]:
        """
        Extract and format references from agent source nodes.
        
        Args:
            source_nodes: Source nodes from agent query result
            
        Returns:
            List of formatted reference dictionaries
        """
        if not source_nodes:
            return []
        
        # Group references by file
        grouped_refs = {}
        
        for ns in source_nodes:
            node = ns.node
            metadata = node.metadata or {}
            
            file_name = metadata.get("file_name", "")
            page_label = metadata.get("page_label", "")
            upload_date = metadata.get("upload_date", "")
            
            if not file_name or not page_label:
                continue
            
            # Format title
            title = os.path.splitext(file_name)[0].replace("_", " ")
            
            # Extract page number
            page = page_label.split("_")[-1] if "_" in page_label else page_label
            
            if title not in grouped_refs:
                grouped_refs[title] = {
                    "pages": set(),
                    "upload_date": upload_date
                }
            grouped_refs[title]["pages"].add(page)
        
        # Format final references
        references = []
        for title, info in grouped_refs.items():
            pages_sorted = sorted(info["pages"], key=lambda x: int(x) if x.isdigit() else 0)
            pages_str = ", ".join(pages_sorted)
            
            references.append({
                "file_name": title,
                "page_label": pages_str,
                "upload_date": info["upload_date"]
            })
        
        logger.info(f"Extracted {len(references)} references from agent response")
        return references
    
    async def _update_conversation_metadata(self, conversation_id: str, last_message: str) -> None:
        """
        Update conversation metadata after new message.
        
        Args:
            conversation_id: Conversation UUID
            last_message: Last user message for potential title update
        """
        update_data = {
            "updated_at": datetime.utcnow()
        }
        
        # Increment message count
        await self.message_collection.increment_message_count(conversation_id)
        
        # Update conversation
        await self.conversation_collection.update_conversation(conversation_id, update_data)
    
    async def regenerate_last_message(
        self,
        conversation_id: str,
        user_id: str
    ) -> Dict[str, Any]:
        """
        Regenerate the last assistant message in a conversation using memory context.
        
        Args:
            conversation_id: Conversation UUID
            user_id: User ID
            
        Returns:
            Dictionary containing new response and references
        """
        try:
            # Validate user ID
            if not ObjectId.is_valid(user_id):
                raise HTTPException(status_code=400, detail="Invalid user ID format")
            
            user_object_id = ObjectId(user_id)
            
            # Check if conversation exists
            if not await self.conversation_collection.conversation_exists(conversation_id):
                raise HTTPException(status_code=404, detail="Conversation not found")
            
            # Get memory for conversation
            memory_key = await self.memory_service.get_memory_by_conversation(conversation_id)
            if not memory_key:
                raise HTTPException(status_code=404, detail="No memory found for conversation")
            
            # Get recent messages
            messages = await self.message_collection.get_conversation_messages(conversation_id, limit=20)
            
            if not messages:
                raise HTTPException(status_code=404, detail="No messages found in conversation")
            
            # Find the last user message
            last_user_message = None
            for msg in reversed(messages):
                if msg.role == "user":
                    last_user_message = msg.content
                    break
            
            if not last_user_message:
                raise HTTPException(status_code=404, detail="No user message found to regenerate response for")
            
            # Delete the last assistant message if it exists
            if messages and messages[-1].role == "assistant":
                await self.message_collection.delete_message(str(messages[-1].id))
            
            # Get conversation context from memory
            conversation_context = await self.memory_service.get_memory_context(memory_key)
            
            # Process with reactAgent
            agent_response = await self._query_react_agent(last_user_message, conversation_context)
            
            # Update memory with new assistant response
            await self.memory_service.add_assistant_message(memory_key, agent_response["response"])
            
            # Save new assistant response
            assistant_message_id = await self._save_message(
                conversation_id, "assistant", agent_response["response"], user_object_id, agent_response["references"]
            )
            
            # Update conversation metadata
            await self._update_conversation_metadata(conversation_id, last_user_message)
            
            return {
                "conversation_id": conversation_id,
                "response": agent_response["response"],
                "references": agent_response["references"],
                "assistant_message_id": str(assistant_message_id)
            }
            
        except Exception as e:
            logger.error(f"Error regenerating message: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Message regeneration failed: {str(e)}")


# Global service instance
_chat_service = None

def get_chat_service() -> ChatService:
    """
    Get the global chat service instance.
    
    Returns:
        ChatService instance
    """
    global _chat_service
    if _chat_service is None:
        _chat_service = ChatService()
    return _chat_service


# Legacy functions for compatibility (keep process-data endpoint working)
async def handle_chat_request(session_id: str, user_question: str) -> Dict[str, Any]:
    """
    Legacy chat handler for process-data endpoint compatibility.
    
    Args:
        session_id: Session identifier
        user_question: User's question
        
    Returns:
        Chat response dictionary
    """
    logger.info(f"[legacy_chat] Processing request for session {session_id}")
    
    # Check if agent is available
    agent = await state.get_agent_for_course(None)
    if agent is None:
        raise HTTPException(500, "ReactAgent not initialized. Please restart the server or upload a new document.")
    
    # Get or create session history
    session_history = state.get_hist(session_id)
    
    # Build context from session history
    context_lines = []
    for role, msg in session_history[-5:]:
        context_lines.append(f"{role.upper()}: {msg}")
    context = "\n".join(context_lines) if context_lines else ""
    
    # Build full prompt
    if context:
        full_prompt = f"{context}\n\nUser: {user_question}"
    else:
        full_prompt = user_question
    
    # Query agent
    loop = asyncio.get_running_loop()
    
    def do_agent_query():
        return agent.query(full_prompt)
    
    try:
        agent_result = await loop.run_in_executor(None, do_agent_query)
        
        # Extract references
        references = []
        if agent_result.source_nodes:
            grouped_refs = {}
            
            for ns in agent_result.source_nodes:
                node = ns.node
                metadata = node.metadata or {}
                
                file_name = metadata.get("file_name", "")
                page_label = metadata.get("page_label", "")
                upload_date = metadata.get("upload_date", "")
                
                if not file_name or not page_label:
                    continue
                
                title = os.path.splitext(file_name)[0].replace("_", " ")
                page = page_label.split("_")[-1] if "_" in page_label else page_label
                
                if title not in grouped_refs:
                    grouped_refs[title] = {
                        "pages": set(),
                        "upload_date": upload_date
                    }
                grouped_refs[title]["pages"].add(page)
            
            for title, info in grouped_refs.items():
                pages_sorted = sorted(info["pages"], key=lambda x: int(x) if x.isdigit() else 0)
                pages_str = ", ".join(pages_sorted)
                
                references.append({
                    "file_name": title,
                    "page_label": pages_str,
                    "upload_date": info["upload_date"]
                })
        
        # Update session history
        state.append_hist(session_id, "user", user_question)
        state.append_hist(session_id, "assistant", agent_result.response)
        
        return {
            "response": agent_result.response,
            "references": references,
            "session_id": session_id
        }
        
    except Exception as e:
        logger.error(f"Legacy chat request failed: {str(e)}")
        raise HTTPException(500, f"Agent error: {str(e)}")