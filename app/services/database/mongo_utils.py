"""
app/services/mongo_utils.py
──────────────────────────────────────────────
Async MongoDB helpers using Motor.
"""
import os
import uuid
from motor.motor_asyncio import AsyncIOMotorClient
from typing import Dict, List, Optional, Union
from dotenv import load_dotenv
from datetime import datetime
from bson import ObjectId
from app.logs import logger

load_dotenv()

_URI = os.getenv("MONGO_URI")
_DB = os.getenv("MONGO_DB")
_DB2 = os.getenv("MONGO_DB_CHAT")

_client = AsyncIOMotorClient(_URI)

async def get_mongo_client() -> AsyncIOMotorClient:
    """Get the shared MongoDB client instance."""
    return _client

class AsyncMongoDBService:
    """Unified async service for all MongoDB operations."""

    def __init__(self, uri: str = None, db_name: str = None, chat_db_name: str = None):
        self.uri = uri or _URI
        self.db_name = db_name or _DB
        self.chat_db_name = chat_db_name or _DB2
        
        if not self.uri:
            raise ValueError("Missing MongoDB URI. Check environment variables.")
        
        if uri and uri != _URI:
            self.client = AsyncIOMotorClient(self.uri)
        else:
            self.client = _client
            
        self.db = self.client[self.db_name]
        self.chat_db = self.client[self.chat_db_name]
        
        self.tools = self.db.tools
        self.topics = self.db.topics
        self.users = self.chat_db.users
        self.admins = self.chat_db.admins
        self.conversations = self.chat_db.conversations
        self.messages = self.chat_db.messages
        self.memories = self.chat_db.memories
        
        self._indexes_created = False
    
    async def connect(self) -> None:
        """Initialize connection and create indexes."""
        try:
            await self.client.admin.command('ping')
            
            if not self._indexes_created:
                await self._create_indexes()
                self._indexes_created = True
            
        except Exception as e:
            raise Exception(f"MongoDB connection error: {str(e)}")
    
    async def _create_indexes(self) -> None:
        """Create all necessary indexes."""
        try:
            await self.messages.create_index([("conversation_id", 1), ("timestamp", 1)])
            await self.messages.create_index([("conversation_id", 1), ("in_summary", 1)])
            
            await self.conversations.create_index([("user_id", 1)])
            await self.conversations.create_index([("updated_at", -1)])
            await self.conversations.create_index([("is_pinned", -1)])
            await self.conversations.create_index([("conversation_id", 1)], unique=True)
            
            try:
                await self.conversations.create_index([("user_id", 1), ("updated_at", -1)])
                await self.conversations.create_index([("user_id", 1), ("is_pinned", -1), ("updated_at", -1)])
                await self.conversations.create_index([("is_deleted", 1), ("user_id", 1)])
            except Exception:
                pass
            
            try:
                await self.memories.create_index([("memory_key", 1)], unique=True)
                await self.memories.create_index([("conversation_id", 1)])
                await self.memories.create_index([("user_id", 1)])
            except Exception:
                pass
            
            try:
                await self.users.create_index([("email", 1)], unique=True)
                await self.admins.create_index("email", unique=True)
            except Exception:
                await self.users.create_index([("email", 1)], unique=False)
                await self.admins.create_index("email", unique=False)
                
        except Exception:
            pass
    
    def generate_conversation_id(self) -> str:
        """Generate conversation ID in UUID format."""
        return str(uuid.uuid4())
    
    async def store_tool_doc(self, doc: Dict) -> None:
        """Insert tool record into tools collection."""
        await self.tools.insert_one(doc)

    async def fetch_all_tools(self) -> List[Dict]:
        """Return all tool records."""
        cursor = self.tools.find({})
        return await cursor.to_list(length=None)
    
    async def fetch_tools_by_course(self, course: str) -> List[Dict]:
        """Return tool records for specific course only."""
        cursor = self.tools.find({"course": course})
        return await cursor.to_list(length=None)

    async def upsert_module_topics(self, program: str, level: str, course: str, module: str, new_topics: List[str], module_order: int = None) -> None:
        """Insert or update module topics with module order."""
        update_data = {
            "program": program,
            "level": level,
            "course": course,
            "module": module,
            "last_updated": datetime.utcnow().isoformat()
        }
        
        if module_order is not None:
            update_data["module_order"] = module_order
        
        await self.topics.update_one(
            {"module": module, "course": course},
            {
                "$set": update_data,
                "$addToSet": {
                    "topics": {"$each": new_topics}
                }
            },
            upsert=True
        )

    async def get_module_topics(self, course: str, module: str) -> List[str]:
        """Get topic list for module and course."""
        doc = await self.topics.find_one({"course": course, "module": module})
        return doc.get("topics", []) if doc else []

    async def find_user_by_email(self, email: str) -> Optional[Dict]:
        """Find user by email."""
        return await self.users.find_one({"email": email})

    async def create_user(self, user_data: Dict) -> str:
        """Create new user."""
        result = await self.users.insert_one(user_data)
        return str(result.inserted_id)

    async def get_user_by_id(self, user_id: str) -> Optional[Dict]:
        """Get user by ID."""
        if not ObjectId.is_valid(user_id):
            return None
        
        user = await self.users.find_one({"_id": ObjectId(user_id)})
        if user:
            user["id"] = str(user["_id"])
            return user
        return None

    async def find_all_users(self) -> List[Dict]:
        """Find all users in the collection."""
        cursor = self.users.find({})
        users = await cursor.to_list(length=None)
        for user in users:
            user["id"] = str(user["_id"])
        return users

    async def update_user(self, user_id: str, update_data: Dict) -> Optional[Dict]:
        """Update user information."""
        if not ObjectId.is_valid(user_id):
            return None
        
        update_dict = {k: v for k, v in update_data.items() if v is not None}
        if not update_dict:
            return await self.get_user_by_id(user_id)
        
        update_dict["updated_at"] = datetime.now()
        
        result = await self.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": update_dict}
        )
        
        if result.modified_count > 0 or result.matched_count > 0:
            return await self.get_user_by_id(user_id)
        return None

    async def update_user_raw(self, user_id: str, update_operations: Dict) -> Optional[Dict]:
        """
        Update user with raw MongoDB operations (like $push, $set, etc.)
        
        Args:
            user_id: User ID
            update_operations: Dictionary containing MongoDB update operations
            
        Returns:
            Updated user document or None
        """
        if not ObjectId.is_valid(user_id):
            return None
        
        result = await self.users.update_one(
            {"_id": ObjectId(user_id)},
            update_operations
        )
        
        if result.modified_count > 0 or result.matched_count > 0:
            return await self.get_user_by_id(user_id)
        return None

    async def delete_user(self, user_id: str) -> bool:
        """Delete user by ID."""
        if not ObjectId.is_valid(user_id):
            return False
        
        result = await self.users.delete_one({"_id": ObjectId(user_id)})
        return result.deleted_count > 0

    async def update_last_login(self, user_id: str) -> bool:
        """
        Update user last login timestamp and last activity date.
        Does not count as activity for activity_dates tracking.
        """
        try:
            if not ObjectId.is_valid(user_id):
                return False
            
            now = datetime.now()
            
            result = await self.users.update_one(
                {"_id": ObjectId(user_id)},
                {
                    "$set": {
                        "last_login": now, 
                        "updated_at": now,
                        "learning_analytics.last_activity_date": now
                    },
                    "$setOnInsert": {
                        "learning_analytics.activity_dates": []
                    }
                }
            )
            return result.modified_count > 0
            
        except Exception as e:
            logger.error(f"Error updating last login for user {user_id}: {str(e)}")
            return False


    async def find_conversations_by_user(self, user_id: str, limit: int = 50) -> List[Dict]:
        """Find user conversations."""
        if isinstance(user_id, str):
            user_id = ObjectId(user_id)
        
        cursor = self.conversations.find(
            {"user_id": user_id, "is_deleted": {"$ne": True}}
        ).sort("updated_at", -1).limit(limit)
        
        conversations = await cursor.to_list(length=None)
        
        for conv in conversations:
            conv["id"] = conv["conversation_id"]
            conv["user_id"] = str(conv["user_id"])
            if "_id" in conv:
                del conv["_id"]
        
        return conversations

    async def create_conversation(self, conversation_data: Dict) -> str:
        """Create new conversation."""
        if "user_id" in conversation_data and isinstance(conversation_data["user_id"], str):
            conversation_data["user_id"] = ObjectId(conversation_data["user_id"])
        
        if "conversation_id" in conversation_data and conversation_data["conversation_id"]:
            conversation_id = conversation_data["conversation_id"]
        else:
            conversation_id = self.generate_conversation_id()
            conversation_data["conversation_id"] = conversation_id
        
        if "memory_key" not in conversation_data or not conversation_data["memory_key"]:
            conversation_data["memory_key"] = f"memory_{conversation_id}"
        
        now = datetime.now()
        conversation_data["created_at"] = now
        conversation_data["updated_at"] = now
        
        conversation_data.setdefault("is_active", True)
        conversation_data.setdefault("is_deleted", False)
        conversation_data.setdefault("is_pinned", False)
        conversation_data.setdefault("memory_summary", "")
        conversation_data.setdefault("memory_token_count", 0)
        
        await self.conversations.insert_one(conversation_data)
        return conversation_id

    async def get_conversation(self, conversation_id: str, include_deleted: bool = False) -> Optional[Dict]:
        """
        Get conversation by external ID.
        
        Args:
            conversation_id: The conversation ID to retrieve
            include_deleted: Whether to include soft-deleted conversations
            
        Returns:
            Conversation dict or None if not found or deleted (unless include_deleted=True)
        """
        query = {"conversation_id": conversation_id}
        if not include_deleted:
            query["is_deleted"] = {"$ne": True}
            
        conversation = await self.conversations.find_one(query)
        if conversation:
            conversation["id"] = conversation["conversation_id"]
            conversation["user_id"] = str(conversation["user_id"])
            if "_id" in conversation:
                del conversation["_id"]
            return conversation
        return None

    async def get_conversation_with_messages(self, conversation_id: str) -> Optional[Dict]:
        """Get conversation with its messages."""
        conversation = await self.get_conversation(conversation_id)
        if not conversation:
            return None
        
        messages = await self.get_conversation_messages(conversation_id)
        conversation["messages"] = messages
        return conversation

    async def update_conversation(self, conversation_id: str, update_data: Dict, include_deleted: bool = False) -> Optional[Dict]:
        """
        Update conversation.
        
        Args:
            conversation_id: The conversation ID to update
            update_data: Data to update
            include_deleted: Whether to allow updating soft-deleted conversations
            
        Returns:
            Updated conversation dict or None if not found or deleted (unless include_deleted=True)
        """
        update_dict = {k: v for k, v in update_data.items() if v is not None}
        update_dict["updated_at"] = datetime.now()
        
        query = {"conversation_id": conversation_id}
        if not include_deleted:
            query["is_deleted"] = {"$ne": True}
        
        result = await self.conversations.update_one(
            query,
            {"$set": update_dict}
        )
        
        if result.modified_count > 0 or result.matched_count > 0:
            return await self.get_conversation(conversation_id, include_deleted)
        return None

    async def update_last_activity(self, conversation_id: str) -> bool:
        """Update conversation last activity."""
        result = await self.conversations.update_one(
            {"conversation_id": conversation_id},
            {"$set": {"updated_at": datetime.now()}}
        )
        return result.modified_count > 0 or result.matched_count > 0

    async def list_user_conversations(self, user_id: Union[str, ObjectId], skip: int = 0, limit: int = 50, include_deleted: bool = False, active_only: bool = True) -> List[Dict]:
        """List user conversations with pagination."""
        if isinstance(user_id, str):
            user_id = ObjectId(user_id)
        
        query = {"user_id": user_id}
        if not include_deleted:
            query["is_deleted"] = False
        if active_only:
            query["is_active"] = True
        
        pipeline = [
            {"$match": query},
            {
                "$lookup": {
                    "from": "messages",
                    "localField": "conversation_id",
                    "foreignField": "conversation_id",
                    "as": "messages"
                }
            },
            {
                "$addFields": {
                    "message_count": {"$size": "$messages"}
                }
            },
            {
                "$project": {
                    "conversation_id": 1,
                    "title": 1,
                    "updated_at": 1,
                    "is_active": 1,
                    "is_pinned": 1,
                    "memory_summary": 1,
                    "message_count": 1
                }
            },
            {"$sort": {"is_pinned": -1, "updated_at": -1}},
            {"$skip": skip},
            {"$limit": limit}
        ]
        
        try:
            conversations = await self.conversations.aggregate(pipeline).to_list(length=None)
        except Exception:
            conversations = await self.conversations.find(
                query,
                {"conversation_id": 1, "title": 1, "updated_at": 1, "is_active": 1, "is_pinned": 1, "memory_summary": 1}
            ).sort("updated_at", -1).skip(skip).limit(limit).to_list(length=None)
        
        for conv in conversations:
            conv["id"] = conv["conversation_id"]
            if "_id" in conv:
                del conv["_id"]
        
        return conversations

    async def delete_conversation(self, conversation_id: str, user_id: str = None) -> bool:
        """Soft delete conversation."""
        query = {"conversation_id": conversation_id}
        if user_id:
            query["user_id"] = ObjectId(user_id) if isinstance(user_id, str) else user_id
        
        result = await self.conversations.update_one(
            query,
            {
                "$set": {
                    "is_deleted": True,
                    "is_active": False,
                    "updated_at": datetime.now()
                }
            }
        )
        return result.modified_count > 0

    async def toggle_pin_conversation(self, conversation_id: str) -> bool:
        """Toggle conversation pin status."""
        conversation = await self.conversations.find_one(
            {"conversation_id": conversation_id},
            {"is_pinned": 1}
        )
        
        if not conversation:
            return False
        
        new_state = not conversation.get("is_pinned", False)
        
        result = await self.conversations.update_one(
            {"conversation_id": conversation_id},
            {
                "$set": {
                    "is_pinned": new_state,
                    "updated_at": datetime.now()
                }
            }
        )
        
        return new_state if result.modified_count > 0 else conversation.get("is_pinned", False)

    async def conversation_exists(self, conversation_id: str, include_deleted: bool = False) -> bool:
        """
        Check if conversation exists.
        
        Args:
            conversation_id: The conversation ID to check
            include_deleted: Whether to include soft-deleted conversations
            
        Returns:
            True if conversation exists and is not deleted (unless include_deleted=True)
        """
        query = {"conversation_id": conversation_id}
        if not include_deleted:
            query["is_deleted"] = {"$ne": True}
            
        count = await self.conversations.count_documents(query)
        return count > 0

    async def add_message(self, message_data: Dict) -> str:
        """Add message to conversation."""
        message_data["timestamp"] = datetime.now()
        message_data.setdefault("in_summary", False)
        
        result = await self.messages.insert_one(message_data)
        return str(result.inserted_id)

    async def get_message(self, message_id: str) -> Optional[Dict]:
        """Get message by ID."""
        if not ObjectId.is_valid(message_id):
            return None
        
        message = await self.messages.find_one({"_id": ObjectId(message_id)})
        if message:
            message["id"] = str(message.pop("_id"))
            return message
        return None

    async def get_conversation_messages(self, conversation_id: str, limit: int = 100) -> List[Dict]:
        """Get conversation messages."""
        cursor = self.messages.find(
            {"conversation_id": conversation_id}
        ).sort("timestamp", 1).limit(limit)
        
        messages = await cursor.to_list(length=None)
        for msg in messages:
            msg["id"] = str(msg.pop("_id"))
        
        return messages

    async def get_conversation_messages_with_options(self, conversation_id: str, skip: int = 0, limit: Optional[int] = 50, include_summarized: bool = True) -> List[Dict]:
        """Get conversation messages with advanced options."""
        query = {"conversation_id": conversation_id}
        if not include_summarized:
            query["in_summary"] = False
        
        find_options = {
            "sort": [("timestamp", 1)],
            "skip": skip
        }
        
        if limit is not None:
            find_options["limit"] = limit
        
        cursor = self.messages.find(query).sort("timestamp", 1).skip(skip)
        if limit is not None:
            cursor = cursor.limit(limit)
        
        messages = await cursor.to_list(length=None)
        for msg in messages:
            msg["id"] = str(msg.pop("_id"))
        
        return messages

    async def count_messages(self, conversation_id: str, include_summarized: bool = True) -> int:
        """Count messages in conversation."""
        query = {"conversation_id": conversation_id}
        if not include_summarized:
            query["in_summary"] = False
        
        return await self.messages.count_documents(query)

    async def get_last_user_message(self, conversation_id: str) -> Optional[Dict]:
        """Get last user message from conversation."""
        message = await self.messages.find_one(
            {"conversation_id": conversation_id, "role": "user"},
            sort=[("timestamp", -1)]
        )
        
        if message:
            message["id"] = str(message.pop("_id"))
            return message
        return None

    async def delete_last_assistant_message(self, conversation_id: str) -> bool:
        """Delete last assistant message."""
        last_assistant_msg = await self.messages.find_one(
            {"conversation_id": conversation_id, "role": "assistant"},
            sort=[("timestamp", -1)]
        )
        
        if last_assistant_msg:
            result = await self.messages.delete_one({"_id": last_assistant_msg["_id"]})
            return result.deleted_count > 0
        
        return False

    async def mark_messages_as_summarized(self, message_ids: List[str]) -> int:
        """Mark messages as summarized."""
        object_ids = [ObjectId(id) for id in message_ids if ObjectId.is_valid(id)]
        
        result = await self.messages.update_many(
            {"_id": {"$in": object_ids}},
            {"$set": {"in_summary": True}}
        )
        
        return result.modified_count

    async def delete_conversation_messages(self, conversation_id: str, soft_delete: bool = True) -> int:
        """Delete all messages for conversation."""
        if soft_delete:
            result = await self.messages.update_many(
                {"conversation_id": conversation_id},
                {"$set": {"in_summary": True}}
            )
            return result.modified_count
        else:
            result = await self.messages.delete_many({"conversation_id": conversation_id})
            return result.deleted_count

    async def get_recent_messages(self, conversation_id: str, limit: int = 20) -> List[Dict]:
        """Get recent messages excluding summarized."""
        cursor = self.messages.find(
            {"conversation_id": conversation_id, "in_summary": {"$ne": True}}
        ).sort("timestamp", -1).limit(limit)
        
        messages = await cursor.to_list(length=None)
        messages = list(reversed(messages))
        
        for msg in messages:
            msg["id"] = str(msg.pop("_id"))
        
        return messages

    async def bulk_update_messages(self, conversation_id: str, updates: Dict) -> int:
        """Bulk update messages in conversation."""
        result = await self.messages.update_many(
            {"conversation_id": conversation_id},
            {"$set": updates}
        )
        return result.modified_count

    async def store_memory(self, memory_data: Dict) -> None:
        """Store or update memory."""
        await self.memories.update_one(
            {"memory_key": memory_data["memory_key"]},
            {"$set": memory_data},
            upsert=True
        )

    async def get_memory(self, memory_key: str) -> Optional[Dict]:
        """Get memory by key."""
        return await self.memories.find_one({"memory_key": memory_key})

    async def get_user_memories(self, user_id: str) -> List[Dict]:
        """Get all user memories."""
        cursor = self.memories.find({"user_id": user_id})
        return await cursor.to_list(length=None)

    async def delete_memory(self, memory_key: str) -> bool:
        """Delete memory by key."""
        result = await self.memories.delete_one({"memory_key": memory_key})
        return result.deleted_count > 0

    async def get_conversation_memory(self, conversation_id: str) -> Optional[Dict]:
        """Get memory for conversation."""
        return await self.memories.find_one({"conversation_id": conversation_id})

    async def update_conversation_memory(self, conversation_id: str, memory_data: Dict) -> None:
        """Update conversation memory."""
        memory_data["updated_at"] = datetime.now()
        await self.memories.update_one(
            {"conversation_id": conversation_id},
            {"$set": memory_data},
            upsert=True
        )

    async def search_conversations(self, user_id: str, query: str, limit: int = 10) -> List[Dict]:
        """Search conversations by title or content."""
        search_filter = {
            "user_id": ObjectId(user_id) if isinstance(user_id, str) else user_id,
            "is_deleted": {"$ne": True},
            "$or": [
                {"title": {"$regex": query, "$options": "i"}},
                {"description": {"$regex": query, "$options": "i"}}
            ]
        }
        
        cursor = self.conversations.find(search_filter).sort("updated_at", -1).limit(limit)
        conversations = await cursor.to_list(length=None)
        
        for conv in conversations:
            conv["id"] = conv["conversation_id"]
            conv["user_id"] = str(conv["user_id"])
            if "_id" in conv:
                del conv["_id"]
        
        return conversations

    async def get_conversation_summary(self, conversation_id: str) -> Optional[Dict]:
        """Get conversation with message count."""
        pipeline = [
            {"$match": {"conversation_id": conversation_id}},
            {"$lookup": {
                "from": "messages",
                "localField": "conversation_id",
                "foreignField": "conversation_id",
                "as": "messages"
            }},
            {"$addFields": {"message_count": {"$size": "$messages"}}},
            {"$project": {"messages": 0}}
        ]
        
        cursor = self.conversations.aggregate(pipeline)
        results = await cursor.to_list(length=1)
        
        if results:
            conv = results[0]
            conv["id"] = conv["conversation_id"]
            conv["user_id"] = str(conv["user_id"])
            if "_id" in conv:
                del conv["_id"]
            return conv
        
        return None

    async def close(self) -> None:
        """Close connection if using custom client."""
        if hasattr(self, 'client') and self.client != _client:
            self.client.close()

    async def is_connected(self) -> bool:
        """Check connection status."""
        try:
            await self.client.admin.command('ping')
            return True
        except Exception:
            return False

    async def get_modules_by_course_ordered(self, course: str) -> List[Dict]:
        """Get all modules for a course ordered by module_order."""
        cursor = self.topics.find({"course": course}).sort("module_order", 1)
        return await cursor.to_list(length=None)
        
    async def get_course_modules_with_order(self, program: str, level: str) -> Dict[str, List[Dict]]:
        """Get all courses with their modules ordered by module_order."""
        cursor = self.topics.find({"program": program, "level": level})
        docs = await cursor.to_list(length=None)
        
        courses = {}
        for doc in docs:
            course_name = doc.get("course")
            if course_name not in courses:
                courses[course_name] = []
            courses[course_name].append({
                "module": doc.get("module"),
                "module_order": doc.get("module_order", 999),
                "topics": doc.get("topics", [])
            })
        
        # Sort modules by module_order for each course
        for course_name in courses:
            courses[course_name].sort(key=lambda x: x.get("module_order", 999))
        
        return courses

    ### Admin new methods 
    async def find_admin_by_email(self, email: str) -> Optional[Dict]:
        """
        Find admin by email.
        """
        return await self.admins.find_one({"email": email})

    async def create_admin(self, admin_data: Dict) -> str:
        """
        Create new admin.
        """
        result = await self.admins.insert_one(admin_data)
        return str(result.inserted_id)

    async def find_all_admins(self) -> List[Dict]:
        """
        Find all admins in the collection.
        """
        cursor = self.admins.find({})
        admins = await cursor.to_list(length=None)
        for admin in admins:
            admin["id"] = str(admin["_id"])
        return admins

    async def update_admin(self, admin_id: str, update_data: Dict) -> Optional[Dict]:
        """
        Update admin information.
        """
        if not ObjectId.is_valid(admin_id):
            return None
        
        update_dict = {k: v for k, v in update_data.items() if v is not None}
        if not update_dict:
            admin = await self.admins.find_one({"_id": ObjectId(admin_id)})
            if admin:
                admin["id"] = str(admin["_id"])
            return admin
        
        update_dict["updated_at"] = datetime.now()
        
        result = await self.admins.update_one(
            {"_id": ObjectId(admin_id)},
            {"$set": update_dict}
        )
        
        if result.modified_count > 0 or result.matched_count > 0:
            admin = await self.admins.find_one({"_id": ObjectId(admin_id)})
            if admin:
                admin["id"] = str(admin["_id"])
            return admin
        return None


_service_instance = None

async def get_service() -> AsyncMongoDBService:
    """Get global service instance."""
    global _service_instance
    if _service_instance is None:
        _service_instance = AsyncMongoDBService()
        await _service_instance.connect()
    return _service_instance


async def store_tool_doc(doc: Dict) -> None:
    service = await get_service()
    await service.store_tool_doc(doc)

async def fetch_all_tools() -> List[Dict]:
    service = await get_service()
    return await service.fetch_all_tools()

async def fetch_tools_by_course(course: str) -> List[Dict]:
    service = await get_service()
    return await service.fetch_tools_by_course(course)

async def upsert_module_topics(program: str, level: str, course: str, module: str, new_topics: List[str], module_order: int = None) -> None:
    service = await get_service()
    await service.upsert_module_topics(program, level, course, module, new_topics, module_order)

async def get_module_topics(course: str, module: str) -> List[str]:
    service = await get_service()
    return await service.get_module_topics(course, module)

async def find_user_by_email(email: str) -> Optional[Dict]:
    service = await get_service()
    return await service.find_user_by_email(email)

async def create_user(user_data: Dict) -> str:
    service = await get_service()
    return await service.create_user(user_data)

async def get_user_by_id(user_id: str) -> Optional[Dict]:
    service = await get_service()
    return await service.get_user_by_id(user_id)

async def find_all_users() -> List[Dict]:
    service = await get_service()
    return await service.find_all_users()

async def update_user(user_id: str, update_data: Dict) -> Optional[Dict]:
    service = await get_service()
    return await service.update_user(user_id, update_data)

async def update_user_raw(user_id: str, update_operations: Dict) -> Optional[Dict]:
    service = await get_service()
    return await service.update_user_raw(user_id, update_operations)

async def delete_user(user_id: str) -> bool:
    service = await get_service()
    return await service.delete_user(user_id)

async def update_last_login(user_id: str) -> bool:
    service = await get_service()
    return await service.update_last_login(user_id)

async def find_conversations_by_user(user_id: str, limit: int = 50) -> List[Dict]:
    service = await get_service()
    return await service.find_conversations_by_user(user_id, limit)

async def create_conversation(conversation_data: Dict) -> str:
    service = await get_service()
    return await service.create_conversation(conversation_data)

async def get_conversation(conversation_id: str, include_deleted: bool = False) -> Optional[Dict]:
    service = await get_service()
    return await service.get_conversation(conversation_id, include_deleted)

async def get_conversation_with_messages(conversation_id: str) -> Optional[Dict]:
    service = await get_service()
    return await service.get_conversation_with_messages(conversation_id)

async def update_conversation(conversation_id: str, update_data: Dict, include_deleted: bool = False) -> Optional[Dict]:
    service = await get_service()
    return await service.update_conversation(conversation_id, update_data, include_deleted)

async def update_last_activity(conversation_id: str) -> bool:
    service = await get_service()
    return await service.update_last_activity(conversation_id)

async def list_user_conversations(user_id: str, skip: int = 0, limit: int = 50, include_deleted: bool = False, active_only: bool = True) -> List[Dict]:
    service = await get_service()
    return await service.list_user_conversations(user_id, skip, limit, include_deleted, active_only)

async def delete_conversation(conversation_id: str, user_id: str = None) -> bool:
    service = await get_service()
    return await service.delete_conversation(conversation_id, user_id)

async def toggle_pin_conversation(conversation_id: str) -> bool:
    service = await get_service()
    return await service.toggle_pin_conversation(conversation_id)

async def conversation_exists(conversation_id: str, include_deleted: bool = False) -> bool:
    service = await get_service()
    return await service.conversation_exists(conversation_id, include_deleted)

async def add_message(message_data: Dict) -> str:
    service = await get_service()
    return await service.add_message(message_data)

async def get_message(message_id: str) -> Optional[Dict]:
    service = await get_service()
    return await service.get_message(message_id)

async def get_conversation_messages(conversation_id: str, limit: int = 100) -> List[Dict]:
    service = await get_service()
    return await service.get_conversation_messages(conversation_id, limit)

async def get_conversation_messages_with_options(conversation_id: str, skip: int = 0, limit: Optional[int] = 50, include_summarized: bool = True) -> List[Dict]:
    service = await get_service()
    return await service.get_conversation_messages_with_options(conversation_id, skip, limit, include_summarized)

async def count_messages(conversation_id: str, include_summarized: bool = True) -> int:
    service = await get_service()
    return await service.count_messages(conversation_id, include_summarized)

async def get_last_user_message(conversation_id: str) -> Optional[Dict]:
    service = await get_service()
    return await service.get_last_user_message(conversation_id)

async def delete_last_assistant_message(conversation_id: str) -> bool:
    service = await get_service()
    return await service.delete_last_assistant_message(conversation_id)

async def mark_messages_as_summarized(message_ids: List[str]) -> int:
    service = await get_service()
    return await service.mark_messages_as_summarized(message_ids)

async def delete_conversation_messages(conversation_id: str, soft_delete: bool = True) -> int:
    service = await get_service()
    return await service.delete_conversation_messages(conversation_id, soft_delete)

async def get_recent_messages(conversation_id: str, limit: int = 20) -> List[Dict]:
    service = await get_service()
    return await service.get_recent_messages(conversation_id, limit)

async def bulk_update_messages(conversation_id: str, updates: Dict) -> int:
    service = await get_service()
    return await service.bulk_update_messages(conversation_id, updates)

async def store_memory(memory_data: Dict) -> None:
    service = await get_service()
    await service.store_memory(memory_data)

async def get_memory(memory_key: str) -> Optional[Dict]:
    service = await get_service()
    return await service.get_memory(memory_key)

async def get_user_memories(user_id: str) -> List[Dict]:
    service = await get_service()
    return await service.get_user_memories(user_id)

async def delete_memory(memory_key: str) -> bool:
    service = await get_service()
    return await service.delete_memory(memory_key)

async def get_conversation_memory(conversation_id: str) -> Optional[Dict]:
    service = await get_service()
    return await service.get_conversation_memory(conversation_id)

async def update_conversation_memory(conversation_id: str, memory_data: Dict) -> None:
    service = await get_service()
    await service.update_conversation_memory(conversation_id, memory_data)

async def search_conversations(user_id: str, query: str, limit: int = 10) -> List[Dict]:
    service = await get_service()
    return await service.search_conversations(user_id, query, limit)

async def get_conversation_summary(conversation_id: str) -> Optional[Dict]:
    service = await get_service()
    return await service.get_conversation_summary(conversation_id)

async def get_modules_by_course_ordered(course: str) -> List[Dict]:
    service = await get_service()
    return await service.get_modules_by_course_ordered(course)

async def get_course_modules_with_order(program: str, level: str) -> Dict[str, List[Dict]]:
    service = await get_service()
    return await service.get_course_modules_with_order(program, level)

async def generate_conversation_id() -> str:
    service = await get_service()
    return service.generate_conversation_id()

### Admins helper functions
async def find_admin_by_email(email: str) -> Optional[Dict]:
    """
    Find admin by email.
    """
    service = await get_service()
    return await service.find_admin_by_email(email)

async def create_admin(admin_data: Dict) -> str:
    """
    Create new admin.
    """
    service = await get_service()
    return await service.create_admin(admin_data)

async def find_all_admins() -> List[Dict]:
    """
    Find all admins.
    """
    service = await get_service()
    return await service.find_all_admins()

async def update_admin(admin_id: str, update_data: Dict) -> Optional[Dict]:
    """
    Update admin information.
    """
    service = await get_service()
    return await service.update_admin(admin_id, update_data)
