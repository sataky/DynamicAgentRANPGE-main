# ----------------------------------------------------------
#   Global, *shared* objects — visible to every module:
#   • `agents_cache` : Dict[str, ReActAgent] -> cache per course
#   • `tools_cache`  : Dict[str, List[QueryEngineTool]] -> tools per course
#   • `history`      : per‑session rolling chat memory (simple in‑RAM)
#   • `_lock`        : asyncio.Lock to prevent racing
# ----------------------------------------------------------
from __future__ import annotations
from typing import List, Tuple, Dict, Optional, Any
import asyncio
from llama_index.core.tools import QueryEngineTool
from llama_index.core import PromptTemplate
from app.utils import prompt_helpers


conversation_history: Dict[str, list] = {}

react_system_header_str = prompt_helpers.reset_system_prompt_for_agent() 
react_system_prompt = PromptTemplate(react_system_header_str)

agents_cache: Dict[str, Any] = {}                    
tools_cache: Dict[str, List[QueryEngineTool]] = {}   
history: Dict[str, List[Tuple[str, str]]] = {}       

_lock = asyncio.Lock()

_chat_service = None

def get_chat_service():
    global _chat_service
    if _chat_service is None:
        from app.services.chat.chat_service import get_chat_service
        _chat_service = get_chat_service()
    return _chat_service

@property
def tools() -> List[QueryEngineTool]:
    return tools_cache.get("all", [])

@property 
def agent():
    return agents_cache.get("all")

def get_hist(sid: str) -> List[Tuple[str, str]]:
    return history.setdefault(sid, [])

def append_hist(sid: str, role: str, msg: str) -> None:
    get_hist(sid).append((role, msg))

async def process_chat_with_persistence(
    user_id: str, 
    message: str, 
    conversation_id: str = None
) -> Dict:
    chat_service = get_chat_service()
    return await chat_service.process_chat_message(
        user_id=user_id,
        message=message,
        conversation_id=conversation_id
    )

async def get_agent_for_course(course_filter: str = None) -> Any:
    cache_key = course_filter or "all"
    
    if cache_key not in agents_cache:
        await _build_agent_for_course(course_filter)
    
    return agents_cache.get(cache_key)

def get_cached_agent(course_filter: str = None) -> Any:
    """
    Get cached agent without async build.
    Returns None if agent is not cached.
    """
    cache_key = course_filter or "all"
    return agents_cache.get(cache_key)

async def _build_agent_for_course(course_filter: str = None) -> None:
    cache_key = course_filter or "all"
    
    async with _lock:
        if cache_key in agents_cache:
            return
            
        from app.services.external.tools_service import load_tools_from_json_server
        from llama_index.core.agent import ReActAgent
        from app.config import init_llama_index_settings

        course_tools = await load_tools_from_json_server(course_filter)
        tools_cache[cache_key] = course_tools

        agent = ReActAgent.from_tools(
            course_tools,
            llm=init_llama_index_settings(),
            verbose=False,
            max_iterations=20
        )
        agent.update_prompts({"agent_worker:system_prompt": react_system_prompt})
        agent.reset()
        
        agents_cache[cache_key] = agent
        
        if course_filter:
            print(f"[state] Agent cached for course '{course_filter}' – {len(course_tools)} tools")
        else:
            print(f"[state] Agent cached for all courses – {len(course_tools)} tools")

async def clear_course_cache(course_filter: str = None) -> None:
    async with _lock:
        if course_filter:
            cache_key = course_filter
            agents_cache.pop(cache_key, None)
            tools_cache.pop(cache_key, None)
            print(f"[state] Cache cleared for course '{course_filter}'")
        else:
            agents_cache.clear()
            tools_cache.clear()
            print("[state] All course caches cleared")

async def reload_agent_from_json(course_filter: str = None) -> None:
    cache_key = course_filter or "all"
    
    async with _lock:
        agents_cache.pop(cache_key, None) 
        tools_cache.pop(cache_key, None)
    
    await _build_agent_for_course(course_filter)