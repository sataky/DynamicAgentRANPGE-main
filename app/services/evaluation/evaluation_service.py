# app/services/evaluation_service.py

import json
import os
import time
import asyncio
import random
import concurrent.futures
import gc
import math
from typing import List, Dict, Any, Tuple
from fastapi import HTTPException

from icecream import ic
import app.state as state
from app.utils import prompt_helpers
from app.config import (
    get_random_llm_client_with_llama_index,
    EVALUATION_BATCH_SIZE,
    MAX_CONCURRENT_EVALUATIONS,
    MAX_CONCURRENT_REFERENCES
)
from app.logs import logger


_evaluation_pool = concurrent.futures.ThreadPoolExecutor(max_workers=10)


class TopicManager:
    """
    Manages random topic selection without replacement.
    Resets the pool when all topics are exhausted.
    Thread-safe for concurrent requests.
    """
    
    def __init__(self, topics: List[str]):
        self.original_topics = topics.copy()
        self.available_topics = topics.copy()
        random.shuffle(self.available_topics)
    
    def get_next_topic(self) -> str:
        """
        Returns a random topic without replacement.
        Resets and reshuffles when pool is exhausted.
        """
        if not self.available_topics:
            self.available_topics = self.original_topics.copy()
            random.shuffle(self.available_topics)
            logger.info(f"[TopicManager] Reset topic pool, reshuffled {len(self.available_topics)} topics")
        
        topic = random.choice(self.available_topics)
        self.available_topics.remove(topic)
        return topic


class PositioningTopicManager:
    """
    Manages topic selection for positioning evaluations with module distribution.
    Ensures all modules participate before reusing topics from the same module.
    Thread-safe for concurrent requests.
    """
    
    def __init__(self, modules_topics: Dict[str, List[str]]):
        """
        Initialize with topics organized by module.
        
        Args:
            modules_topics: Dict with module names as keys and topic lists as values
            Example: {
                "Fundamentals_of_Marketing_Management": ["topic1", "topic2"],
                "Understand_the_Market": ["topic3", "topic4"]
            }
        """
        self.modules_topics = {}
        self.module_managers = {}
        
        for module_name, topics in modules_topics.items():
            if topics:  
                self.modules_topics[module_name] = topics.copy()
                self.module_managers[module_name] = TopicManager(topics)
        
        self.used_modules = set()
        self.available_modules = list(self.module_managers.keys())
        random.shuffle(self.available_modules)
    
    def get_next_topic(self) -> str:
        """
        Returns a topic ensuring module distribution.
        Prioritizes unused modules, then cycles through all modules.
        """
        if not self.module_managers:
            raise ValueError("No modules with topics available")
        
        if self.available_modules:
            module_name = random.choice(self.available_modules)
            self.available_modules.remove(module_name)
            self.used_modules.add(module_name)
        else:
            self.available_modules = list(self.module_managers.keys())
            random.shuffle(self.available_modules)
            module_name = random.choice(self.available_modules)
            self.available_modules.remove(module_name)
            logger.info(f"[PositioningTopicManager] Reset module pool, reshuffled {len(self.available_modules)} modules")
        
        topic_manager = self.module_managers[module_name]
        topic = topic_manager.get_next_topic()
        
        logger.info(f"[PositioningTopicManager] Selected topic '{topic}' from module '{module_name}'")
        return topic


async def fetch_references_for_question(question: str, course_filter: str = None) -> List[str]:
    """
    Fetch raw references for a single question.
    Returns list of "File.pdf:chunk_X" format.
    """
    agent = state.get_cached_agent(course_filter)
    if agent is None:
        raise HTTPException(500, "No agent available for reference fetching")
    
    loop = asyncio.get_running_loop()
    
    def call_agent():
        return agent.query(question)
    
    t0 = time.perf_counter()
    result = await loop.run_in_executor(_evaluation_pool, call_agent)
    t1 = time.perf_counter()
    logger.info(f"[fetch_refs] agent.query for '{question[:30]}…' took {t1-t0:.3f}s")
    
    raw_refs = []
    for ns in result.source_nodes:
        node = ns.node
        m = node.metadata or {}
        fname = m.get("file_name", "").split("/")[-1]
        plabel = m.get("page_label", "")
        if fname and plabel:
            raw_refs.append(f"{fname}:{plabel}")
    
    deduped = list(dict.fromkeys(raw_refs))
    logger.info(f"[fetch_refs] found {len(deduped)} refs")
    return deduped


def format_and_merge_refs(raw_refs: List[str]) -> List[str]:
    """
    Format and merge raw references.
    Input:  ["Chap_1_File.pdf:chunk_3","Chap_1_File.pdf:chunk_4"]
    Output: ["Chap 1 File, Page 3, 4"]
    """
    grouped: Dict[str, List[str]] = {}
    for rr in raw_refs:
        filepart, chunkpart = rr.split(":", 1)
        title = os.path.splitext(filepart)[0].replace("_", " ")
        page = chunkpart.split("_")[-1]
        grouped.setdefault(title, []).append(page)
    
    merged = []
    for title, pages in grouped.items():
        unique = sorted(set(pages), key=int)
        merged.append(f"{title}, Page {', '.join(unique)}")
    
    logger.info(f"[format_refs] merged into {len(merged)} entries")
    return merged


def extract_and_parse_json(raw_response: str, context_info: str = "response") -> Dict[str, Any]:
    """
    Extract JSON from LLM response with fallback and parse it.
    
    Args:
        raw_response: Raw response from LLM
        context_info: Context information for error messages
        
    Returns:
        Parsed JSON as dictionary
        
    Raises:
        HTTPException: If JSON parsing fails
    """
    raw = str(raw_response).strip()
    
    if not raw.startswith("{"):
        start = raw.find("{")
        end = raw.rfind("}")
        if start != -1 and end != -1:
            raw = raw[start:end+1]
            logger.info(f"[parse_llm] fallback JSON slicing applied for {context_info}")
    
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        logger.error(f"JSON parse error for '{context_info}': {e}")
        raise HTTPException(502, f"LLM returned invalid JSON for {context_info}: {e}")

def distribute_question_counts(num_questions: int, weights: List[float]) -> List[int]:
    """
    Convert weights into integer counts of questions, ensuring the total equals `num_questions`.

    This function proportionally allocates question types based on weights and uses
    a rounding correction strategy to guarantee the total number of questions is exact.
    """
    raw_counts = [w * num_questions for w in weights]

    floored = [math.floor(rc) for rc in raw_counts]

    # Step 3: Calculate how many questions remain to be distributed
    remainder = num_questions - sum(floored)

    residuals = [(i, raw_counts[i] - floored[i]) for i in range(len(weights))]
    residuals.sort(key=lambda x: x[1], reverse=True)

    for i in range(remainder):
        floored[residuals[i][0]] += 1

    return floored

def parse_llm_response(raw_response: str, topic: str) -> List[Any]:
    """
    Parse LLM JSON response with fallback extraction.
    Returns the questions list from parsed JSON.
    """
    payload = extract_and_parse_json(raw_response, f"topic '{topic}'")
    
    questions = payload.get("questions")
    if not isinstance(questions, list):
        raise HTTPException(502, f"`questions` missing for '{topic}'")
    
    if questions:
        return questions[:1]
    else:
        return questions


async def generate_single_question(topic: str, eval_type: str, context: str, language: str = "French") -> List[Any]:
    """
    Generate a single question for the given topic and type.
    Returns the parsed questions list.
    """
    llm = get_random_llm_client_with_llama_index(temperature=0.7)
    
    if eval_type == 'mcq':
        gen_prompt = prompt_helpers.mqc_gen_prompt(context, topic, 1, language)
    else:
        gen_prompt = prompt_helpers.open_gen_prompt(context, topic, 1, language)
    
    loop = asyncio.get_running_loop()
    
    def do_generation():
        return llm.complete(prompt=gen_prompt)
    
    t0 = time.perf_counter()
    try:
        llm_result = await loop.run_in_executor(_evaluation_pool, do_generation)
    except Exception as e:
        raise HTTPException(500, f"Generation failed for '{topic}': {e}")
    t1 = time.perf_counter()
    
    logger.info(f"[generate_single] LLM generation for '{topic}' took {t1-t0:.3f}s")
    
    return parse_llm_response(llm_result, topic)


async def get_context_for_topic(topic: str, course_filter: str = None) -> str:
    """
    Get contextual information for a topic using the cached agent.
    """
    agent = state.get_cached_agent(course_filter)
    if agent is None:
        raise HTTPException(500, "No agent available for context retrieval")
    
    loop = asyncio.get_running_loop()
    
    def do_search():
        return agent.query(f"What is {topic}? Provide comprehensive information.")
    
    result = await loop.run_in_executor(_evaluation_pool, do_search)
    return str(result)


async def generate_single_case(topics: List[str], level: str, context: str | None = None, language: str = "French") -> Dict[str, Any]:
    """
    Generate a practical case with pedagogical metadata using selected topics.
    """
    llm = get_random_llm_client_with_llama_index(temperature=0.7)
    prompt = prompt_helpers.practical_case_gen_prompt(
        topics=topics,
        level=level,
        language=language, 
        course_context=context
    )

    loop = asyncio.get_running_loop()

    def do_generation():
        return llm.complete(prompt=prompt)

    try:
        raw_result = await loop.run_in_executor(_evaluation_pool, do_generation)
        print(raw_result)
    except Exception as e:
        raise HTTPException(500, f"[generate_case] LLM generation failed: {e}")
    
    return extract_and_parse_json(str(raw_result), "case generation")


async def generate_questions_batch(
    topics_and_types: List[Tuple[str, str]], 
    semaphore: asyncio.Semaphore,
    language: str = "French",
    course_filter: str = None
) -> List[List[Any]]:
    """
    Generate a batch of questions in parallel with concurrency control.
    Each item in topics_and_types is (topic, eval_type).
    """
    async def generate_with_semaphore(topic: str, eval_type: str):
        async with semaphore:
            context = await get_context_for_topic(topic, course_filter)
            return await generate_single_question(topic, eval_type, context, language)
    
    tasks = [
        generate_with_semaphore(topic, eval_type) 
        for topic, eval_type in topics_and_types
    ]
    
    t0 = time.perf_counter()
    results = await asyncio.gather(*tasks)
    t1 = time.perf_counter()
    
    logger.info(f"[batch] Generated {len(topics_and_types)} questions in {t1-t0:.3f}s")
    return results


async def orchestrate_standard_evaluation(
    topics: List[str], 
    eval_type: str, 
    num_questions: int,
    language: str = "French",
    course_filter: str = None
) -> List[List[Any]]:
    """
    Orchestrate standard evaluation (single type: mcq OR open).
    Returns list of question lists, each with references populated.
    """
    logger.info(f"[orchestrate_standard] Starting {eval_type} evaluation: {num_questions} questions")
    
    topic_manager = TopicManager(topics)
    
    topics_and_types = [
        (topic_manager.get_next_topic(), eval_type) 
        for _ in range(num_questions)
    ]
    
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_EVALUATIONS)
    
    all_question_batches = []
    for i in range(0, len(topics_and_types), EVALUATION_BATCH_SIZE):
        batch = topics_and_types[i:i + EVALUATION_BATCH_SIZE]
        batch_results = await generate_questions_batch(batch, semaphore, language, course_filter)
        all_question_batches.extend(batch_results)
    
    all_questions = []
    for question_batch in all_question_batches:
        all_questions.extend(question_batch)
    
    logger.info(f"[orchestrate_standard] Generated {len(all_questions)} questions total")
    
    if all_questions:
        await populate_references_parallel(all_questions, course_filter)
    
    return all_questions


async def orchestrate_mixed_evaluation_optimized(
    topics: List[str], 
    num_questions: int,
    mcq_weight: float,
    open_weight: float,
    language: str = "French",
    is_positioning: bool = False,
    modules_topics: Dict[str, List[str]] = None,
    course_filter: str = None
) -> List[List[Any]]:
    """
    Parallel batch processing with pipeline references for 40-50% performance improvement.
    """
    logger.info(f"[orchestrate_mixed_optimized] Starting parallel mixed evaluation: {num_questions} questions (positioning: {is_positioning})")
    num_mcq, num_open = distribute_question_counts(num_questions, [mcq_weight, open_weight])
    
    logger.info(f"[orchestrate_mixed_optimized] Distribution: {num_mcq} MCQ, {num_open} Open")
    
    if is_positioning and modules_topics:
        topic_manager = PositioningTopicManager(modules_topics)
        logger.info(f"[orchestrate_mixed_optimized] Using PositioningTopicManager with {len(modules_topics)} modules")
    else:
        topic_manager = TopicManager(topics)
        logger.info(f"[orchestrate_mixed_optimized] Using standard TopicManager with {len(topics)} topics")
    
    topics_and_types = []
    for _ in range(num_mcq):
        topics_and_types.append((topic_manager.get_next_topic(), 'mcq'))
    for _ in range(num_open):
        topics_and_types.append((topic_manager.get_next_topic(), 'open'))
    
    random.shuffle(topics_and_types)
    
    generation_semaphore = asyncio.Semaphore(MAX_CONCURRENT_EVALUATIONS)
    reference_semaphore = asyncio.Semaphore(MAX_CONCURRENT_REFERENCES)
    
    async def process_batch_with_pipeline(batch):
        batch_results = await generate_questions_batch(batch, generation_semaphore, language, course_filter)
        
        batch_questions = []
        for question_list in batch_results:
            batch_questions.extend(question_list)
        
        if batch_questions:
            await populate_references_parallel_memory_safe(batch_questions, reference_semaphore, course_filter)
        
        del batch_results
        gc.collect()
        
        return batch_questions
    
    batch_tasks = []
    for i in range(0, len(topics_and_types), EVALUATION_BATCH_SIZE):
        batch = topics_and_types[i:i + EVALUATION_BATCH_SIZE]
        task = process_batch_with_pipeline(batch)
        batch_tasks.append(task)
    
    t0 = time.perf_counter()
    all_batch_results = await asyncio.gather(*batch_tasks)
    t1 = time.perf_counter()
    
    all_questions = []
    for batch_questions in all_batch_results:
        all_questions.extend(batch_questions)
    
    logger.info(f"[orchestrate_mixed_optimized] Generated {len(all_questions)} questions in {t1-t0:.3f}s")
    
    del all_batch_results, batch_tasks
    gc.collect()
    
    return all_questions


async def populate_references_parallel(questions: List[List[Any]], course_filter: str = None) -> None:
    """
    Populate references for all questions in parallel.
    Modifies questions in-place by updating the last index with formatted references.
    """
    logger.info(f"[populate_refs] Starting reference population for {len(questions)} questions")
    
    question_texts = [q[0] for q in questions]
    
    t0 = time.perf_counter()
    tasks = [fetch_references_for_question(text, course_filter) for text in question_texts]
    raw_refs_list = await asyncio.gather(*tasks)
    t1 = time.perf_counter()
    
    logger.info(f"[populate_refs] Fetched raw refs for {len(question_texts)} questions in {t1-t0:.3f}s")
    
    t2 = time.perf_counter()
    for question, raw_refs in zip(questions, raw_refs_list):
        formatted_refs = format_and_merge_refs(raw_refs)
        question[-1] = formatted_refs
    t3 = time.perf_counter()
    
    logger.info(f"[populate_refs] Formatted all references in {t3-t2:.3f}s")


async def populate_references_parallel_memory_safe(
    questions: List[List[Any]], 
    semaphore: asyncio.Semaphore,
    course_filter: str = None
) -> None:
    """
    Memory-safe version of reference population for low-RAM environments.
    Processes references in small batches with explicit memory cleanup.
    """
    if not questions:
        return
    
    batch_size = min(5, len(questions))
    
    for i in range(0, len(questions), batch_size):
        batch_questions = questions[i:i + batch_size]
        question_texts = [q[0] for q in batch_questions]
        
        async def fetch_with_semaphore(text):
            async with semaphore:
                return await fetch_references_for_question(text, course_filter)
        
        tasks = [fetch_with_semaphore(text) for text in question_texts]
        raw_refs_list = await asyncio.gather(*tasks)
        
        for question, raw_refs in zip(batch_questions, raw_refs_list):
            formatted_refs = format_and_merge_refs(raw_refs)
            question[-1] = formatted_refs
        
        del raw_refs_list, tasks
        gc.collect()


async def evaluate_standard(
    topics: List[str], 
    eval_type: str, 
    num_questions: int,
    language: str = "French",
    course_filter: str = None
) -> Dict[str, Any]:
    """
    Public API for standard evaluation (mcq OR open).
    
    Args:
        topics: List of topics for question generation
        eval_type: Either 'mcq' or 'open'
        num_questions: Total number of questions to generate
        course_filter: Optional course name to filter tools
        
    Returns:
        Dict with 'questions' key containing the generated questions
    """
    agent = await state.get_agent_for_course(course_filter)
    if agent is None:
        raise HTTPException(500, "Agent initialization failed")
    
    questions = await orchestrate_standard_evaluation(topics, eval_type, num_questions, language, course_filter)
    
    return {"questions": questions}


async def evaluate_mixed(
    topics: List[str], 
    num_questions: int,
    mcq_weight: float = 0.5,
    open_weight: float = 0.5,
    language: str = "French",
    is_positioning: bool = False,
    modules_topics: Dict[str, List[str]] = None,
    course_filter: str = None
) -> Dict[str, Any]:
    """
    Public API for parallel mixed evaluation (mcq AND open).
    
    Args:
        topics: List of topics for question generation
        num_questions: Total number of questions to generate
        mcq_weight: Proportion of MCQ questions (0.0 to 1.0)
        open_weight: Proportion of open questions (0.0 to 1.0)
        language: Language for question generation
        is_positioning: Whether this is a positioning evaluation
        modules_topics: Dict of topics by module (for positioning evaluation)
        course_filter: Optional course name to filter tools
        
    Returns:
        Dict with 'questions' key containing the mixed questions
    """
    if not (0 <= mcq_weight <= 1 and 0 <= open_weight <= 1):
        raise HTTPException(400, "Weights must be between 0 and 1")
    
    if abs((mcq_weight + open_weight) - 1.0) > 0.001:
        raise HTTPException(400, "MCQ and Open weights must sum to 1.0")
    
    if is_positioning and not modules_topics:
        raise HTTPException(400, "modules_topics is required for positioning evaluation")

    agent = await state.get_agent_for_course(course_filter)
    if agent is None:
        raise HTTPException(500, "Agent initialization failed")

    questions = await orchestrate_mixed_evaluation_optimized(
        topics, 
        num_questions, 
        mcq_weight, 
        open_weight, 
        language,
        is_positioning,
        modules_topics,
        course_filter
    )
    
    return {"questions": questions}


async def evaluate_case(
    topics: List[str], 
    level: str,
    course_context: str | None = None,
    language: str = "French",
    course_filter: str = None
) -> Dict[str, Any]:
    """
    Generate a single practical case for a list of topics.
    """
    agent = await state.get_agent_for_course(course_filter)
    if agent is None:
        raise HTTPException(500, "Agent initialization failed")

    return await generate_single_case(topics, level, context=course_context, language=language)