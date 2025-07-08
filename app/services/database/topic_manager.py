from typing import List
import json
from app.utils import prompt_helpers
from app.services.database.mongo_utils import upsert_module_topics
from app.logs import logger
from app.config import get_azure_openai_client, AZURE_OPENAI_MODEL_AND_DEPLOYMENT_4omini


def extract_topics(summary: str) -> List[str]:
    """
    Extracts the most relevant topics from a document summary using Azure OpenAI client.
    
    Args:
        summary (str): The summary of the document.
        
    Returns:
        List[str]: A list of the top relevant topics.
    """
    system_message = f"""You are a helpful assistant that extracts key topics. Return ONLY a JSON array like: ["Topic A", "Topic B"]"""
    user_message = prompt_helpers.extract_topics_from_summary(summary)
    client = get_azure_openai_client()
    response = client.chat.completions.create(
        model=AZURE_OPENAI_MODEL_AND_DEPLOYMENT_4omini,
        messages=[
            {"role": "system", "content": system_message},
            {"role": "user", "content": user_message}
        ],
        temperature=0.2,
        max_tokens=150
    )
    
    raw_content = response.choices[0].message.content.strip()
    try:
        topics = json.loads(raw_content)
        if isinstance(topics, list):
            return [topic for topic in topics if isinstance(topic, str) and topic.strip()]
        else:
            logger.warning(f"Expected list but got {type(topics)}: {topics}")
            return []
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {e}. Raw content: {raw_content}")
        return []



async def background_topic_registration(program, level, course, module, summary, module_order=None):
    """
    Asynchronously extracts topics from a summary and stores them in the 'topics' MongoDB collection.

    This function runs in the background without blocking the main execution flow.
    It ensures new topics are incrementally added without duplication and logs the result or any errors.

    Args:
        program (str): The program name (e.g., 'MM').
        level (str): The academic level (e.g., 'M1').
        course (str): The name of the course.
        module (str): The name of the module.
        summary (str): The document summary from which topics are extracted.
        module_order (int, optional): The order of the module within the course.
    """
    try:
        topics = extract_topics(summary)
        await upsert_module_topics(program, level, course, module, topics, module_order)
        logger.info(f"✅ Topics for module '{module}' updated successfully with order {module_order}")
    except Exception as e:
        logger.error(f"❌ Failed to extract or update topics for module '{module}': {e}")