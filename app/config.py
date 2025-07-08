# app/config.py
import os
from openai import AzureOpenAI as Azure_
from llama_index.llms.azure_openai import AzureOpenAI
from llama_index.embeddings.azure_openai import AzureOpenAIEmbedding
from llama_index.core import Settings
from dotenv import load_dotenv
import random
from functools import lru_cache

load_dotenv()

AZURE_CONTAINER_NAME = os.getenv("AZURE_CONTAINER_NAME")
AZURE_STORAGE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")

# MongoDB configuration
MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB_CHAT")

# Secret Key for token
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_REFRESH_SECRET_KEY = os.getenv("JWT_REFRESH_SECRET_KEY")

# Grader service configuration
GRADER_API_URL = os.getenv("GRADER_API_URL")

# Question Generation Configuration
QUESTION_GENERATION_INTERVAL_DAYS = int(os.getenv("QUESTION_GENERATION_INTERVAL_DAYS", "4"))
QUESTIONS_PER_MODULE = int(os.getenv("QUESTIONS_PER_MODULE", "50"))
QUESTION_BATCH_SIZE = int(os.getenv("QUESTION_BATCH_SIZE", "5"))
QUESTION_GENERATION_MCQ_WEIGHT = float(os.getenv("QUESTION_GENERATION_MCQ_WEIGHT", "0.9"))
QUESTION_GENERATION_OPEN_WEIGHT = float(os.getenv("QUESTION_GENERATION_OPEN_WEIGHT", "0.1"))
QUESTION_BANK_PATH = "question_bank"

# Supported languages for question generation
SUPPORTED_LANGUAGES = ["French", "English"]
DEFAULT_LANGUAGE = "French"

# Azure OpenAI configuration
AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT") 
AZURE_OPENAI_KEY = os.getenv("AZURE_OPENAI_KEY")  
AZURE_OPENAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION")
AZURE_OPENAI_MODEL_AND_DEPLOYMENT_4=os.getenv("AZURE_OPENAI_MODEL_AND_DEPLOYMENT_4", "gpt-4")
AZURE_OPENAI_MODEL_AND_DEPLOYMENT_4o=os.getenv("AZURE_OPENAI_MODEL_AND_DEPLOYMENT_4o", "gpt-4o")
AZURE_OPENAI_MODEL_AND_DEPLOYMENT_4omini=os.getenv("AZURE_OPENAI_MODEL_AND_DEPLOYMENT_4omini", "gpt-4o-mini")

# Azure AD Configuration
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET") 
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
AZURE_REDIRECT_URI = os.getenv("AZURE_REDIRECT_URI")

# Evaluation configuration
EVALUATION_BATCH_SIZE = 15  
MAX_CONCURRENT_EVALUATIONS = 15 
MAX_CONCURRENT_REFERENCES = 15
AVAILABLE_MODELS = [
    AZURE_OPENAI_MODEL_AND_DEPLOYMENT_4,
    AZURE_OPENAI_MODEL_AND_DEPLOYMENT_4o, 
    AZURE_OPENAI_MODEL_AND_DEPLOYMENT_4omini
]  # Available Azure OpenAI models for random selection during evaluation

# Course progression configuration
MODULE_UNLOCK_THRESHOLD = float(os.getenv("MODULE_UNLOCK_THRESHOLD", "57.0"))
PLACEMENT_TEST_PASSING_SCORE = float(os.getenv("PLACEMENT_TEST_PASSING_SCORE", "57.0"))
COURSE_PROGRESSION_ENABLED = os.getenv("COURSE_PROGRESSION_ENABLED", "true").lower() == "true"
AUTO_UNLOCK_MODULE_1 = os.getenv("AUTO_UNLOCK_MODULE_1", "true").lower() == "true"
PLACEMENT_TEST_UNLOCKS_ALL = os.getenv("PLACEMENT_TEST_UNLOCKS_ALL", "true").lower() == "true"

class OpenAIEmbeddingService:
    def __init__(
        self, 
        deployment_name: str = "text-embedding-3-large",
        model_name: str = "text-embedding-3-large",
        api_version: str = "2024-02-15-preview"
        #api_version: str = "2024-12-01-preview"
    ):
        """
        Initializes the Azure OpenAI embedding service and sets it globally in LlamaIndex Settings.
        """
        

        if not AZURE_OPENAI_KEY or not AZURE_OPENAI_ENDPOINT:
            raise ValueError("AZURE_OPENAI_API_KEY_FOR_EMB and AZURE_OPENAI_ENDPOINT_FOR_EMB must be set.")

        embed_model = AzureOpenAIEmbedding(
            model=model_name,
            azure_endpoint=AZURE_OPENAI_ENDPOINT,
            api_key=AZURE_OPENAI_KEY,
            azure_deployment=deployment_name,
            api_version=api_version,
            #num_workers=10,
            #dimensions=1536
        )

        # Set globally so LlamaIndex components use this embedding
        Settings.embed_model = embed_model


def get_random_model() -> str:
    """
    Returns a random model from the available models list.
    Used for random model selection during evaluation.
    """
    return random.choice(AVAILABLE_MODELS)


def get_azure_openai_client_with_llama_index(
    temperature: float = 0.7,
    engine: str = AZURE_OPENAI_MODEL_AND_DEPLOYMENT_4omini,
    model: str = AZURE_OPENAI_MODEL_AND_DEPLOYMENT_4omini,
    **kwargs
) -> AzureOpenAI:    
    """
        Factory function to create an Azure OpenAI client for use with LlamaIndex.

        Args:
            temperature (float): Sampling temperature for the model.
            engine (str): The deployment name to use in Azure OpenAI.
            model (str): The model name to use (usually the same as engine).
            **kwargs: Additional arguments passed to the AzureOpenAI client.

        Returns:
            AzureOpenAI: Configured Azure OpenAI client instance.

        Raises:
            ValueError: If required environment variables are missing.
            RuntimeError: If the client fails to initialize.
    """
    if not AZURE_OPENAI_ENDPOINT or not AZURE_OPENAI_KEY or not AZURE_OPENAI_API_VERSION:
        raise ValueError("Environment variables AZURE_OPENAI_KEY, AZURE_OPENAI_API_VERSION, and AZURE_OPENAI_ENDPOINT must be set.")
    
    try:
        return AzureOpenAI(
            engine=engine,
            model=model,
            temperature=temperature,
            #max_tokens=max_tokens
            azure_endpoint=AZURE_OPENAI_ENDPOINT,
            api_key=AZURE_OPENAI_KEY,
            api_version=AZURE_OPENAI_API_VERSION,
            **kwargs
        )
    except Exception as e:
        raise RuntimeError(f"Failed to initialize Azure OpenAI client: {e}")

@lru_cache()
def init_embedding_once():
    """
    Lazily initialize and cache Azure OpenAI Embedding service.
    Ensures embedding is only set once for all LlamaIndex operations.
    """
    OpenAIEmbeddingService()
    
def get_random_llm_client_with_llama_index(**kwargs) -> AzureOpenAI:
    """
    Creates an Azure OpenAI client with a randomly selected model.
    Also updates LlamaIndex Settings.llm with that client.
    """
    random_model = get_random_model()
    init_embedding_once()
    llm = get_azure_openai_client_with_llama_index(
        engine=random_model,
        model=random_model,
        **kwargs
    )
    
    Settings.llm = llm 
    return llm

def get_default_llm_for_agents(**kwargs) -> AzureOpenAI:
    """
    Returns a randomly selected LLM and sets it in LlamaIndex Settings.
    This should be the default LLM used across agents/tools.
    """
    llm = get_azure_openai_client_with_llama_index(**kwargs)
    Settings.llm = llm
    return llm

def init_llama_index_settings():
    """
    Initialize both embedding and LLM settings for LlamaIndex.
    This ensures all LlamaIndex components use Azure OpenAI.
    """
    # Initialize embeddings
    init_embedding_once()
    
    # Initialize and set LLM
    llm = get_azure_openai_client_with_llama_index()
    Settings.llm = llm
    
    print(f"✅ LlamaIndex Settings initialized - LLM: {type(llm).__name__}")
    return llm

@lru_cache()
def get_azure_openai_client(**kwargs) -> AzureOpenAI:
    """
    Factory function to create Azure OpenAI client.
    Better for testing and dependency injection.
    """
    if not AZURE_OPENAI_ENDPOINT or not AZURE_OPENAI_KEY or not AZURE_OPENAI_API_VERSION:
        raise ValueError("Environment variables AZURE_OPENAI_KEY, AZURE_OPENAI_API_VERSION, and AZURE_OPENAI_ENDPOINT must be set.")
    
    try:
        return Azure_(
            api_key=AZURE_OPENAI_KEY,
            api_version=AZURE_OPENAI_API_VERSION,
            azure_endpoint=AZURE_OPENAI_ENDPOINT,
            **kwargs
        )
    except Exception as e:
        raise RuntimeError(f"Failed to initialize Azure OpenAI client: {e}")
