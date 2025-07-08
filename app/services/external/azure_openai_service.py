from typing import Generator, List, Dict, Any, Optional, AsyncGenerator
from fastapi import HTTPException
from functools import lru_cache
from app.config import get_azure_openai_client, AZURE_OPENAI_MODEL_AND_DEPLOYMENT_4omini
from app.utils import prompt_helpers

class AzureOpenAIService:
    """
    Service for interacting with the Azure OpenAI API.
    Manages response generation for conversations.
    """

    def __init__(self):
        """
        Initialize the OpenAI service with Azure parameters.
        """
        
        # Initialize Azure OpenAI client
        self.client = get_azure_openai_client()
        
        # Default system prompt
        self.default_system_prompt = prompt_helpers.system_prompt_for_chat()
    
    async def generate_completion(self, 
                           messages: List[Dict[str, str]], 
                           temperature: float = 0.7, 
                           max_tokens: int = 2000, 
                           stream: bool = False,
                           system_prompt: Optional[str] = None) -> Any:
        """
        Generate a chat completion via the Azure OpenAI API.
        
        Args:
            messages: List of conversation messages
            temperature: Temperature parameter for generation (0.0-1.0)
            max_tokens: Maximum number of tokens to generate
            stream: If True, return a stream of responses instead of a complete response
            system_prompt: Custom system prompt (uses default if None)
            
        Returns:
            A completion object or a completion stream depending on 'stream'
        """
        try:
            # Prepare messages with system prompt
            if not any(m["role"] == "system" for m in messages):
                formatted_messages = [{"role": "system", "content": system_prompt or self.default_system_prompt}]
            else:
                formatted_messages = []
            formatted_messages.extend(messages)

            
            # Call OpenAI API
            response = self.client.chat.completions.create(
                model=AZURE_OPENAI_MODEL_AND_DEPLOYMENT_4omini,
                messages=formatted_messages,
                temperature=temperature,
                max_tokens=max_tokens,
                stream=stream
            )

            return response
            
        except Exception as e:
            # Log the error here
            print(f"Error in Azure OpenAI call: {str(e)}")
            raise HTTPException(status_code=500, detail=f"OpenAI Error: {str(e)}")
    
    def extract_text_from_completion(self, completion) -> str:
        """
        Extract text from a non-streamed completion response.
        
        Args:
            completion: Completion response from OpenAI API
            
        Returns:
            The textual content of the response
        """
        if not completion.choices:
            return ""
        
        return completion.choices[0].message.content
    
    async def stream_chat_completion(self, 
                                    messages: List[Dict[str, str]], 
                                    temperature: float = 0.7,
                                    max_tokens: int = 2000,
                                    system_prompt: Optional[str] = None) -> AsyncGenerator[str, None]:
        """
        Stream a chat completion response asynchronously.
        
        Args:
            messages: List of conversation messages
            temperature: Temperature parameter for generation
            max_tokens: Maximum number of tokens to generate
            system_prompt: Custom system prompt (uses default if None)
            
        Yields:
            Chunks of the generated text
        """
        try:
            response = await self.generate_completion(
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                stream=True,
                system_prompt=system_prompt
            )
            
            for chunk in self._process_stream(response):
                yield chunk
                
        except Exception as e:
            print(f"Error in streaming: {str(e)}")
            yield f"Error: {str(e)}"
    
    def _process_stream(self, stream) -> Generator[str, None, None]:
        """
        Process a streaming response from OpenAI.
        
        Args:
            stream: Streaming response from OpenAI
            
        Yields:
            Text chunks from the stream
        """
        try:
            for chunk in stream:
                if chunk.choices and len(chunk.choices) > 0:
                    delta = chunk.choices[0].delta
                    
                    if hasattr(delta, 'content') and delta.content is not None:
                        yield delta.content
        except Exception as e:
            print(f"Error processing stream: {str(e)}")
            yield f"Error: {str(e)}"
    
    async def generate_text(self, prompt: str, temperature: float = 0.7, max_tokens: int = 2000) -> str:
        """
        Generate text from a prompt directly.
        
        Args:
            prompt: Text prompt
            temperature: Temperature parameter for generation (0.0-1.0)
            max_tokens: Maximum number of tokens to generate
            
        Returns:
            Generated text
        """
        try:
            messages = [{"role": "user", "content": prompt}]
            
            completion = await self.generate_completion(
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                stream=False
            )
            
            result = self.extract_text_from_completion(completion)
            return result
            
        except Exception as e:
            print(f"Error in generate_text: {str(e)}")
            raise ValueError(f"Text generation error: {str(e)}")


@lru_cache()
def get_openai_client():
    """
    Returns a cached instance of the Azure OpenAI client for improved performance.
    
    Returns:
        AzureOpenAI: An instance of the Azure OpenAI client
    """
    client = get_azure_openai_client()
    return client