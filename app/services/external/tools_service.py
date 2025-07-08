"""
app/services/external/tools_service.py
──────────────────────────────────────────────
Adapter so that the rest of the code still calls:
  • store_tool(payload)
  • load_tools_from_json_server()
but under the hood we use MongoDB via mongo_utils.py
and Azure Blob for index retrieval if needed.
"""
import os, zipfile, tempfile, asyncio
from typing import List
from app.config import init_llama_index_settings
from llama_index.core.tools import QueryEngineTool, ToolMetadata
from llama_index.core import StorageContext, load_index_from_storage
from app.services.database.mongo_utils import store_tool_doc
from app.services.external.azure_utils import _blob_service, _container_client
from icecream import ic
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Base directory for storing indexes (use local app/ instead of Azure restricted root)
BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data")

# admin_upload → call this to persist metadata
async def store_tool(payload: dict) -> None:
    await store_tool_doc(payload)

# state.reload_agent_from_json → calls this to rebuild tools[]
async def load_tools_from_json_server(course_filter: str = None) -> List[QueryEngineTool]:
    """
    1) Fetch all records from Mongo (or filtered by course)
    2) For each, ensure index exists locally (or download+unzip from Azure)
    3) load index + wrap as QueryEngineTool
    """
    init_llama_index_settings()
    if course_filter:
        from app.services.database.mongo_utils import fetch_tools_by_course
        records = await fetch_tools_by_course(course_filter)
        logger.info(f"Loading tools for course: {course_filter} - Found {len(records)} tools")
    else:
        from app.services.database.mongo_utils import fetch_all_tools
        records = await fetch_all_tools()
        logger.info(f"Loading all tools - Found {len(records)} tools")
    
    ic(records)
    result: List[QueryEngineTool] = []

    for rec in records:
        try:
            # Hierarchical local path
            base = os.path.splitext(rec["file_name"])[0]
            idx_dir = os.path.normpath(os.path.join(
                BASE_DIR,
                rec["program"],
                rec["level"],
                rec["course"],
                rec["module"],
                f"dynamic_index_{base}"
            ))


            # if missing, download & unzip from Azure
            if not os.path.isdir(idx_dir):
                zip_url = rec.get("index_s3_url") or rec.get("index_azure_url")
                if zip_url:
                    try:
                        # Create necessary directories
                        os.makedirs(idx_dir, exist_ok=True)
                        
                        logger.info(f"Processing index URL: {zip_url}")
                        
                        # Extract the path correctly, handling double slashes
                        account_name = _blob_service.account_name
                        container_name = _container_client.container_name
                        
                        # Fix double slash issue
                        blob_path = zip_url.replace(f"https://{account_name}.blob.core.windows.net//{container_name}/", "")
                        # Also handle normal case
                        if blob_path == zip_url:
                            blob_path = zip_url.replace(f"https://{account_name}.blob.core.windows.net/{container_name}/", "")
                        
                        logger.info(f"Constructed blob path: {blob_path}")
                        
                        # Use the Azure SDK client directly
                        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip").name
                        
                        loop = asyncio.get_event_loop()
                        
                        # Define the download function
                        def _download_blob():
                            # Get a blob client
                            blob_client = _container_client.get_blob_client(blob_path)
                            
                            # Download to a temporary file
                            with open(tmp, "wb") as file:
                                download_stream = blob_client.download_blob()
                                file.write(download_stream.readall())
                        
                        # Run the download in the thread pool
                        try:
                            await loop.run_in_executor(None, _download_blob)
                            logger.info(f"Download completed for {blob_path}")
                            
                            # Unzip the file
                            with zipfile.ZipFile(tmp, "r") as zf:
                                zf.extractall(idx_dir)
                            logger.info(f"✅ Extracted index to: {idx_dir}")
                            
                            # Clean up
                            os.remove(tmp)
                        except Exception as download_error:
                            logger.error(f"Failed to download or extract blob: {str(download_error)}")
                            continue
                            
                    except Exception as e:
                        logger.error(f"Error preparing blob download: {str(e)}")
                        continue
                else:
                    logger.warning(f"No index URL found for {rec['tool_name']}")
                    continue  # skip this tool if no index URL

            # Check if directory exists before loading
            if not os.path.isdir(idx_dir):
                logger.warning(f"Index directory does not exist: {idx_dir}")
                continue
                
            # load the LlamaIndex vector store
            try:
                ctx = StorageContext.from_defaults(persist_dir=idx_dir)
                index = load_index_from_storage(ctx)
                if not index:
                    logger.warning(f"Failed to load index from {idx_dir}")
                    continue

                # wrap as a tool
                result.append(
                    QueryEngineTool(
                        query_engine=index.as_query_engine(),
                        metadata=ToolMetadata(
                            name=rec["tool_name"],
                            description=rec["summary"]
                        )
                    )
                )
                logger.info(f"Successfully loaded tool: {rec['tool_name']}")
            except Exception as index_error:
                logger.error(f"Error loading index for {rec['tool_name']}: {str(index_error)}")
                continue
                
        except Exception as record_error:
            logger.error(f"Error processing record {rec.get('tool_name', 'unknown')}: {str(record_error)}")
            continue

    logger.info(f"Loaded {len(result)} tools successfully")
    return result