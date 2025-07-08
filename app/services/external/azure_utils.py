"""
app/services/azure_utils.py
──────────────────────────────────────────────
Helpers for uploading files and zipped indexes
to Azure Blob Storage.  Uses a ThreadPool so
async code never blocks on network I/O.
"""

import os, zipfile, tempfile, asyncio, concurrent.futures
from azure.storage.blob import BlobServiceClient, ContentSettings
from azure.core.exceptions import ResourceNotFoundError
from typing import Final, Optional

from app.config import (
    AZURE_STORAGE_CONNECTION_STRING,
    AZURE_CONTAINER_NAME
)
# Read from .env / process env
_CONN_STR: Final[str]    = AZURE_STORAGE_CONNECTION_STRING
_CONTAINER: Final[str]   = AZURE_CONTAINER_NAME

# Singleton BlobServiceClient
_blob_service = BlobServiceClient.from_connection_string(_CONN_STR)
_container_client = _blob_service.get_container_client(_CONTAINER)

# ThreadPool for CPU + network tasks
_pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)

async def download_file(blob_path: str) -> Optional[str]:
    """
    Downloads a file from Azure Blob Storage to a temporary file.
    Returns the local path to the downloaded file, or None if blob doesn't exist.
    
    Args:
        blob_path: Path to the blob in Azure Storage
        
    Returns:
        Local path to downloaded file, or None if not found
    """
    def _download():
        try:
            blob_client = _container_client.get_blob_client(blob_path)
            tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
            
            with open(tmp_file.name, "wb") as download_file:
                download_stream = blob_client.download_blob()
                download_file.write(download_stream.readall())
            
            return tmp_file.name
        except ResourceNotFoundError:
            return None
        except Exception as e:
            raise Exception(f"Failed to download blob {blob_path}: {str(e)}")

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_pool, _download)

async def upload_file(local_path: str, blob_path: str) -> str:
    """
    Uploads a local file to Azure Blob Storage under blob_path.
    Returns the blob URL.
    """
    def _upload():
        with open(local_path, "rb") as data:
            _container_client.upload_blob(
                name=blob_path,
                data=data,
                overwrite=True,
                content_settings=ContentSettings(content_type="application/octet-stream")
            )

    loop = asyncio.get_event_loop()
    await loop.run_in_executor(_pool, _upload)

    # Construct the URL
    account_url = _blob_service.url
    return f"{account_url}/{_CONTAINER}/{blob_path}"

async def upload_index_folder(folder_path: str, blob_prefix: str) -> str:
    """
    Zips the entire index folder, uploads as blob_prefix.zip,
    and returns the blob URL.
    """
    # 1) Create a temporary ZIP
    tmp_zip = tempfile.NamedTemporaryFile(suffix=".zip", delete=False).name

    def _zip():
        with zipfile.ZipFile(tmp_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(folder_path):
                for fname in files:
                    abs_path = os.path.join(root, fname)
                    rel_path = os.path.relpath(abs_path, folder_path)
                    zf.write(abs_path, arcname=rel_path)
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(_pool, _zip)

    # 2) Upload ZIP
    zip_blob = f"{blob_prefix}.zip"
    url = await upload_file(tmp_zip, zip_blob)

    # 3) Clean up
    os.remove(tmp_zip)
    return url
