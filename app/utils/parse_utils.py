# app/helpers/parse_utils.py

import os
import docx2txt
import whisper
import time
import pymupdf4llm
from llama_index.core import Document
from icecream import ic

# ────────────────────────────────────────────────────────────────
# INTERNAL: parse PDF to Document chunks via PyMuPDF4LLM
# ────────────────────────────────────────────────────────────────


def _pymupdf_pdf_to_docs(pdf_path: str) -> list[Document]:
    """
    Use pymupdf4llm to split the PDF into ~1500-char markdown chunks.
    Returns a list of LlamaIndex Document objects.
    """
    reader = pymupdf4llm.LlamaMarkdownReader()
    t0 = time.time()
    docs = reader.load_data(pdf_path)  # returns List[Document]
    print(f"[parse_utils] Parsed PDF into {len(docs)} chunks in {time.time()-t0:.2f}s")
    return docs

# ────────────────────────────────────────────────────────────────
# INTERNAL: attach uniform metadata to each Document
# ────────────────────────────────────────────────────────────────
def _decorate(docs: list[Document], name: str, date: str) -> list[Document]:
    """
    For each chunk Document, set:
      • file_name   : original filename
      • upload_date : ISO timestamp
      • page_label  : unique chunk index (chunk_1, chunk_2, …)
    """
    out = []
    for idx, doc in enumerate(docs, start=1):
        doc.metadata = {
            "file_name":   name,
            "upload_date": date,
            "page_label":  f"chunk_{idx}"
        }
        out.append(doc)
    return out

# ────────────────────────────────────────────────────────────────
# PUBLIC: choose parser based on file_name extension
# ────────────────────────────────────────────────────────────────
def file_to_documents(file_path: str, file_name: str, upload_date: str) -> list[Document]:
    """
    Parse any supported file to a list of Documents:
      • .pdf   → pymupdf4llm chunks
      • .docx  → docx2txt single chunk
      • .mp3, .wav, .mp4, .m4a → Whisper transcript single chunk

    IMPORTANT: we use the *file_name* to detect extension,
    since temp files may lack suffix.
    """
    # Derive extension from the original filename
    ext = os.path.splitext(file_name)[1].lower()

    if ext == ".pdf":
        docs = _pymupdf_pdf_to_docs(file_path)
        return _decorate(docs, file_name, upload_date)

    if ext == ".docx":
        text = docx2txt.process(file_path)
        return _decorate([Document(text=text)], file_name, upload_date)

    if ext in (".mp3", ".wav", ".mp4", ".m4a"):
        model = whisper.load_model("base")
        result = model.transcribe(file_path)
        text = result.get("text", "")
        return _decorate([Document(text=text)], file_name, upload_date)

    # If we reach here, extension is unsupported
    raise ValueError(f"Unsupported file extension: {ext}")
