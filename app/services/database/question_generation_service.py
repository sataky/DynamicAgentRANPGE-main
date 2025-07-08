import os
import csv
import tempfile
import asyncio
import hashlib
import json
from typing import List, Dict, Any, Set, Tuple
from datetime import datetime

from app.services.external.azure_utils import upload_file
from app.services.database.mongo_utils import fetch_all_tools
from app.services.evaluation.evaluation_service import (
    orchestrate_mixed_evaluation_optimized,
    populate_references_parallel_memory_safe
)
from app.config import (
    QUESTIONS_PER_MODULE,
    QUESTION_BATCH_SIZE,
    QUESTION_GENERATION_MCQ_WEIGHT,
    QUESTION_GENERATION_OPEN_WEIGHT,
    QUESTION_BANK_PATH,
    SUPPORTED_LANGUAGES
)
from app.logs import logger


class QuestionGenerationService:
    def __init__(self):
        self.generated_hashes: Dict[str, Set[str]] = {
            "French": set(),
            "English": set()
        }
    
    def _hash_question(self, question: List[Any], language: str) -> str:
        """Hash a question for the specific language to avoid duplicates"""
        text = str(question[0]).strip().lower()
        return hashlib.sha256(f"{language}_{text}".encode()).hexdigest()
    
    def _is_duplicate(self, question: List[Any], language: str) -> bool:
        """Check if question is duplicate for the specific language"""
        question_hash = self._hash_question(question, language)
        if question_hash in self.generated_hashes[language]:
            return True
        self.generated_hashes[language].add(question_hash)
        return False
    
    def _detect_question_type(self, question: List[Any]) -> str:
        if len(question) >= 7:
            return "mcq"
        else:
            return "open"
    
    async def _generate_batch_questions(
        self, 
        topics: List[str], 
        batch_size: int,
        language: str,
        course_filter: str = None
    ) -> List[List[Any]]:
        """Generate a batch of questions in the specified language"""
        questions = await orchestrate_mixed_evaluation_optimized(
            topics=topics,
            num_questions=batch_size,
            mcq_weight=QUESTION_GENERATION_MCQ_WEIGHT,
            open_weight=QUESTION_GENERATION_OPEN_WEIGHT,
            language=language,
            is_positioning=False,
            course_filter=course_filter
        )
        
        semaphore = asyncio.Semaphore(10)
        await populate_references_parallel_memory_safe(questions, semaphore, course_filter)
        
        flat_questions = []
        for q in questions:
            if not self._is_duplicate(q, language):
                flat_questions.append(q)
        
        return flat_questions
    
    async def generate_module_questions(
        self, 
        course: str, 
        module: str, 
        topics: List[str],
        language: str,
        course_filter: str = None
    ) -> List[List[Any]]:
        """Generate questions for a module in the specified language"""
        logger.info(f"Generating {QUESTIONS_PER_MODULE} questions for {course}/{module} in {language}")
        
        all_questions = []
        iterations = 0
        max_iterations = 20
        
        while len(all_questions) < QUESTIONS_PER_MODULE and iterations < max_iterations:
            remaining = QUESTIONS_PER_MODULE - len(all_questions)
            batch_size = min(QUESTION_BATCH_SIZE, remaining)
            
            try:
                batch_questions = await self._generate_batch_questions(
                    topics, batch_size, language, course_filter
                )
                all_questions.extend(batch_questions)
                
                logger.info(f"Generated batch of {len(batch_questions)} questions in {language}. Total: {len(all_questions)}/{QUESTIONS_PER_MODULE}")
                
            except Exception as e:
                logger.error(f"Error generating batch for {course}/{module} in {language}: {str(e)}")
            
            iterations += 1
            await asyncio.sleep(0.9)
        
        return all_questions[:QUESTIONS_PER_MODULE]
    
    async def generate_module_questions_both_languages(
        self, 
        course: str, 
        module: str, 
        topics: List[str],
        course_filter: str = None
    ) -> Tuple[List[List[Any]], List[List[Any]]]:
        """Generate questions for a module in both French and English"""
        logger.info(f"Generating questions for {course}/{module} in both languages")
        
        # Generate questions in parallel for both languages
        french_task = self.generate_module_questions(course, module, topics, "French", course_filter)
        english_task = self.generate_module_questions(course, module, topics, "English", course_filter)
        
        french_questions, english_questions = await asyncio.gather(french_task, english_task)
        
        return french_questions, english_questions
    
    async def save_questions_to_csv(
        self, 
        questions: List[List[Any]], 
        course: str, 
        module: str,
        language: str
    ) -> str:
        """Save questions to CSV file for a specific language"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv', encoding='utf-8') as tmp_file:
            writer = csv.writer(tmp_file, quoting=csv.QUOTE_ALL)
            
            headers = ["id", "text", "type", "options", "correct_answer", "feedback", "references", "metadata"]
            writer.writerow(headers)
            
            for i, question in enumerate(questions):
                question_type = self._detect_question_type(question)
                
                if question_type == "mcq":
                    question_text = question[0]
                    options = json.dumps([question[1], question[2], question[3], question[4]], ensure_ascii=False)
                    correct_answer = question[5]
                    feedback = question[6] if len(question) > 6 else ""
                    references = question[7] if len(question) > 7 else ""
                else:
                    question_text = question[0]
                    options = ""
                    correct_answer = question[1] if len(question) > 1 else ""
                    feedback = ""
                    references = question[2] if len(question) > 2 else ""
                
                if isinstance(references, list):
                    references = json.dumps(references, ensure_ascii=False)
                elif not isinstance(references, str):
                    references = str(references)
                
                metadata = json.dumps({
                    "course": course,
                    "module": module,
                    "language": language,
                    "generated_at": datetime.utcnow().isoformat()
                }, ensure_ascii=False)
                
                writer.writerow([
                    f"{course}_{module}_{language}_{i+1}",
                    question_text,
                    question_type,
                    options,
                    correct_answer,
                    feedback,
                    references,
                    metadata
                ])
        
        # Create language-specific blob path
        blob_path = f"{QUESTION_BANK_PATH}/{course}/{module}/questions_{language.lower()}.csv"
        url = await upload_file(tmp_file.name, blob_path)
        
        os.unlink(tmp_file.name)
        
        logger.info(f"Uploaded questions CSV to {blob_path}")
        return url
    
    async def save_questions_both_languages(
        self,
        french_questions: List[List[Any]],
        english_questions: List[List[Any]],
        course: str,
        module: str
    ) -> Dict[str, str]:
        """Save questions to CSV files for both languages"""
        logger.info(f"Saving questions for {course}/{module} in both languages")
        
        # Save both CSVs in parallel
        french_task = self.save_questions_to_csv(french_questions, course, module, "French")
        english_task = self.save_questions_to_csv(english_questions, course, module, "English")
        
        french_url, english_url = await asyncio.gather(french_task, english_task)
        
        return {
            "French": french_url,
            "English": english_url
        }
    
    async def generate_all_module_questions(self) -> Dict[str, Any]:
        """Generate questions for all modules in both languages"""
        tools = await fetch_all_tools()
        
        results = {
            "total_modules": 0,
            "successful_modules": 0,
            "failed_modules": 0,
            "details": []
        }
        
        module_groups = {}
        for tool in tools:
            course = tool.get("course")
            module = tool.get("module")
            if course and module:
                key = f"{course}_{module}"
                if key not in module_groups:
                    module_groups[key] = {
                        "course": course,
                        "module": module,
                        "tools": []
                    }
                module_groups[key]["tools"].append(tool)
        
        results["total_modules"] = len(module_groups)
        
        for key, group in module_groups.items():
            course = group["course"]
            module = group["module"]
            
            try:
                from app.services.database.mongo_utils import get_module_topics
                topics = await get_module_topics(course, module)
                
                if not topics:
                    logger.warning(f"No topics found for {course}/{module}")
                    results["failed_modules"] += 1
                    results["details"].append({
                        "course": course,
                        "module": module,
                        "status": "failed",
                        "error": "No topics found"
                    })
                    continue
                
                # Generate questions in both languages
                french_questions, english_questions = await self.generate_module_questions_both_languages(
                    course, module, topics, course
                )
                
                # Save CSV files for both languages
                csv_urls = await self.save_questions_both_languages(
                    french_questions, english_questions, course, module
                )
                
                results["successful_modules"] += 1
                results["details"].append({
                    "course": course,
                    "module": module,
                    "status": "success",
                    "questions_french": len(french_questions),
                    "questions_english": len(english_questions),
                    "csv_urls": csv_urls
                })
                
                logger.info(f"Successfully generated questions for {course}/{module}: {len(french_questions)} French, {len(english_questions)} English")
                
            except Exception as e:
                results["failed_modules"] += 1
                results["details"].append({
                    "course": course,
                    "module": module,
                    "status": "failed",
                    "error": str(e)
                })
                logger.error(f"Failed to generate questions for {course}/{module}: {str(e)}")
        
        return results 