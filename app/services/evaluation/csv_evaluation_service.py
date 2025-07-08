import csv
import json
import os
import random
import math
from typing import List, Dict, Any, Optional
from fastapi import HTTPException

from app.services.external.azure_utils import download_file
from app.services.evaluation.evaluation_service import evaluate_mixed
from app.config import QUESTION_BANK_PATH
from app.logs import logger


class CSVQuestion:
    """Represents a question loaded from CSV with proper typing"""
    
    def __init__(self, row: Dict[str, str]):
        self.id = row['id']
        self.text = row['text']
        self.type = row['type']
        self.options = json.loads(row['options']) if row['options'] else []
        self.correct_answer = row['correct_answer']
        self.feedback = row['feedback']
        self.references = json.loads(row['references']) if row['references'] else []
        self.metadata = json.loads(row['metadata']) if row['metadata'] else {}
    
    def to_evaluation_format(self) -> List[Any]:
        """
        Convert CSV question to the format expected by evaluation system.
        Returns format consistent with agent-generated questions.
        """
        if self.type == "mcq":
            return [
                self.text,
                self.options[0] if len(self.options) > 0 else "",
                self.options[1] if len(self.options) > 1 else "",
                self.options[2] if len(self.options) > 2 else "",
                self.options[3] if len(self.options) > 3 else "",
                self.correct_answer,
                self.feedback,
                self.references
            ]
        else:
            return [
                self.text,
                self.correct_answer,
                self.references
            ]


async def load_questions_from_csv(course: str, module: str, language: str) -> Optional[List[CSVQuestion]]:
    """
    Load questions from CSV file for a specific course/module/language.
    
    Args:
        course: Course name
        module: Module name  
        language: Language (French/English)
        
    Returns:
        List of CSVQuestion objects, or None if CSV not found
    """
    blob_path = f"{QUESTION_BANK_PATH}/{course}/{module}/questions_{language.lower()}.csv"
    logger.info(f"Attempting to load CSV from: {blob_path}")
    
    try:
        local_file_path = await download_file(blob_path)
        if local_file_path is None:
            logger.info(f"CSV not found: {blob_path}")
            return None
            
        questions = []
        with open(local_file_path, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                questions.append(CSVQuestion(row))
        
        os.unlink(local_file_path)
        logger.info(f"Loaded {len(questions)} questions from CSV: {blob_path}")
        return questions
        
    except Exception as e:
        logger.error(f"Error loading CSV {blob_path}: {str(e)}")
        return None

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


def select_random_questions_balanced(
    questions_by_module: Dict[str, List[CSVQuestion]], 
    question_type: str, 
    count: int,
    is_positioning: bool = False
) -> List[CSVQuestion]:
    """
    Select random questions of specified type with optional module balancing.
    
    Args:
        questions_by_module: Questions grouped by module
        question_type: 'mcq' or 'open'
        count: Number of questions to select
        is_positioning: Whether to balance across modules
        
    Returns:
        List of selected questions
    """
    if not is_positioning:
        all_questions = []
        for module_questions in questions_by_module.values():
            all_questions.extend([q for q in module_questions if q.type == question_type])
        
        if len(all_questions) < count:
            logger.warning(f"Requested {count} {question_type} questions, but only {len(all_questions)} available")
            return all_questions
        
        return random.sample(all_questions, count)
    
    selected_questions = []
    modules = list(questions_by_module.keys())
    questions_per_module = max(1, count // len(modules))
    remaining_questions = count % len(modules)
    
    for i, module in enumerate(modules):
        module_questions = [q for q in questions_by_module[module] if q.type == question_type]
        target_count = questions_per_module + (1 if i < remaining_questions else 0)
        
        if module_questions:
            selected_count = min(target_count, len(module_questions))
            selected_questions.extend(random.sample(module_questions, selected_count))
    
    if len(selected_questions) < count:
        remaining_needed = count - len(selected_questions)
        all_remaining = []
        for module_questions in questions_by_module.values():
            all_remaining.extend([q for q in module_questions if q.type == question_type and q not in selected_questions])
        
        if all_remaining:
            additional = random.sample(all_remaining, min(remaining_needed, len(all_remaining)))
            selected_questions.extend(additional)
    
    return selected_questions[:count]


def select_random_questions(questions: List[CSVQuestion], question_type: str, count: int) -> List[CSVQuestion]:
    """
    Select random questions of specified type.
    
    Args:
        questions: Available questions
        question_type: 'mcq' or 'open'
        count: Number of questions to select
        
    Returns:
        List of selected questions
    """
    filtered_questions = [q for q in questions if q.type == question_type]
    if len(filtered_questions) < count:
        logger.warning(f"Requested {count} {question_type} questions, but only {len(filtered_questions)} available")
        return filtered_questions
    
    return random.sample(filtered_questions, count)


async def evaluate_mixed_from_csv(
    modules_topics: Dict[str, List[str]],
    num_questions: int,
    mcq_weight: float = 0.5,
    open_weight: float = 0.5,
    language: str = "French",
    is_positioning: bool = False,
    course_filter: str = None
) -> Dict[str, Any]:
    """
    Evaluate using CSV questions with fallback to agent-based generation.
    
    Args:
        modules_topics: Dict mapping module names to topic lists
        num_questions: Total number of questions to generate
        mcq_weight: Proportion of MCQ questions
        open_weight: Proportion of open questions
        language: Language for questions
        is_positioning: Whether to balance across modules
        course_filter: Course filter for agent fallback
        
    Returns:
        Dict containing questions in evaluation format
    """
    logger.info(f"Starting CSV-based mixed evaluation: {num_questions} questions, language: {language}")
    
    questions_by_module = {}
    missing_modules = []
    course_name = None
    
    for module_name, topics in modules_topics.items():
        if not topics:
            continue
        
        if course_name is None:
            course_name = course_filter or "Marketing Management"
            
        csv_questions = await load_questions_from_csv(course_name, module_name, language)
        
        if csv_questions:
            questions_by_module[module_name] = csv_questions
            if course_name is None and csv_questions:
                course_name = csv_questions[0].metadata.get("course", "Marketing Management")
            logger.info(f"Loaded {len(csv_questions)} questions from module: {module_name}")
        else:
            missing_modules.append(module_name)
            logger.info(f"CSV not available for module: {module_name}")
    
    if not questions_by_module:
        logger.info("No CSV questions available, falling back to agent-based generation")
        topics_list = []
        for topic_list in modules_topics.values():
            topics_list.extend(topic_list)
        
        return await evaluate_mixed(
            topics=topics_list,
            num_questions=num_questions,
            mcq_weight=mcq_weight,
            open_weight=open_weight,
            language=language,
            is_positioning=is_positioning,
            modules_topics=modules_topics,
            course_filter=course_filter
        )
    
    if num_questions == 15:
        mcq_count = 10
        open_count = 5
    elif num_questions == 10:
        mcq_count = 7
        open_count = 3
    elif num_questions == 5:
        mcq_count = 3
        open_count = 2
    else:
        mcq_count, open_count = distribute_question_counts(num_questions, [mcq_weight, open_weight])
    
    selected_mcq = select_random_questions_balanced(
        questions_by_module, "mcq", mcq_count, is_positioning
    )
    selected_open = select_random_questions_balanced(
        questions_by_module, "open", open_count, is_positioning
    )
    
    all_selected = selected_mcq + selected_open
    random.shuffle(all_selected)
    
    final_questions = [q.to_evaluation_format() for q in all_selected]
    
    logger.info(f"CSV evaluation completed: {len(final_questions)} questions ({len(selected_mcq)} MCQ, {len(selected_open)} open)")
    
    return {
        "questions": final_questions,
        "source": "csv",
        "missing_modules": missing_modules
    } 