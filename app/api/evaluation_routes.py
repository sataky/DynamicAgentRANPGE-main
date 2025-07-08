# app/routes/evaluation_routes.py

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any

from dotenv import load_dotenv

from app.models.schemas.evaluation_models import EvaluationRequest, MixedEvaluationRequest, CaseRequest, CaseResponse
from app.models.entities.user import EvaluationSubmissionRequest, CaseEvaluationSubmissionRequest, AddEvaluationScore
from app.services.evaluation.evaluation_service import evaluate_standard, evaluate_mixed, evaluate_case
from app.services.evaluation.csv_evaluation_service import evaluate_mixed_from_csv
from app.services.external.auth_service import auth_service
from app.services.external.grader_service import grader_service
from app.services.evaluation.progression_service import ProgressionService
from app.repositories.user_repository import UserCollection
from app.logs import logger

load_dotenv()

# ─── Dependency injection ─────────────────────────────────
user_collection = UserCollection()
progression_service = ProgressionService()


router = APIRouter(
    prefix="/api/evaluation",
    tags=["evaluation"],
    dependencies=[Depends(auth_service.get_current_user)]
)

# ─── Standard Evaluation endpoint ────────────────────────

@router.post("/mcq-or-open")
async def evaluate(req: EvaluationRequest) -> Dict[str, Any]:
    """
    Standard evaluation endpoint for single question type (mcq OR open).
    Features:
    - Random model selection for each question generation
    - Random topic selection without replacement (with reset when exhausted)
    - Parallel processing with configurable batch size and concurrency limits
    - Automatic reference fetching and formatting
    
    Args:
        req: EvaluationRequest with eval_type, topics, num_questions, course_filter
        
    Returns:
        Dict containing 'questions' key with generated questions and references
    """
    logger.info(f"evaluate ➤ start: {req.eval_type} evaluation, {req.num_questions} questions")
    
    try:
        # Delegate to evaluation service
        result = await evaluate_standard(
            topics=req.topics,
            eval_type=req.eval_type,
            num_questions=req.num_questions,
            course_filter=req.course_filter
        )
        
        logger.info(f"evaluate ➤ success: generated {len(result['questions'])} questions")
        return result
        
    except HTTPException:
        # Re-raise HTTP exceptions (they already have proper status codes)
        raise
    except Exception as e:
        logger.error(f"evaluate ➤ unexpected error: {e}")
        raise HTTPException(500, f"Evaluation failed: {e}")


# ─── Mixed Evaluation endpoint ───────────────────────────

@router.post("/evaluate-mixed")
async def evaluate_mixed_endpoint(req: MixedEvaluationRequest) -> Dict[str, Any]:
    """
    Mixed evaluation endpoint for combining mcq AND open questions.
    Features:
    - Generates both MCQ and open questions based on specified weights
    - Random model selection for each question generation
    - Random topic selection without replacement (shared pool between types)
    - Questions are shuffled to mix MCQ and open types in final result
    - Parallel processing with configurable batch size and concurrency limits
    - Automatic reference fetching and formatting
    - Positioning evaluation support with module distribution
    
    Args:
        req: MixedEvaluationRequest with topics, num_questions, mcq_weight, open_weight, language, is_positioning, modules_topics, course_filter
        
    Returns:
        Dict containing 'questions' key with mixed questions and references
        
    Example:
        POST /evaluate-mixed
        {
            "topics": ["Marketing", "Finance", "Strategy"],
            "num_questions": 10,
            "mcq_weight": 0.7,
            "open_weight": 0.3
        }
        # Will generate 7 MCQ questions and 3 open questions, shuffled together
    """
    logger.info(f"evaluate-mixed ➤ start: {req.num_questions} questions (MCQ: {req.mcq_weight}, Open: {req.open_weight})")
    
    try:
        # Delegate to evaluation service
        result = await evaluate_mixed(
            topics=req.topics,
            num_questions=req.num_questions,
            mcq_weight=req.mcq_weight,
            open_weight=req.open_weight,
            language=req.language,
            is_positioning=req.is_positioning,
            modules_topics=req.modules_topics,
            course_filter=req.course_filter
        )
        
        logger.info(f"evaluate-mixed ➤ success: generated {len(result['questions'])} mixed questions")
        return result
        
    except HTTPException:
        # Re-raise HTTP exceptions (they already have proper status codes)
        raise
    except Exception as e:
        logger.error(f"evaluate-mixed ➤ unexpected error: {e}")
        raise HTTPException(500, f"Mixed evaluation failed: {e}")

# ─── CSV-based Mixed Evaluation endpoint ─────────────────

@router.post("/evaluate-mixed-csv")
async def evaluate_mixed_csv_endpoint(req: MixedEvaluationRequest) -> Dict[str, Any]:
    """
    CSV-based mixed evaluation endpoint with fallback to agent-based generation.
    
    Features:
    - Attempts to load questions from pre-generated CSV files in Azure Blob Storage
    - Falls back to agent-based generation if CSV files are not available
    - Supports both MCQ and open questions with configurable weights
    - Maintains same interface as standard mixed evaluation
    - Faster performance when CSV files are available
    - Automatic module-based distribution for positioning evaluations
    
    Args:
        req: MixedEvaluationRequest with modules_topics, num_questions, mcq_weight, open_weight, language, is_positioning, course_filter
        
    Returns:
        Dict containing 'questions' key with mixed questions and 'source' indicating CSV or agent-based generation
        
    Example:
        POST /evaluate-mixed-csv
        {
            "modules_topics": {
                "Fundamentals_of_Marketing": ["topic1", "topic2"],
                "Understanding_Markets": ["topic3", "topic4"]
            },
            "num_questions": 10,
            "mcq_weight": 0.7,
            "open_weight": 0.3,
            "language": "English"
        }
    """
    logger.info(f"evaluate-mixed-csv ➤ start: {req.num_questions} questions (MCQ: {req.mcq_weight}, Open: {req.open_weight})")
    
    if not req.modules_topics:
        raise HTTPException(400, "modules_topics is required for CSV-based evaluation")
    
    try:
        result = await evaluate_mixed_from_csv(
            modules_topics=req.modules_topics,
            num_questions=req.num_questions,
            mcq_weight=req.mcq_weight,
            open_weight=req.open_weight,
            language=req.language,
            is_positioning=req.is_positioning,
            course_filter=req.course_filter
        )
        
        source = result.get("source", "unknown")
        logger.info(f"evaluate-mixed-csv ➤ success: generated {len(result['questions'])} mixed questions from {source}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"evaluate-mixed-csv ➤ unexpected error: {e}")
        raise HTTPException(500, f"CSV-based mixed evaluation failed: {e}")

@router.post("/evaluate/case", response_model=CaseResponse)
async def generate_practical_case(request: CaseRequest):
    """
    Generate a practical business case based on topics and level.
    """
    result = await evaluate_case(
        topics=request.topics,
        level=request.level,
        course_context=request.course_context,
        language=request.language,
        course_filter=request.course_filter
    )
    return result

# ─── Submit and Save Evaluation endpoints ────────────────
@router.post("/submit-and-save")
async def submit_evaluation_and_save(
    evaluation_data: EvaluationSubmissionRequest,
    user_id: str = Depends(auth_service.get_current_user_id)
) -> Dict[str, Any]:
    """
    Submit evaluation to grader and automatically save the score with activity tracking
    
    Args:
        evaluation_data: Evaluation submission request containing questions, responses, and metadata
        is_final: Whether this is a final validation evaluation
        user_id: Current authenticated user ID
        
    Returns:
        Dict containing grading result, save status, final score, and progression update status
    """
    try:
        logger.info(f"Submit evaluation and save for user: {user_id}, course: {evaluation_data.course}")
        grader_result = await grader_service.grade_evaluation(
            user_id=user_id,
            questions=evaluation_data.questions,
            responses=evaluation_data.responses,
            language=evaluation_data.language
        )
        
        final_score = grader_result.get("final_score")
        score_saved = False
        is_final = evaluation_data.is_final
        if final_score is not None:
            evaluation_type = evaluation_data.evaluation_type
            if is_final and evaluation_data.evaluation_type == "positionnement":
                evaluation_type = "finale"
            
            score_data = AddEvaluationScore(
                score=final_score,
                #topics=evaluation_data.topics,
                topics=[],
                course=evaluation_data.course,
                module=evaluation_data.module,
                evaluation_type=evaluation_type
            )
            
            updated_user = await user_collection.add_evaluation_score(user_id, score_data)
            score_saved = updated_user is not None
            
            if score_saved:
                await user_collection.add_activity_date(user_id)
                logger.info(f"Score saved successfully for user: {user_id}, score: {final_score}")
            else:
                logger.warning(f"Failed to save score for user: {user_id}")
        
        progression_updated = False
        if score_saved and final_score is not None:
            if evaluation_data.evaluation_type == "positionnement" and not is_final:
                try:
                    progression_updated = await progression_service.update_placement_test_result(
                        user_id, evaluation_data.course, final_score
                    )
                    if progression_updated:
                        logger.info(f"Placement test progression updated for user: {user_id}, course: {evaluation_data.course}")
                except Exception as e:
                    logger.warning(f"Failed to update placement test progression for user: {user_id}: {str(e)}")
            
            elif evaluation_data.evaluation_type == "module_mixed":
                try:
                    progression_updated = await progression_service.update_module_progress(
                        user_id, evaluation_data.course, evaluation_data.module, final_score
                    )
                    if progression_updated:
                        logger.info(f"Module progression updated for user: {user_id}, course: {evaluation_data.course}, module: {evaluation_data.module}")
                except Exception as e:
                    logger.warning(f"Failed to update module progression for user: {user_id}: {str(e)}")
        
        return {
            "grading_result": grader_result,
            "score_saved": score_saved,
            "final_score": final_score,
            "user_updated": score_saved,
            "progression_updated": progression_updated
        }
        
    except Exception as e:
        logger.error(f"Error in submit_evaluation_and_save: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Evaluation submission failed: {str(e)}")
        

@router.post("/submit-case-and-save")
async def submit_case_evaluation_and_save(
    evaluation_data: CaseEvaluationSubmissionRequest,
    user_id: str = Depends(auth_service.get_current_user_id)
) -> Dict[str, Any]:
    """
    Submit case evaluation to grader and automatically save the score
    
    Args:
        evaluation_data: Case evaluation submission request
        user_id: Current authenticated user ID
        
    Returns:
        Combined case grading result and save status
    """
    try:
        logger.info(f"Submit case evaluation and save for user: {user_id}, course: {evaluation_data.course}")
        
        grader_result = await grader_service.grade_case_evaluation(
            user_id=user_id,
            case_data=evaluation_data.case_data,
            user_response=evaluation_data.user_response,
            course=evaluation_data.course,
            level=evaluation_data.level,
            topics=evaluation_data.topics,
            language=evaluation_data.language
        )
        
        final_score = grader_result.get("score")
        score_saved = False
        
        if final_score is not None:
            score_data = AddEvaluationScore(
                score=final_score,
                #topics=evaluation_data.topics,
                topics=[],
                course=evaluation_data.course,
                module=evaluation_data.module,
                evaluation_type="module_case"
            )
            
            updated_user = await user_collection.add_evaluation_score(user_id, score_data)
            score_saved = updated_user is not None
            
            if score_saved:
                await user_collection.add_activity_date(user_id)
                logger.info(f"Case score saved successfully for user: {user_id}, score: {final_score}")
            else:
                logger.warning(f"Failed to save case score for user: {user_id}")
        
        return {
            "grading_result": grader_result,
            "score_saved": score_saved,
            "final_score": final_score,
            "user_updated": score_saved
        }
        
    except Exception as e:
        logger.error(f"Error in submit_case_evaluation_and_save: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Case evaluation submission failed: {str(e)}")
        


# ─── Health check endpoint ───────────────────────────────

@router.get("/health")
async def health_check() -> Dict[str, str]:
    """
    Simple health check endpoint to verify service availability.
    """
    return {"status": "healthy", "service": "evaluation_service"}
