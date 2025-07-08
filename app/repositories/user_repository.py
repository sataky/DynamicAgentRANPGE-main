from datetime import datetime
import logging
from typing import Optional, Dict, Any, Union

from app.models.entities.user import UserModel, UserCreate, UserUpdate, UserResponse, AddEvaluationScore, EvaluationScore
from app.services.database.mongo_utils import get_service
from app.services.external.auth_service import get_auth_service

logger = logging.getLogger(__name__)

class UserCollectionError(Exception):
    """Custom exception for user collection errors"""
    pass

class UserCollection:
    """User collection manager using unified MongoDB service"""
    
    def __init__(self):
        """Initialize user collection"""
        logger.debug("UserCollection initialized")
    
    def _prepare_user_response(self, user: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare user data for UserResponse by adding computed fields
        
        Args:
            user: Raw user data from database
            
        Returns:
            User data with computed fields
        """
        if user:
            user["id"] = str(user["_id"])
            user["total_evaluations"] = len(user.get("evaluations", []))
            if "average_score" not in user:
                user["average_score"] = 0.0
            if "evaluations" not in user:
                user["evaluations"] = []
            if "course_scores" not in user:
                user["course_scores"] = {}
        return user
    
    async def create_user(self, user: UserCreate, program: str = "MM", level: str = "M1") -> str:
        """
        Create new user in database with progression initialization
        
        Args:
            user: Pydantic user creation model
            program: Program name for progression initialization
            level: Level name for progression initialization
            
        Returns:
            Created user ID
            
        Raises:
            UserCollectionError: On creation error
        """
        try:
            service = await get_service()
            existing_user = await service.find_user_by_email(user.email)
            if existing_user:
                logger.warning(f"Attempt to create user with existing email: {user.email}")
                raise UserCollectionError(f"User with email {user.email} already exists")
            
            auth_service = get_auth_service()
            course_progress = await auth_service.initialize_user_progression("temp_id", program, level)
            
            user_model = UserModel(
                username=user.username,
                email=user.email,
                created_at=datetime.now(),
                course_scores={},
                average_score=0.0,
                evaluations=[],
                course_progress=course_progress or {}
            )
            
            user_data = user_model.dict(exclude={"id"})
            user_id = await service.create_user(user_data)
            
            logger.info(f"User created with ID: {user_id} and progression initialized")
            return user_id
            
        except UserCollectionError:
            raise
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            raise UserCollectionError(f"Error creating user: {str(e)}")
    
    async def get_user_by_email(self, email: str) -> Optional[UserResponse]:
        """
        Get user by email
        
        Args:
            email: User email
            
        Returns:
            User response model or None
            
        Raises:
            UserCollectionError: On retrieval error
        """
        try:
            service = await get_service()
            user = await service.find_user_by_email(email)
            if user:
                user = self._prepare_user_response(user)
                logger.debug(f"User retrieved by email: {email}")
                return UserResponse(**user)
                
            logger.debug(f"User not found for email: {email}")
            return None
            
        except Exception as e:
            logger.error(f"Error retrieving user by email: {str(e)}")
            raise UserCollectionError(f"Error retrieving user by email: {str(e)}")
    
    async def get_user_by_id(self, user_id: str) -> Optional[UserResponse]:
        """
        Get user by ID
        
        Args:
            user_id: User ID
            
        Returns:
            User response model or None
        """
        try:
            service = await get_service()
            user = await service.get_user_by_id(user_id)
            if user:
                user = self._prepare_user_response(user)
                logger.debug(f"User retrieved: {user_id}")
                return UserResponse(**user)
                    
            logger.debug(f"User not found: {user_id}")
            return None
                
        except Exception as e:
            logger.error(f"Error retrieving user: {str(e)}")
            return None
    
    async def update_user(self, user_id: str, update_data: Union[UserUpdate, Dict[str, Any]]) -> Optional[UserResponse]:
        """
        Update user information
        
        Args:
            user_id: User ID
            update_data: Pydantic update model or dictionary
            
        Returns:
            Updated user response model or None
        """
        try:
            service = await get_service()
            if isinstance(update_data, UserUpdate):
                update_dict = update_data.dict(exclude_unset=True, exclude_none=True)
            else:
                update_dict = {k: v for k, v in update_data.items() if v is not None}
            
            if not update_dict:
                logger.debug(f"No data to update for user: {user_id}")
                return await self.get_user_by_id(user_id)
            
            if "email" in update_dict:
                existing_user = await service.find_user_by_email(update_dict["email"])
                if existing_user and str(existing_user["_id"]) != user_id:
                    logger.warning(f"Attempt to update with existing email: {update_dict['email']}")
                    raise UserCollectionError(f"Email {update_dict['email']} is already used by another user")
            
            updated_user = await service.update_user_raw(user_id, update_dict)
            if updated_user:
                updated_user = self._prepare_user_response(updated_user)
                logger.info(f"User updated: {user_id}")
                return UserResponse(**updated_user)
                
            logger.warning(f"User not found for update: {user_id}")
            return None
            
        except UserCollectionError:
            raise
        except Exception as e:
            logger.error(f"Error updating user: {str(e)}")
            raise UserCollectionError(f"Error updating user: {str(e)}")

    async def delete_user(self, user_id: str) -> bool:
        """
        Delete user from database
        
        Args:
            user_id: User ID
            
        Returns:
            True if deletion successful, False otherwise
            
        Raises:
            UserCollectionError: On deletion error
        """
        try:
            service = await get_service()
            success = await service.delete_user(user_id)
            
            if success:
                logger.info(f"User deleted: {user_id}")
                return True
                
            logger.warning(f"User not found for deletion: {user_id}")
            return False
            
        except Exception as e:
            logger.error(f"Error deleting user: {str(e)}")
            raise UserCollectionError(f"Error deleting user: {str(e)}")
    
    async def update_last_login(self, user_id: str) -> bool:
        """
        Update user last login timestamp
        
        Args:
            user_id: User ID
            
        Returns:
            True if update successful, False otherwise
            
        Raises:
            UserCollectionError: On update error
        """
        try:
            service = await get_service()
            success = await service.update_last_login(user_id)
            
            if success:
                logger.debug(f"Last login updated for user: {user_id}")
                return True
                
            logger.warning(f"User not found for last login update: {user_id}")
            return False
            
        except Exception as e:
            logger.error(f"Error updating last login: {str(e)}")
            raise UserCollectionError(f"Error updating last login: {str(e)}")

    async def add_evaluation_score(self, user_id: str, score_data: AddEvaluationScore) -> Optional[UserResponse]:
        """
        Add evaluation score to user and update course-specific and overall averages
        
        Args:
            user_id: User ID
            score_data: Evaluation score data
            
        Returns:
            Updated user response model or None
            
        Raises:
            UserCollectionError: On evaluation addition error
        """
        try:
            service = await get_service()
            user = await service.get_user_by_id(user_id)
            if not user:
                logger.warning(f"User not found for evaluation: {user_id}")
                return None
            
            new_evaluation = EvaluationScore(
                score=score_data.score,
                topics=score_data.topics,
                course=score_data.course,
                module=score_data.module,
                evaluation_type=score_data.evaluation_type,
                date=datetime.now()
            )
            
            course_scores = user.get("course_scores", {})
            course_name = score_data.course
            
            if course_name in course_scores:
                current_avg = course_scores[course_name]["average_score"]
                current_count = course_scores[course_name]["total_evaluations"]
                new_avg = round((current_avg * current_count + score_data.score) / (current_count + 1), 2)
                course_scores[course_name] = {
                    "average_score": new_avg,
                    "total_evaluations": current_count + 1
                }
            else:
                course_scores[course_name] = {
                    "average_score": round(score_data.score, 2),
                    "total_evaluations": 1
                }
            
            total_weighted_score = 0
            total_evaluations = 0
            for course_data in course_scores.values():
                total_weighted_score += course_data["average_score"] * course_data["total_evaluations"]
                total_evaluations += course_data["total_evaluations"]
            
            global_average = round(total_weighted_score / total_evaluations, 2) if total_evaluations > 0 else 0

            update_data = {
                "$push": {"evaluations": new_evaluation.dict()},
                "$set": {
                    "course_scores": course_scores,
                    "average_score": global_average
                }
            }
            
            updated_user = await service.update_user_raw(user_id, update_data)
            if updated_user:
                updated_user = self._prepare_user_response(updated_user)
                logger.info(f"Evaluation added for user: {user_id}, course: {course_name}, new course avg: {course_scores[course_name]['average_score']}")
                return UserResponse(**updated_user)
                
            logger.warning(f"Failed to update user evaluation: {user_id}")
            return None
            
        except Exception as e:
            logger.error(f"Error adding evaluation score: {str(e)}")
            raise UserCollectionError(f"Error adding evaluation score: {str(e)}")
    
    async def add_activity_date(self, user_id: str) -> bool:
        """
        Add current date to user activity_dates array if not already present.
        Used for tracking actual user activities (chat, evaluations).
        """
        try:
            service = await get_service()
            today_str = datetime.now().strftime("%Y-%m-%d")
            
            result = await service.update_user_raw(user_id, {
                "$addToSet": {
                    "learning_analytics.activity_dates": today_str
                },
                "$set": {
                    "learning_analytics.last_activity_date": datetime.now()
                }
            })
            
            return result is not None
            
        except Exception as e:
            logger.error(f"Error adding activity date for user {user_id}: {str(e)}")
            return False

    async def get_user_evaluation_stats(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get user evaluation statistics
        
        Args:
            user_id: User ID
            
        Returns:
            Dictionary with evaluation stats or None
            
        Raises:
            UserCollectionError: On retrieval error
        """
        try:
            service = await get_service()
            user = await service.get_user_by_id(user_id)
            if not user:
                logger.warning(f"User not found for evaluation stats: {user_id}")
                return None
            
            user = self._prepare_user_response(user)
            evaluations = user.get("evaluations", [])
            average_score = user.get("average_score", 0.0)
            total_evaluations = len(evaluations)
            course_scores = user.get("course_scores", {})
            
            stats = {
                "user_id": user_id,
                "username": user.get("username"),
                "average_score": average_score,
                "total_evaluations": total_evaluations,
                "course_scores": course_scores,
                "evaluations": evaluations
            }
            
            logger.debug(f"Evaluation stats retrieved for user: {user_id}")
            return stats
                
        except Exception as e:
            logger.error(f"Error retrieving evaluation stats: {str(e)}")
            raise UserCollectionError(f"Error retrieving evaluation stats: {str(e)}")

    async def get_user_course_scores(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get user scores by course
        
        Args:
            user_id: User ID
            
        Returns:
            Dictionary with course scores or None
            
        Raises:
            UserCollectionError: On retrieval error
        """
        try:
            service = await get_service()
            user = await service.get_user_by_id(user_id)
            if not user:
                logger.warning(f"User not found for course scores: {user_id}")
                return None
            
            return {
                "user_id": user_id,
                "course_scores": user.get("course_scores", {}),
                "average_score": round(user.get("average_score", 0.0), 2)
            }
                
        except Exception as e:
            logger.error(f"Error retrieving course scores: {str(e)}")
            raise UserCollectionError(f"Error retrieving course scores: {str(e)}")

    async def get_user_score_for_course(self, user_id: str, course_name: str) -> Optional[Dict[str, Any]]:
        """
        Get user score for a specific course
        
        Args:
            user_id: User ID
            course_name: Course name
            
        Returns:
            Dictionary with course score data or None
            
        Raises:
            UserCollectionError: On retrieval error
        """
        try:
            course_scores = await self.get_user_course_scores(user_id)
            if not course_scores:
                return None
                
            course_data = course_scores["course_scores"].get(course_name, {
                "average_score": 0.0,
                "total_evaluations": 0
            })
            
            return {
                "user_id": user_id,
                "course": course_name,
                **course_data
            }
                
        except Exception as e:
            logger.error(f"Error retrieving course score: {str(e)}")
            raise UserCollectionError(f"Error retrieving course score: {str(e)}")