from typing import Dict, List, Optional
from datetime import datetime
from app.models.entities.user import (
    CourseProgress, 
    PositionnementTestStatus, 
    ModuleStatus, 
    LearningAnalytics
)
from app.repositories.user_repository import UserCollection
from app.services.database.mongo_utils import get_service
from app import config
from app.logs import logger

class ProgressionService:
    """
    Service to manage course progression system including placement tests and module unlocking
    """
    
    def __init__(self):
        """Initialize progression service with database collections"""
        self.user_collection = UserCollection()
    
    def _extract_module_number(self, module_name: str) -> int:
        """
        Extract module number from module name for fallback ordering
        
        Args:
            module_name (str): Module name like "Module_1:_Title" or "Module_2:_Title"
            
        Returns:
            int: Module number or 999 if not found
        """
        try:
            if "Module_" in module_name:
                start_idx = module_name.find("Module_") + 7
                end_idx = module_name.find(":", start_idx)
                if end_idx == -1:
                    end_idx = module_name.find("_", start_idx)
                if end_idx == -1:
                    end_idx = len(module_name)
                
                number_str = module_name[start_idx:end_idx]
                return int(number_str)
        except (ValueError, IndexError):
            pass
        return 999
    
    async def initialize_user_course_progress(self, user_email: str) -> Dict[str, CourseProgress]:
        """
        Initialize course progression for a user based on available courses in database
        
        Args:
            user_email (str): User email to initialize progression for
            
        Returns:
            Dict[str, CourseProgress]: Initialized course progress data with proper module ordering
        """
        try:
            course_progress = {}
            
            service = await get_service()
            topics_cursor = service.topics.find({})
            topics_docs = await topics_cursor.to_list(length=None)
            
            courses_data = {}
            for doc in topics_docs:
                course_name = doc.get("course", "")
                module_name = doc.get("module", "")
                topics = doc.get("topics", [])
                db_order = doc.get("order", 999)
                
                if course_name and module_name and topics:
                    if course_name not in courses_data:
                        courses_data[course_name] = {}
                    
                    fallback_order = self._extract_module_number(module_name)
                    final_order = db_order if db_order != 999 else fallback_order
                    
                    courses_data[course_name][module_name] = {
                        "topics": topics,
                        "order": final_order
                    }
            
            for course_name, modules_data in courses_data.items():
                modules_status = {}
                module_count = 0
                
                sorted_modules = sorted(modules_data.items(), key=lambda x: x[1]["order"])
                
                for i, (module_name, module_info) in enumerate(sorted_modules):
                    module_count += 1
                    status = "unlocked" if (i == 0 and config.AUTO_UNLOCK_MODULE_1) else "locked"
                    
                    modules_status[module_name] = ModuleStatus(
                        status=status,
                        unlocked_at=datetime.now() if status == "unlocked" else None
                    )
                
                course_progress[course_name] = CourseProgress(
                    positionnement_test=PositionnementTestStatus(),
                    modules_status=modules_status,
                    total_modules=module_count,
                    unlocked_modules=1 if config.AUTO_UNLOCK_MODULE_1 else 0,
                    completed_modules=0,
                    overall_progress=0.0
                )
            
            logger.info(f"Initialized progression for {len(course_progress)} courses for user: {user_email}")
            return course_progress
            
        except Exception as e:
            logger.error(f"Error initializing course progress for {user_email}: {str(e)}")
            return {}
    
    async def _get_module_order_map(self, course_name: str) -> Dict[str, int]:
        """
        Get module order mapping for a specific course with fallback ordering
        
        Args:
            course_name (str): Name of the course
            
        Returns:
            Dict[str, int]: Mapping of module names to their order (1, 2, 3, etc.)
        """
        try:
            service = await get_service()
            cursor = service.topics.find({"course": course_name})
            docs = await cursor.to_list(length=None)
            
            module_order_map = {}
            for doc in docs:
                module_name = doc.get("module", "")
                db_order = doc.get("order", 999)
                
                if module_name:
                    fallback_order = self._extract_module_number(module_name)
                    final_order = db_order if db_order != 999 else fallback_order
                    module_order_map[module_name] = final_order
            
            if not module_order_map:
                return {}
            
            sorted_modules = sorted(module_order_map.items(), key=lambda x: x[1])
            reordered_map = {}
            for i, (module_name, _) in enumerate(sorted_modules):
                reordered_map[module_name] = i + 1
            
            return reordered_map
            
        except Exception as e:
            logger.error(f"Error getting module order map for course {course_name}: {str(e)}")
            return {}
    
    async def update_placement_test_result(self, user_id: str, course_name: str, score: float) -> bool:
        """
        Update positionnement test result and handle module unlocking logic
        
        Args:
            user_id (str): User identifier
            course_name (str): Name of the course
            score (float): Test score achieved
            
        Returns:
            bool: True if update was successful
        """
        try:
            user = await self.user_collection.get_user_by_id(user_id)
            if not user:
                logger.error(f"User not found: {user_id}")
                return False
            
            if not user.course_progress:
                user.course_progress = await self.initialize_user_course_progress(user.email)
            
            if course_name not in user.course_progress:
                logger.error(f"Course not found in user progress: {course_name}")
                return False
            
            course_progress = user.course_progress[course_name]
            course_progress.positionnement_test.status = "passed" if score >= config.PLACEMENT_TEST_PASSING_SCORE else "failed"
            course_progress.positionnement_test.score = score
            course_progress.positionnement_test.date_attempted = datetime.now()
            course_progress.positionnement_test.attempts += 1
            
            if score >= config.PLACEMENT_TEST_PASSING_SCORE and config.PLACEMENT_TEST_UNLOCKS_ALL:
                unlocked_count = 0
                
                for module_name, module_status in course_progress.modules_status.items():
                    if module_status.status == "locked":
                        module_status.status = "unlocked"
                        module_status.unlocked_at = datetime.now()
                    if module_status.status in ["unlocked", "in_progress", "completed"]:
                        unlocked_count += 1
                
                course_progress.unlocked_modules = unlocked_count
            elif not config.AUTO_UNLOCK_MODULE_1:
                module_order_map = await self._get_module_order_map(course_name)
                if module_order_map:
                    first_module_name = min(module_order_map.keys(), key=lambda x: module_order_map[x])
                    
                    if first_module_name in course_progress.modules_status:
                        first_module = course_progress.modules_status[first_module_name]
                        if first_module.status == "locked":
                            first_module.status = "unlocked"
                            first_module.unlocked_at = datetime.now()
                            course_progress.unlocked_modules = 1
            
            if not user.learning_analytics:
                user.learning_analytics = LearningAnalytics()
            
            user.learning_analytics.total_positionnement_tests += 1
            user.learning_analytics.last_activity_date = datetime.now()
            
            from app.services.database.mongo_utils import get_service
            service = await get_service()
            await service.update_user_raw(user_id, {
                "$set": {
                    "course_progress": {k: v.dict() for k, v in user.course_progress.items()},
                    "learning_analytics": user.learning_analytics.dict()
                }
            })
            
            logger.info(f"Updated placement test result for user {user_id}, course {course_name}, score: {score}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating placement test result: {str(e)}")
            return False
    
    async def update_module_progress(self, user_id: str, course_name: str, module_name: str, mixed_score: float) -> bool:
        """
        Update module progression after evaluation completion with fixed ordering logic
        
        Args:
            user_id (str): User identifier
            course_name (str): Name of the course
            module_name (str): Name of the module
            mixed_score (float): Mixed evaluation score achieved
            
        Returns:
            bool: True if update was successful
        """
        try:
            user = await self.user_collection.get_user_by_id(user_id)
            if not user:
                logger.error(f"User not found: {user_id}")
                return False
            
            if not user.course_progress or course_name not in user.course_progress:
                logger.error(f"Course progress not found: {course_name}")
                return False
            
            course_progress = user.course_progress[course_name]
            
            if module_name not in course_progress.modules_status:
                logger.error(f"Module not found: {module_name}")
                return False
            
            module_status = course_progress.modules_status[module_name]
            
            module_status.last_activity = datetime.now()
            module_status.total_attempts += 1
            
            if not module_status.best_mixed_score or mixed_score > module_status.best_mixed_score:
                module_status.best_mixed_score = mixed_score
            
            if mixed_score >= config.MODULE_UNLOCK_THRESHOLD:
                module_status.mixed_evaluation_passed = True
                module_status.status = "completed"
                
                if module_status.status != "completed":
                    course_progress.completed_modules += 1
                
                module_order_map = await self._get_module_order_map(course_name)
                current_order = module_order_map.get(module_name, 999)
                
                next_module_name = None
                next_order = current_order + 1
                
                for mod_name, mod_order in module_order_map.items():
                    if mod_order == next_order:
                        next_module_name = mod_name
                        break
                
                if not next_module_name:
                    module_names = list(course_progress.modules_status.keys())
                    try:
                        current_index = module_names.index(module_name)
                        if current_index < len(module_names) - 1:
                            next_module_name = module_names[current_index + 1]
                    except ValueError:
                        pass
                
                if next_module_name and next_module_name in course_progress.modules_status:
                    next_module = course_progress.modules_status[next_module_name]
                    if next_module.status == "locked":
                        next_module.status = "unlocked"
                        next_module.unlocked_at = datetime.now()
                        course_progress.unlocked_modules += 1
            else:
                module_status.status = "in_progress"
            
            course_progress.overall_progress = (course_progress.completed_modules / course_progress.total_modules) * 100
            
            if not user.learning_analytics:
                user.learning_analytics = LearningAnalytics()
            
            user.learning_analytics.total_evaluations_completed += 1
            user.learning_analytics.last_activity_date = datetime.now()
            
            service = await get_service()
            await service.update_user_raw(user_id, {
                "$set": {
                    "course_progress": {k: v.dict() for k, v in user.course_progress.items()},
                    "learning_analytics": user.learning_analytics.dict()
                }
            })
            
            logger.info(f"Updated module progress for user {user_id}, course {course_name}, module {module_name}, score: {mixed_score}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating module progress: {str(e)}")
            return False
    
    async def get_courses_with_user_progress(self, user_id: str) -> List[Dict]:
        """
        Get all courses from database with user progression status ordered by module order
        
        Args:
            user_id (str): User identifier
            
        Returns:
            List[Dict]: List of courses with progression status and modules in correct order
        """
        try:
            user = await self.user_collection.get_user_by_id(user_id)
            if not user:
                logger.error(f"User not found: {user_id}")
                return []
            
            if not user.course_progress:
                user.course_progress = await self.initialize_user_course_progress(user.email)
                service = await get_service()
                await service.update_user_raw(user_id, {
                    "$set": {
                        "course_progress": {k: v.dict() for k, v in user.course_progress.items()}
                    }
                })
            
            courses_with_progress = []
            
            service = await get_service()
            topics_cursor = service.topics.find({})
            topics_docs = await topics_cursor.to_list(length=None)
            
            courses_data = {}
            for doc in topics_docs:
                course_name = doc.get("course", "")
                module_name = doc.get("module", "")
                topics = doc.get("topics", [])
                db_order = doc.get("order", 999)
                
                if course_name and module_name and topics:
                    if course_name not in courses_data:
                        courses_data[course_name] = {}
                    
                    fallback_order = self._extract_module_number(module_name)
                    final_order = db_order if db_order != 999 else fallback_order
                    
                    courses_data[course_name][module_name] = {
                        "topics": topics,
                        "order": final_order
                    }
            
            for course_name, modules_data in courses_data.items():
                course_progress = user.course_progress.get(course_name)
                if not course_progress:
                    continue
                
                sorted_modules = sorted(modules_data.items(), key=lambda x: x[1]["order"])
                all_topics = []
                for _, module_info in sorted_modules:
                    all_topics.extend(module_info["topics"])
                
                is_active = self._is_course_active(course_progress)
                
                ordered_modules_status = {}
                for module_name, _ in sorted_modules:
                    if module_name in course_progress.modules_status:
                        ordered_modules_status[module_name] = course_progress.modules_status[module_name].dict()
                
                course_data = {
                    "course_name": course_name,
                    "total_modules": len(sorted_modules),
                    "topics": all_topics,
                    "is_active": is_active,
                    "positionnement_test_status": course_progress.positionnement_test.status,
                    "positionnement_test_score": course_progress.positionnement_test.score,
                    "unlocked_modules": course_progress.unlocked_modules,
                    "completed_modules": course_progress.completed_modules,
                    "overall_progress": course_progress.overall_progress,
                    "modules_status": ordered_modules_status
                }
                
                courses_with_progress.append(course_data)
            
            logger.info(f"Retrieved {len(courses_with_progress)} courses with progress for user: {user_id}")
            return courses_with_progress
            
        except Exception as e:
            logger.error(f"Error getting courses with user progress: {str(e)}")
            return []
    
    async def order_user_course_progress(self, user_course_progress: Dict[str, CourseProgress]) -> Dict[str, CourseProgress]:
        """
        Reorder modules in user course progress according to database order field with fallback
        
        Args:
            user_course_progress (Dict[str, CourseProgress]): User course progress data
            
        Returns:
            Dict[str, CourseProgress]: Course progress with modules in correct order
        """
        try:
            ordered_progress = {}
            
            for course_name, course_progress in user_course_progress.items():
                module_order_map = await self._get_module_order_map(course_name)
                
                if not module_order_map:
                    ordered_progress[course_name] = course_progress
                    continue
                
                sorted_module_names = sorted(module_order_map.keys(), key=lambda x: module_order_map[x])
                
                ordered_modules_status = {}
                for module_name in sorted_module_names:
                    if module_name in course_progress.modules_status:
                        ordered_modules_status[module_name] = course_progress.modules_status[module_name]
                
                ordered_course_progress = CourseProgress(
                    positionnement_test=course_progress.positionnement_test,
                    modules_status=ordered_modules_status,
                    total_modules=course_progress.total_modules,
                    unlocked_modules=course_progress.unlocked_modules,
                    completed_modules=course_progress.completed_modules,
                    overall_progress=course_progress.overall_progress
                )
                
                ordered_progress[course_name] = ordered_course_progress
            
            return ordered_progress
            
        except Exception as e:
            logger.error(f"Error ordering course progress: {str(e)}")
            return user_course_progress

    def _is_course_active(self, course_progress: CourseProgress) -> bool:
        """
        Determine if a course should be active based on progression rules
        
        Args:
            course_progress (CourseProgress): Course progression data
            
        Returns:
            bool: True if course should be active/clickable
        """
        positionnement_attempted = course_progress.positionnement_test.status != "not_attempted"
        has_unlocked_modules = course_progress.unlocked_modules > 0
        
        return positionnement_attempted or has_unlocked_modules 