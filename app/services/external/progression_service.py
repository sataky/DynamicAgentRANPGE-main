"""
Progression service for managing user course progression with module ordering
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
from app.models.entities.user import CourseProgress, ModuleStatus, PositionnementTestStatus
from app.services.database.mongo_utils import get_course_modules_with_order
from app.config import (
    MODULE_UNLOCK_THRESHOLD, 
    COURSE_PROGRESSION_ENABLED,
    AUTO_UNLOCK_MODULE_1,
    PLACEMENT_TEST_PASSING_SCORE,
    PLACEMENT_TEST_UNLOCKS_ALL
)
from app.logs import logger


class ProgressionService:
    """
    Service for managing user course progression based on module ordering
    """
    
    def __init__(self):
        """Initialize progression service"""
        self.module_unlock_threshold = MODULE_UNLOCK_THRESHOLD
        self.placement_test_passing_score = PLACEMENT_TEST_PASSING_SCORE
        self.course_progression_enabled = COURSE_PROGRESSION_ENABLED
        self.auto_unlock_module_1 = AUTO_UNLOCK_MODULE_1
        self.placement_test_unlocks_all = PLACEMENT_TEST_UNLOCKS_ALL

    async def initialize_user_progression(self, program: str, level: str) -> Dict[str, CourseProgress]:
        """
        Initialize course progression for a user based on current courses in database
        
        Args:
            program: The program name (e.g., 'MM')
            level: The level name (e.g., 'M1')
            
        Returns:
            Dict containing course progression data
        """
        if not self.course_progression_enabled:
            logger.info("Course progression disabled, returning empty progression")
            return {}
            
        try:
            courses_data = await get_course_modules_with_order(program, level)
            
            if not courses_data:
                logger.warning(f"No courses found for program '{program}' level '{level}'")
                return {}
            
            course_progress = {}
            
            for course_name, modules in courses_data.items():
                sorted_modules = sorted(modules, key=lambda x: x.get('module_order', 999))
                
                modules_status = {}
                for i, module_data in enumerate(sorted_modules):
                    module_name = module_data['module']
                    is_first_module = i == 0
                    
                    status = "unlocked" if (self.auto_unlock_module_1 and is_first_module) else "locked"
                    unlocked_at = datetime.now() if status == "unlocked" else None
                    
                    modules_status[module_name] = ModuleStatus(
                        status=status,
                        unlocked_at=unlocked_at,
                        best_mixed_score=None,
                        mixed_evaluation_passed=False,
                        last_activity=None,
                        total_attempts=0
                    )
                
                course_progress[course_name] = CourseProgress(
                    positionnement_test=PositionnementTestStatus(),
                    modules_status=modules_status,
                    total_modules=len(sorted_modules),
                    unlocked_modules=1 if self.auto_unlock_module_1 else 0,
                    completed_modules=0,
                    overall_progress=0.0
                )
            
            logger.info(f"Initialized progression for {len(course_progress)} courses")
            return course_progress
            
        except Exception as e:
            logger.error(f"Error initializing user progression: {str(e)}")
            return {}

    async def update_placement_test_result(self, course_progress: Dict[str, CourseProgress], 
                                         course: str, score: float) -> Dict[str, CourseProgress]:
        """
        Update placement test result and unlock modules if needed
        
        Args:
            course_progress: Current user course progression
            course: Course name
            score: Placement test score
            
        Returns:
            Updated course progression
        """
        if course not in course_progress:
            logger.warning(f"Course '{course}' not found in user progression")
            return course_progress
            
        course_prog = course_progress[course]
        
        course_prog.positionnement_test.status = "completed"
        course_prog.positionnement_test.score = score
        course_prog.positionnement_test.date_attempted = datetime.now()
        course_prog.positionnement_test.attempts += 1
        
        if score >= self.placement_test_passing_score and self.placement_test_unlocks_all:
            unlocked_count = 0
            for module_name, module_status in course_prog.modules_status.items():
                if module_status.status == "locked":
                    module_status.status = "unlocked"
                    module_status.unlocked_at = datetime.now()
                    unlocked_count += 1
            
            course_prog.unlocked_modules = len(course_prog.modules_status)
            logger.info(f"Placement test passed for course '{course}': unlocked {unlocked_count} modules")
        else:
            if not self.auto_unlock_module_1:
                first_module = self._get_first_module(course_prog.modules_status)
                if first_module and course_prog.modules_status[first_module].status == "locked":
                    course_prog.modules_status[first_module].status = "unlocked"
                    course_prog.modules_status[first_module].unlocked_at = datetime.now()
                    course_prog.unlocked_modules += 1
        
        self._update_overall_progress(course_prog)
        course_progress[course] = course_prog
        
        return course_progress

    async def update_module_evaluation_result(self, course_progress: Dict[str, CourseProgress], 
                                            course: str, module: str, score: float) -> Dict[str, CourseProgress]:
        """
        Update module evaluation result and unlock next module if needed
        
        Args:
            course_progress: Current user course progression
            course: Course name
            module: Module name
            score: Module evaluation score
            
        Returns:
            Updated course progression
        """
        if course not in course_progress:
            logger.warning(f"Course '{course}' not found in user progression")
            return course_progress
            
        course_prog = course_progress[course]
        
        if module not in course_prog.modules_status:
            logger.warning(f"Module '{module}' not found in course '{course}' progression")
            return course_progress
            
        module_status = course_prog.modules_status[module]
        
        if module_status.best_mixed_score is None or score > module_status.best_mixed_score:
            module_status.best_mixed_score = score
            
        module_status.total_attempts += 1
        module_status.last_activity = datetime.now()
        
        if score >= self.module_unlock_threshold:
            module_status.mixed_evaluation_passed = True
            next_module = self._get_next_module(course_prog.modules_status, module)
            
            if next_module and course_prog.modules_status[next_module].status == "locked":
                course_prog.modules_status[next_module].status = "unlocked"
                course_prog.modules_status[next_module].unlocked_at = datetime.now()
                course_prog.unlocked_modules += 1
                logger.info(f"Module '{module}' passed: unlocked next module '{next_module}'")
        
        self._update_overall_progress(course_prog)
        course_progress[course] = course_prog
        
        return course_progress

    def _get_first_module(self, modules_status: Dict[str, ModuleStatus]) -> Optional[str]:
        """Get the first module in the course (assuming modules are ordered)"""
        if not modules_status:
            return None
        return next(iter(modules_status.keys()))

    def _get_next_module(self, modules_status: Dict[str, ModuleStatus], current_module: str) -> Optional[str]:
        """Get the next module after the current one"""
        module_names = list(modules_status.keys())
        try:
            current_index = module_names.index(current_module)
            if current_index < len(module_names) - 1:
                return module_names[current_index + 1]
        except ValueError:
            pass
        return None

    def _update_overall_progress(self, course_progress: CourseProgress) -> None:
        """Update overall progress percentage for a course"""
        if course_progress.total_modules == 0:
            course_progress.overall_progress = 0.0
            return
            
        completed_modules = sum(1 for status in course_progress.modules_status.values() 
                              if status.mixed_evaluation_passed)
        course_progress.completed_modules = completed_modules
        course_progress.overall_progress = (completed_modules / course_progress.total_modules) * 100.0

    def get_course_activation_status(self, course_progress: Dict[str, CourseProgress]) -> Dict[str, bool]:
        """
        Get activation status for all courses based on placement test completion
        
        Args:
            course_progress: User course progression data
            
        Returns:
            Dict mapping course names to their activation status
        """
        activation_status = {}
        
        for course_name, course_prog in course_progress.items():
            is_active = course_prog.positionnement_test.status != "not_attempted"
            activation_status[course_name] = is_active
            
        return activation_status 