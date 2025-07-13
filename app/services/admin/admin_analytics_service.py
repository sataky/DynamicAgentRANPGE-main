from datetime import datetime, timedelta
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict, Counter

from app.repositories.admin_repository import AdminCollection
from app.services.database.mongo_utils import get_service
from app.models.schemas.admin_models import (
    UserStatsData, EvaluationStatsData, EvaluationTypeStats,
    CourseStatsData, CourseRankingItem, InsightsData, InsightItem,
    DashboardResponse, DashboardFilters
)

logger = logging.getLogger(__name__)


class AdminAnalyticsError(Exception):
    """
    Custom exception for admin analytics errors.
    """
    pass


class AdminAnalyticsService:
    """
    Service for calculating admin dashboard statistics excluding admin users from student metrics.
    """
    
    def __init__(self):
        """
        Initialize admin analytics service.
        """
        self.admin_collection = AdminCollection()
    
    async def _get_student_users(self, filters: Optional[DashboardFilters] = None) -> List[Dict[str, Any]]:
        """
        Get all users excluding admins.
        
        Args:
            filters: Optional filters for data selection
            
        Returns:
            List of student user data
        """
        try:
            service = await get_service()
            all_users = await service.find_all_users()
            admin_user_ids = await self.admin_collection.get_admin_user_ids()
            
            student_users = [
                user for user in all_users 
                if user.get("id") not in admin_user_ids
            ]
            
            if filters:
                if filters.start_date:
                    start_date = datetime.fromisoformat(filters.start_date.replace('Z', '+00:00')) if isinstance(filters.start_date, str) else filters.start_date
                    student_users = [
                        user for user in student_users
                        if self._get_user_created_date(user) >= start_date
                    ]
                
                if filters.end_date:
                    end_date = datetime.fromisoformat(filters.end_date.replace('Z', '+00:00')) if isinstance(filters.end_date, str) else filters.end_date
                    student_users = [
                        user for user in student_users
                        if self._get_user_created_date(user) <= end_date
                    ]
                
                if filters.user_status == "active":
                    student_users = [
                        user for user in student_users
                        if user.get("learning_analytics", {}).get("activity_dates", [])
                    ]
                elif filters.user_status == "inactive":
                    student_users = [
                        user for user in student_users
                        if not user.get("learning_analytics", {}).get("activity_dates", [])
                    ]
            
            return student_users
            
        except Exception as e:
            logger.error(f"Error getting student users: {str(e)}")
            raise AdminAnalyticsError(f"Error getting student users: {str(e)}")
    
    def _get_user_created_date(self, user: Dict[str, Any]) -> datetime:
        """
        Extract creation date from user data.
        
        Args:
            user: User data dictionary
            
        Returns:
            User creation datetime
        """
        created_at = user.get("created_at")
        if isinstance(created_at, str):
            try:
                return datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            except ValueError:
                logger.warning(f"Invalid date format for user {user.get('id')}: {created_at}")
                return datetime.min
        elif isinstance(created_at, datetime):
            return created_at
        else:
            return datetime.min
    
    async def get_user_stats(self, filters: Optional[DashboardFilters] = None) -> UserStatsData:
        """
        Calculate user statistics excluding admins.
        
        Args:
            filters: Optional filters for data selection
            
        Returns:
            User statistics data
        """
        try:
            student_users = await self._get_student_users(filters)
            
            total_users = len(student_users)
            active_users = len([
                user for user in student_users
                if user.get("learning_analytics", {}).get("activity_dates", [])
            ])
            inactive_users = total_users - active_users
            usage_rate = (active_users / total_users * 100) if total_users > 0 else 0
            
            # Calculate new users in last 7 days
            seven_days_ago = datetime.now() - timedelta(days=7)
            new_users_last_7_days = len([
                user for user in student_users
                if self._get_user_created_date(user) >= seven_days_ago
            ])
            
            # Users with evaluations
            users_with_evaluations = len([
                user for user in student_users
                if user.get("evaluations", [])
            ])
            
            # Average activity days
            total_activity_days = sum([
                len(user.get("learning_analytics", {}).get("activity_dates", []))
                for user in student_users
            ])
            avg_activity_days = (total_activity_days / active_users) if active_users > 0 else 0
            
            return UserStatsData(
                total_users=total_users,
                active_users=active_users,
                inactive_users=inactive_users,
                usage_rate=round(usage_rate, 1),
                new_users_last_7_days=new_users_last_7_days,
                users_with_evaluations=users_with_evaluations,
                avg_activity_days=round(avg_activity_days, 1)
            )
            
        except Exception as e:
            logger.error(f"Error calculating user stats: {str(e)}")
            raise AdminAnalyticsError(f"Error calculating user stats: {str(e)}")
    
    async def get_evaluation_stats(self, filters: Optional[DashboardFilters] = None) -> EvaluationStatsData:
        """
        Calculate evaluation statistics by type.
        
        Args:
            filters: Optional filters for data selection
            
        Returns:
            Evaluation statistics data
        """
        try:
            student_users = await self._get_student_users(filters)
            
            # Collect all evaluations from all users
            all_evaluations = []
            for user in student_users:
                evaluations = user.get("evaluations", [])
                for eval_data in evaluations:
                    eval_data["user_id"] = user.get("id")
                    all_evaluations.append(eval_data)
            
            # Group by evaluation type
            eval_types = {
                "positionnement": [],
                "finale": [],
                "module_mixed": [],
                "module_case": []
            }
            
            for evaluation in all_evaluations:
                eval_type = evaluation.get("evaluation_type", "").lower()
                if eval_type in eval_types:
                    eval_types[eval_type].append(evaluation)
            
            # Calculate stats for each type
            def calculate_type_stats(evaluations: List[Dict]) -> EvaluationTypeStats:
                if not evaluations:
                    return EvaluationTypeStats(
                        total_completed=0,
                        unique_users=0,
                        average_score=0,
                        completion_rate=0,
                        trend="N/A"
                    )
                
                total_completed = len(evaluations)
                unique_users = len(set(eval.get("user_id") for eval in evaluations))
                
                scores = [eval.get("score", 0) for eval in evaluations if eval.get("score") is not None]
                average_score = sum(scores) / len(scores) if scores else 0
                
                completion_rate = (unique_users / len(student_users) * 100) if student_users else 0
                
                trend = "stable" 
                
                return EvaluationTypeStats(
                    total_completed=total_completed,
                    unique_users=unique_users,
                    average_score=round(average_score, 1),
                    completion_rate=round(completion_rate, 1),
                    trend=trend
                )
            
            positionnement_stats = calculate_type_stats(eval_types["positionnement"])
            finale_stats = calculate_type_stats(eval_types["finale"])
            module_mixed_stats = calculate_type_stats(eval_types["module_mixed"])
            module_case_stats = calculate_type_stats(eval_types["module_case"])
            
            total_evaluations = len(all_evaluations)
            all_scores = [eval.get("score", 0) for eval in all_evaluations if eval.get("score") is not None]
            avg_score_overall = sum(all_scores) / len(all_scores) if all_scores else 0
            
            return EvaluationStatsData(
                positionnement=positionnement_stats,
                finale=finale_stats,
                module_mixed=module_mixed_stats,
                module_case=module_case_stats,
                total_evaluations=total_evaluations,
                avg_score_overall=round(avg_score_overall, 1)
            )
            
        except Exception as e:
            logger.error(f"Error calculating evaluation stats: {str(e)}")
            raise AdminAnalyticsError(f"Error calculating evaluation stats: {str(e)}")
    
    async def get_course_stats(self, limit_courses: int = 10, filters: Optional[DashboardFilters] = None) -> CourseStatsData:
        """
        Calculate course statistics and rankings.
        
        Args:
            limit_courses: Maximum number of courses to return in rankings
            filters: Optional filters for data selection
            
        Returns:
            Course statistics data
        """
        try:
            student_users = await self._get_student_users(filters)
            
            # Collect course data from users
            course_data = defaultdict(lambda: {
                "users": set(),
                "evaluations": [],
                "total_progress": 0
            })
            
            for user in student_users:
                # Get user's courses from evaluations or progression
                user_courses = set()
                
                # From evaluations
                for evaluation in user.get("evaluations", []):
                    course = evaluation.get("course")
                    if course:
                        user_courses.add(course)
                        course_data[course]["evaluations"].append(evaluation)
                
                # From progression
                progression = user.get("progression", {})
                for course in progression.keys():
                    user_courses.add(course)
                    # Add progress if available
                    course_progress = progression.get(course, {})
                    if isinstance(course_progress, dict):
                        progress_value = course_progress.get("progress", 0)
                        course_data[course]["total_progress"] += progress_value
                
                # Add user to courses
                for course in user_courses:
                    course_data[course]["users"].add(user.get("id"))
            
            # Calculate course rankings
            course_rankings = []
            for course_name, data in course_data.items():
                total_users = len(data["users"])
                if total_users == 0:
                    continue
                
                avg_progress = data["total_progress"] / total_users if total_users > 0 else 0
                total_evaluations = len(data["evaluations"])
                
                scores = [eval.get("score", 0) for eval in data["evaluations"] if eval.get("score") is not None]
                avg_score = sum(scores) / len(scores) if scores else 0
                
                course_rankings.append(CourseRankingItem(
                    course_name=course_name,
                    total_users=total_users,
                    avg_progress=round(avg_progress, 1),
                    total_evaluations=total_evaluations,
                    avg_score=round(avg_score, 1),
                    popularity_rank=0  # Will be set after sorting
                ))
            
            # Sort by popularity (total users) and assign ranks
            course_rankings.sort(key=lambda x: x.total_users, reverse=True)
            for i, course in enumerate(course_rankings[:limit_courses]):
                course.popularity_rank = i + 1
            
            # Calculate completion rates
            course_completion_rates = {}
            for course_ranking in course_rankings:
                completion_rate = (course_ranking.total_users / len(student_users) * 100) if student_users else 0
                course_completion_rates[course_ranking.course_name] = round(completion_rate, 1)
            
            return CourseStatsData(
                total_courses=len(course_data),
                courses_with_users=len([c for c in course_data.values() if c["users"]]),
                avg_users_per_course=round(sum(len(c["users"]) for c in course_data.values()) / len(course_data), 1) if course_data else 0,
                most_popular_courses=course_rankings[:limit_courses],
                course_completion_rates=course_completion_rates
            )
            
        except Exception as e:
            logger.error(f"Error calculating course stats: {str(e)}")
            raise AdminAnalyticsError(f"Error calculating course stats: {str(e)}")
    
    async def generate_insights(
        self, 
        user_stats: UserStatsData, 
        evaluation_stats: EvaluationStatsData, 
        course_stats: CourseStatsData
    ) -> InsightsData:
        """
        Generate insights and alerts based on statistics.
        
        Args:
            user_stats: User statistics
            evaluation_stats: Evaluation statistics
            course_stats: Course statistics
            
        Returns:
            Insights data with alerts and recommendations
        """
        try:
            insights = []
            critical_alerts = 0
            warnings = 0
            
            # High success rate insight
            if evaluation_stats.finale.average_score > 85:
                insights.append(InsightItem(
                    type="success",
                    title="Forte Adoption",
                    description=f"Excellent taux de réussite de {evaluation_stats.finale.average_score}% aux validations finales",
                    priority="medium",
                    created_at=datetime.now().isoformat()
                ))
            
            # High inactive users warning
            if user_stats.usage_rate < 70:
                insights.append(InsightItem(
                    type="warning",
                    title="À Surveiller",
                    description=f"{user_stats.usage_rate}% de taux d'utilisation - {user_stats.inactive_users} utilisateurs inactifs",
                    priority="high",
                    created_at=datetime.now().isoformat()
                ))
                warnings += 1
            
            # Very low usage critical alert
            if user_stats.usage_rate < 50:
                insights.append(InsightItem(
                    type="alert",
                    title="Alerte Critique",
                    description=f"Taux d'utilisation très bas ({user_stats.usage_rate}%) - Action requise",
                    priority="critical",
                    created_at=datetime.now().isoformat()
                ))
                critical_alerts += 1
            
            # Positive trend in case studies
            if evaluation_stats.module_case.total_completed > 0:
                insights.append(InsightItem(
                    type="info",
                    title="Tendance Positive",
                    description=f"Bon engagement sur les cas pratiques avec {evaluation_stats.module_case.total_completed} complétés",
                    priority="low",
                    created_at=datetime.now().isoformat()
                ))
            
            # Low course adoption
            if course_stats.avg_users_per_course < 10:
                insights.append(InsightItem(
                    type="warning",
                    title="Adoption Cours Faible",
                    description=f"Moyenne de {course_stats.avg_users_per_course} utilisateurs par cours",
                    priority="medium",
                    created_at=datetime.now().isoformat()
                ))
                warnings += 1
            
            return InsightsData(
                total_insights=len(insights),
                critical_alerts=critical_alerts,
                warnings=warnings,
                insights=insights,
                last_updated=datetime.now().isoformat()
            )
            
        except Exception as e:
            logger.error(f"Error generating insights: {str(e)}")
            raise AdminAnalyticsError(f"Error generating insights: {str(e)}")
    
    async def get_dashboard_data(
        self, 
        filters: Optional[DashboardFilters] = None,
        include_insights: bool = True,
        limit_courses: int = 10
    ) -> DashboardResponse:
        """
        Get complete dashboard data.
        
        Args:
            filters: Optional filters for data selection
            include_insights: Whether to include insights generation
            limit_courses: Maximum number of courses in rankings
            
        Returns:
            Complete dashboard response
        """
        try:
            user_stats = await self.get_user_stats(filters)
            evaluation_stats = await self.get_evaluation_stats(filters)
            course_stats = await self.get_course_stats(limit_courses, filters)
            
            insights_data = None
            if include_insights:
                insights_data = await self.generate_insights(user_stats, evaluation_stats, course_stats)
            
            return DashboardResponse(
                user_stats=user_stats,
                evaluation_stats=evaluation_stats,
                course_stats=course_stats,
                insights_data=insights_data,
                timestamp=datetime.now().isoformat(),
                success=True
            )
            
        except Exception as e:
            logger.error(f"Error getting dashboard data: {str(e)}")
            raise AdminAnalyticsError(f"Error getting dashboard data: {str(e)}")


# Global instance
admin_analytics_service = AdminAnalyticsService()
