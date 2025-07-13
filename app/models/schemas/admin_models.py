from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from enum import Enum

class UserStatus(str, Enum):
    """User status filter options"""
    active = "active"
    inactive = "inactive"
    all = "all"

class TrendDirection(str, Enum):
    """Trend direction options"""
    up = "up"
    down = "down"
    stable = "stable"
    not_applicable = "N/A"

class InsightType(str, Enum):
    """Insight type options"""
    info = "info"
    warning = "warning"
    alert = "alert"
    success = "success"

class InsightPriority(str, Enum):
    """Insight priority levels"""
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class DashboardFilters(BaseModel):
    """Dashboard filters for data selection"""
    start_date: Optional[str] = Field(None, description="Start date filter (ISO format)")
    end_date: Optional[str] = Field(None, description="End date filter (ISO format)")
    course_filter: Optional[str] = Field(None, description="Course name filter")
    program_filter: Optional[str] = Field(None, description="Program filter")
    level_filter: Optional[str] = Field(None, description="Level filter")
    user_status: Optional[UserStatus] = Field(UserStatus.all, description="User status filter")

class UserStatsData(BaseModel):
    """User statistics data"""
    total_users: int = Field(..., description="Total number of users")
    active_users: int = Field(..., description="Number of active users")
    inactive_users: int = Field(..., description="Number of inactive users")
    usage_rate: float = Field(..., description="Usage rate percentage")
    new_users_last_7_days: int = Field(..., description="New users in last 7 days")
    users_with_evaluations: int = Field(..., description="Users with at least one evaluation")
    avg_activity_days: float = Field(..., description="Average activity days per active user")

class EvaluationTypeStats(BaseModel):
    """Statistics for a specific evaluation type"""
    total_completed: int = Field(..., description="Total evaluations completed")
    unique_users: int = Field(..., description="Number of unique users")
    average_score: float = Field(..., description="Average score percentage")
    completion_rate: float = Field(..., description="Completion rate percentage")
    trend: TrendDirection = Field(..., description="Recent trend direction")

class EvaluationStatsData(BaseModel):
    """Evaluation statistics by type"""
    positionnement: EvaluationTypeStats = Field(..., description="Positioning quiz stats")
    finale: EvaluationTypeStats = Field(..., description="Final validation stats")
    module_mixed: EvaluationTypeStats = Field(..., description="Mixed module stats")
    module_case: EvaluationTypeStats = Field(..., description="Case study stats")
    total_evaluations: int = Field(..., description="Total evaluations across all types")
    avg_score_overall: float = Field(..., description="Overall average score")

class CourseRankingItem(BaseModel):
    """Course ranking item"""
    course_name: str = Field(..., description="Course name")
    total_users: int = Field(..., description="Number of enrolled users")
    avg_progress: float = Field(..., description="Average progress percentage")
    total_evaluations: int = Field(..., description="Total evaluations in course")
    avg_score: float = Field(..., description="Average score in course")
    popularity_rank: int = Field(..., description="Popularity ranking")

class CourseStatsData(BaseModel):
    """Course statistics and rankings"""
    total_courses: int = Field(..., description="Total number of courses")
    courses_with_users: int = Field(..., description="Courses with at least one user")
    avg_users_per_course: float = Field(..., description="Average users per course")
    most_popular_courses: List[CourseRankingItem] = Field(default_factory=list, description="Most popular courses")
    course_completion_rates: Dict[str, float] = Field(default_factory=dict, description="Course completion rates")

class InsightItem(BaseModel):
    """Individual insight or alert"""
    type: InsightType = Field(..., description="Insight type")
    title: str = Field(..., max_length=100, description="Insight title")
    description: str = Field(..., max_length=500, description="Insight description")
    priority: InsightPriority = Field(..., description="Priority level")
    created_at: str = Field(..., description="Creation timestamp")

class InsightsData(BaseModel):
    """Insights and alerts data"""
    total_insights: int = Field(..., description="Total number of insights")
    critical_alerts: int = Field(..., description="Number of critical alerts")
    warnings: int = Field(..., description="Number of warnings")
    insights: List[InsightItem] = Field(default_factory=list, description="List of insights")
    last_updated: str = Field(..., description="Last update timestamp")

class AdminDashboardRequest(BaseModel):
    """Request model for admin dashboard data"""
    filters: Optional[DashboardFilters] = Field(None, description="Data filters")
    include_insights: Optional[bool] = Field(True, description="Include insights generation")
    include_trends: Optional[bool] = Field(True, description="Include trend analysis")
    limit_courses: Optional[int] = Field(10, ge=1, le=50, description="Limit for course rankings")

class DashboardResponse(BaseModel):
    """Complete dashboard response"""
    user_stats: UserStatsData = Field(..., description="User statistics")
    evaluation_stats: EvaluationStatsData = Field(..., description="Evaluation statistics")
    course_stats: CourseStatsData = Field(..., description="Course statistics")
    insights_data: Optional[InsightsData] = Field(None, description="Insights and alerts")
    timestamp: str = Field(..., description="Response timestamp")
    success: bool = Field(True, description="Success status")

class GlobalStatsResponse(BaseModel):
    """Global user statistics response"""
    user_stats: UserStatsData = Field(..., description="User statistics")
    timestamp: str = Field(..., description="Response timestamp")
    success: bool = Field(True, description="Success status")

class EvaluationStatsResponse(BaseModel):
    """Evaluation statistics response"""
    evaluation_stats: EvaluationStatsData = Field(..., description="Evaluation statistics")
    timestamp: str = Field(..., description="Response timestamp")
    success: bool = Field(True, description="Success status")

class CourseStatsResponse(BaseModel):
    """Course statistics response"""
    course_stats: CourseStatsData = Field(..., description="Course statistics")
    timestamp: str = Field(..., description="Response timestamp")
    success: bool = Field(True, description="Success status")

class InsightsResponse(BaseModel):
    """Insights response"""
    insights_data: InsightsData = Field(..., description="Insights data")
    timestamp: str = Field(..., description="Response timestamp")
    success: bool = Field(True, description="Success status")

class AdminRegistryItem(BaseModel):
    """Admin registry item"""
    email: str = Field(..., description="Admin email")
    username: Optional[str] = Field(None, description="Admin username")
    role: str = Field(..., description="Admin role")
    added_date: str = Field(..., description="Date added to registry")
    admin_id: str = Field(..., description="Admin ID")

class AdminRegistryResponse(BaseModel):
    """Admin registry response"""
    success: bool = Field(..., description="Success status")
    admin_emails: List[str] = Field(..., description="List of admin emails")
    total_admins: int = Field(..., description="Total number of admins")

class AddAdminRequest(BaseModel):
    """Request to add admin"""
    email: str = Field(..., pattern=r'^[^@]+@skema\.edu$', description="Admin email (must be @skema.edu)")
    username: Optional[str] = Field(None, description="Optional username")
    role: Optional[str] = Field("admin", description="Admin role")

class AddAdminResponse(BaseModel):
    """Response for adding admin"""
    success: bool = Field(..., description="Success status")
    message: str = Field(..., description="Response message")
    admin_id: str = Field(..., description="Created admin ID")

class RemoveAdminResponse(BaseModel):
    """Response for removing admin"""
    success: bool = Field(..., description="Success status")
    message: str = Field(..., description="Response message")

class ErrorResponse(BaseModel):
    """Error response model"""
    success: bool = Field(False, description="Success status")
    error: str = Field(..., description="Error message")
    details: Optional[str] = Field(None, description="Error details")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(), description="Error timestamp")
