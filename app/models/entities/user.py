from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Dict
from datetime import datetime
from bson import ObjectId
from pydantic_core import core_schema
from typing import Any
from pydantic import GetCoreSchemaHandler

class PyObjectId(ObjectId):
    """
    Custom ObjectId type for Pydantic models
    """

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        _source_type: Any,
        _handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        return core_schema.no_info_after_validator_function(
            cls.validate,
            core_schema.str_schema()
        )

    @classmethod
    def validate(cls, value: Any) -> ObjectId:
        if not ObjectId.is_valid(value):
            raise ValueError("Invalid ObjectId")
        return ObjectId(value)


class PositionnementTestStatus(BaseModel):
    """
    Model for positionnement test status and results
    """
    status: str = "not_attempted"
    score: Optional[float] = None
    date_attempted: Optional[datetime] = None
    attempts: int = 0

class ModuleStatus(BaseModel):
    """
    Model for individual module status and progression
    """
    status: str = "locked"
    unlocked_at: Optional[datetime] = None
    best_mixed_score: Optional[float] = None
    mixed_evaluation_passed: bool = False
    last_activity: Optional[datetime] = None
    total_attempts: int = 0

class CourseProgress(BaseModel):
    """
    Model for overall course progression including positionnement test and modules
    """
    positionnement_test: PositionnementTestStatus = PositionnementTestStatus()
    modules_status: Dict[str, ModuleStatus] = {}
    total_modules: int = 0
    unlocked_modules: int = 0
    completed_modules: int = 0
    overall_progress: float = 0.0

#class LearningAnalytics(BaseModel):
#    """
#    Model for user learning analytics and statistics
#    """
#    total_positionnement_tests: int = 0
#    total_evaluations_completed: int = 0
#    first_course_started: Optional[datetime] = None
#    last_activity_date: Optional[datetime] = None

class LearningAnalytics(BaseModel):
    """
    Model for user learning analytics and statistics
    """
    total_positionnement_tests: int = 0
    total_evaluations_completed: int = 0
    first_course_started: Optional[datetime] = None
    last_activity_date: Optional[datetime] = None
    activity_dates: List[str] = Field(default_factory=list)

class EvaluationScore(BaseModel):
    """
    Model for individual evaluation score
    """
    score: float
    topics: List[str]
    course: str
    module: str
    evaluation_type: str
    date: datetime = Field(default_factory=datetime.now)

class CourseScore(BaseModel):
    """
    Model for course-specific score data
    """
    average_score: float
    total_evaluations: int

class UserModel(BaseModel):
    """
    Base model for User entity
    """
    id: Optional[PyObjectId] = Field(default_factory=PyObjectId, alias="_id")
    username: str
    email: EmailStr
    created_at: datetime = Field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    course_scores: Dict[str, CourseScore] = {}
    average_score: float = 0.0
    evaluations: List[EvaluationScore] = []
    course_progress: Optional[Dict[str, CourseProgress]] = {}
    learning_analytics: Optional[LearningAnalytics] = LearningAnalytics()

    class Config:
        validate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str,
            datetime: lambda dt: dt.isoformat()
        }

class UserCreate(BaseModel):
    """
    Model for creating a new user
    """
    username: str
    email: EmailStr


class UserUpdate(BaseModel):
    """
    Model for updating user information
    """
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    last_login: Optional[datetime] = None


class AddEvaluationScore(BaseModel):
    """
    Model for adding a new evaluation score
    """
    score: float
    topics: List[str]
    course: str
    module: str
    evaluation_type: str

class UserResponse(BaseModel):
    """
    Model for API response containing user information
    """
    id: str
    username: str
    email: str
    created_at: datetime
    last_login: Optional[datetime] = None
    course_scores: Dict[str, CourseScore] = {}
    average_score: float
    total_evaluations: int
    evaluations: List[EvaluationScore] = []
    course_progress: Optional[Dict[str, CourseProgress]] = {}
    learning_analytics: Optional[LearningAnalytics] = None
    progression_initialized: bool = False

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda dt: dt.isoformat() if dt else None 
        }

class EvaluationSubmissionRequest(BaseModel):
    """
    Model for evaluation submission request
    """
    questions: List[Any]
    responses: List[str]
    topics: List[str]
    course: str
    module: str
    evaluation_type: str
    language: str = Field(default="French", description="Language for evaluation grading")
    is_final: bool = Field(default=False)


class CaseEvaluationSubmissionRequest(BaseModel):
    """
    Model for case evaluation submission request
    """
    case_data: Dict[str, Any]
    user_response: str
    course: str
    level: str
    topics: List[str]
    module: str
    language: str = Field(default="French", description="Language for case evaluation grading")
