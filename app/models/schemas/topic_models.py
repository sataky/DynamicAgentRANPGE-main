from pydantic import BaseModel, Field
from typing import List, Optional

class TopicResponse(BaseModel):
    """Response model for module topics."""
    program: str
    level: str
    course: str
    module: str
    module_order: int = Field(..., description="Order of the module within the course (starting from 1)")
    topics: List[str]
    last_updated: Optional[str] = None

class TopicsListResponse(BaseModel):
    """Response model for listing all available topics."""
    total_modules: int
    modules: List[TopicResponse]

class TopicRequest(BaseModel):
    """Request model for topic operations."""
    course: str
    module: str

class AdminUploadRequest(BaseModel):
    """Request model for admin upload with module order."""
    program: str
    level: str
    course: str
    module: str
    module_order: int = Field(..., gt=0, description="Order of the module within the course (must be positive)")

class CourseModuleOrder(BaseModel):
    """Model for course module ordering."""
    course: str
    modules: List[dict] = Field(..., description="List of modules with their order: [{'module': 'name', 'order': 1}]")