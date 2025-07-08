# app/models/evaluation_models.py

from pydantic import BaseModel, Field, field_validator, model_validator
from typing import List, Literal, Optional, Dict, Any


class CaseRequest(BaseModel):
    """Request model for generating educational cases."""
    topics: List[str]
    level: str
    course_context: Optional[str] = None
    language: str = "French"
    course_filter: Optional[str] = Field(default=None, description="Optional course name to filter agent tools")

class CaseResponse(BaseModel):
    """Response model for generated educational cases."""
    case: Dict[str, Any]
    pedagogical_objectives: List[str]
    expected_elements_of_response: List[str]
    evaluation_criteria: List[Dict[str, Any]]

    @model_validator(mode='after')
    def evaluation_criteria_weights_must_sum_to_100(self):
        total_weight = 0
        for criterion in self.evaluation_criteria:
            weight = criterion.get('weight', 0)
            if not isinstance(weight, (int, float)):
                raise ValueError('Each evaluation criterion must have a numeric weight')
            total_weight += weight
        
        if abs(total_weight - 100) > 0.1:
            raise ValueError(f'Evaluation criteria weights must sum to 100, got {total_weight}')
        return self

class EvaluationRequest(BaseModel):
    """Standard evaluation request model for single question type (mcq OR open)."""
    eval_type: Literal['mcq', 'open']
    topics: List[str]
    num_questions: int = Field(default=1, ge=1, description="Number of questions to generate")
    course_filter: Optional[str] = Field(default=None, description="Optional course name to filter agent tools")

    @field_validator('topics')
    @classmethod
    def topics_must_not_be_empty(cls, v):
        if not v:
            raise ValueError('Topics list cannot be empty')
        return v

class MixedEvaluationRequest(BaseModel):
    """Mixed evaluation request model for combining mcq AND open questions."""
    topics: List[str]
    num_questions: int = Field(default=1, ge=1, description="Total number of questions to generate")
    mcq_weight: float = Field(default=0.5, ge=0.0, le=1.0, description="Proportion of MCQ questions (0.0 to 1.0)")
    open_weight: float = Field(default=0.5, ge=0.0, le=1.0, description="Proportion of open questions (0.0 to 1.0)")
    language: str = Field(default="French", description="Language for question generation")
    is_positioning: bool = Field(default=False, description="Whether this is a positioning evaluation")
    modules_topics: Optional[Dict[str, List[str]]] = Field(default=None, description="Topics organized by module for positioning evaluation")
    course_filter: Optional[str] = Field(default=None, description="Optional course name to filter agent tools")

    @field_validator('topics')
    @classmethod
    def topics_must_not_be_empty(cls, v):
        if not v:
            raise ValueError('Topics list cannot be empty')
        return v

    @model_validator(mode='after')
    def weights_must_sum_to_one(self):
        total = self.mcq_weight + self.open_weight
        if abs(total - 1.0) > 0.001:
            raise ValueError('MCQ weight and Open weight must sum to 1.0')
        return self

    @model_validator(mode='after')
    def positioning_validation(self):
        if self.is_positioning and not self.modules_topics:
            raise ValueError('modules_topics is required when is_positioning is True')
        return self

class UserQuery(BaseModel):
    """User query model for chat functionality."""
    session_id: str
    question: str