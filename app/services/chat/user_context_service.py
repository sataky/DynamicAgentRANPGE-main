from typing import Dict, Any, Optional
from app.repositories.user_repository import UserCollection

class UserContextService:
    """Service for enriching chat context with user performance data"""
    
    def __init__(self):
        self.user_collection = UserCollection()
    
    async def get_user_context_for_agent(self, user_id: str) -> str:
        """
        Generate compact user performance context for the agent
        
        Args:
            user_id: User ID
            
        Returns:
            Formatted user context string
        """
        try:
            user_stats = await self.user_collection.get_user_evaluation_stats(user_id)
            if not user_stats:
                return ""
            
            username = user_stats.get('username', 'User')
            avg_score = user_stats.get('average_score', 0)
            total_evals = user_stats.get('total_evaluations', 0)
            
            context = f"[STUDENT_PROFILE: {username} - Overall: {avg_score:.1f}/100 ({total_evals} evaluations)"
            
            course_scores = user_stats.get("course_scores", {})
            evaluations = user_stats.get("evaluations", [])
            
            if course_scores and evaluations:
                module_scores = {}
                for evaluation in evaluations:
                    course = evaluation.get("course")
                    module = evaluation.get("module")
                    score = evaluation.get("score", 0)
                    if course and module:
                        if course not in module_scores:
                            module_scores[course] = {}
                        if module not in module_scores[course]:
                            module_scores[course][module] = []
                        module_scores[course][module].append(score)
                
                for course in module_scores:
                    for module in module_scores[course]:
                        scores = module_scores[course][module]
                        module_scores[course][module] = sum(scores) / len(scores)
                
                courses_data = []
                for course, scores in course_scores.items():
                    avg = scores.get("average_score", 0)
                    count = scores.get("total_evaluations", 0)
                    courses_data.append((course, avg, count))
                
                courses_data.sort(key=lambda x: (x[2], x[1]), reverse=True)
                
                course_details = []
                for course, avg, count in courses_data[:4]:
                    course_detail = f"{course}: {avg:.1f}/100"
                    if course in module_scores:
                        module_list = []
                        for module, module_avg in module_scores[course].items():
                            module_list.append(f"{module}: {module_avg:.1f}/100")
                        if module_list:
                            course_detail += f" ({', '.join(module_list)})"
                    course_details.append(course_detail)
                
                context += f" - {' - '.join(course_details)}]"
            else:
                context += "]"
            
            return context
            
        except Exception as e:
            return "" 