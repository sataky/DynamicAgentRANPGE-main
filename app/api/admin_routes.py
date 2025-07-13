"""
app/routes/admin_routes.py
──────────────────────────────────────────────
When an admin uploads a file:
1) Save to a temp file
2) Upload raw file to Azure Blob
3) Parse into Docs, summarise, build local index
4) Zip & upload index to Azure Blob
5) Persist metadata + Azure URLs in Mongo
6) Reload in‑memory agent once
"""

import os, shutil, datetime, tempfile, asyncio
from fastapi import APIRouter, HTTPException, UploadFile, status, File, Depends
from app.services.external.auth_service import auth_service
from app.repositories.admin_repository import AdminCollection
from app.services.admin.admin_analytics_service import admin_analytics_service
from app.models.schemas.admin_models import (
    GlobalStatsResponse, EvaluationStatsResponse, CourseStatsResponse,
    InsightsResponse, AdminDashboardRequest, DashboardResponse
)
from app.utils.parse_utils import file_to_documents
from app.state import clear_course_cache
from app.services.database.indexing_service import summarize_text, get_or_create_index
from app.services.external.azure_utils import upload_file, upload_index_folder
from app.services.external.tools_service import store_tool
from app.services.database.topic_manager import background_topic_registration
from app.services.database.mongo_utils import get_module_topics, get_service, get_course_modules_with_order
from app.models.schemas.topic_models import TopicResponse, TopicsListResponse, TopicRequest
from app.logs import logger


router = APIRouter(
    prefix="/api/admin",
    tags=["admin"]
)


async def verify_admin_access(current_user_id: str = Depends(auth_service.get_current_user)) -> str:
    """
    Verify current user has admin access.
    
    Args:
        current_user_id: Current authenticated user ID
        
    Returns:
        User ID if admin access granted
        
    Raises:
        HTTPException: If user is not admin
    """
    try:
        service = await get_service()
        user = await service.get_user_by_id(current_user_id)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        admin_collection = AdminCollection()
        is_admin = await admin_collection.is_admin(user["email"])
        
        if not is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
        
        return current_user_id
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error verifying admin access: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication verification failed"
        )
    

@router.post("/upload/{program}/{level}/{course}/{module}/{module_order}")
async def admin_upload_file(
    program: str, level: str, course: str, module: str, module_order: int,
    file: UploadFile = File(...)
):
    # 1) write file to a temp path
    fd, tmp_path = tempfile.mkstemp()
    with os.fdopen(fd, "wb") as buf:
        shutil.copyfileobj(file.file, buf)

    # 2) upload raw file to Azure Blob
    blob_key = f"raw/{program}/{level}/{course}/{module}/{file.filename}"
    raw_url  = await upload_file(tmp_path, blob_key)

    # get ISO timestamp
    iso_now = datetime.datetime.utcnow().isoformat()

    # 3) parse → Documents
    docs = file_to_documents(tmp_path, file.filename, iso_now)

    # 4) summarise
    summary = summarize_text("\n\n".join(d.get_content() for d in docs))
    
    # 5) async background task: extract and persist topics in Mongo
    asyncio.create_task(background_topic_registration(
        program=program,
        level=level,
        course=course,
        module=module,
        summary=summary,
        module_order=module_order
    ))

    # 6) build index locally → zip → upload to Azure Blob
    base    = os.path.splitext(file.filename)[0]
    idx_dir = os.path.join("data", program, level, course, module,
                           f"dynamic_index_{base}")
    get_or_create_index(docs, idx_dir)

    idx_url = await upload_index_folder(
        idx_dir,
        f"index/{program}/{level}/{course}/{module}/dynamic_index_{base}"
    )

    # 7) persist metadata in Mongo
    await store_tool({
        "program": program,
        "level":    level,
        "course":   course,
        "module":   module,
        "tool_name":f"DynamicTool_{base}",
        "file_name":file.filename,
        "summary":  summary,
        "date_added": iso_now,
        "raw_azure_url": raw_url,
        "index_azure_url": idx_url
    })

    await clear_course_cache(course)

    return {"msg": "uploaded", "tool": f"DynamicTool_{base}"}



@router.get("/topics/by-program/{program}/{level}", response_model=TopicsListResponse)
async def get_topics_for_program_level(program: str, level: str):
    """Get all courses and their modules/topics for a specific program and level."""
    try:
        service = await get_service()
        cursor = service.topics.find({"program": program, "level": level})
        program_docs = await cursor.to_list(length=None)
        
        if not program_docs:
            raise HTTPException(
                status_code=404, 
                detail=f"No topics found for program '{program}' level '{level}'"
            )
        
        modules = []
        for doc in program_docs:
            modules.append(TopicResponse(
                program=doc.get("program", "unknown"),
                level=doc.get("level", "unknown"),
                course=doc.get("course", "unknown"),
                module=doc.get("module", "unknown"),
                module_order=doc.get("module_order", 999),
                topics=doc.get("topics", []),
                last_updated=doc.get("last_updated")
            ))
        
        return TopicsListResponse(
            total_modules=len(modules),
            modules=modules
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving topics for program '{program}' level '{level}': {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail="An error occurred while retrieving topics"
        )

@router.get("/topics/by-module/{course}/{module}", response_model=TopicResponse)
async def get_topics_for_module(course: str, module: str):
    """Get all topics for a specific module and course."""
    try:
        topics = await get_module_topics(course, module)
        
        if not topics:
            raise HTTPException(
                status_code=404, 
                detail=f"No topics found for module '{module}' in course '{course}'"
            )
        
        # Get additional metadata from the topics collection
        service = await get_service()
        doc = await service.topics.find_one({"course": course, "module": module})
        
        return TopicResponse(
            program=doc.get("program", "unknown") if doc else "unknown",
            level=doc.get("level", "unknown") if doc else "unknown",
            course=course,
            module=module,
            module_order=doc.get("module_order", 999) if doc else 999,
            topics=topics,
            last_updated=doc.get("last_updated") if doc else None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving topics for module '{module}': {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail="An error occurred while retrieving topics"
        )

@router.get("/topics/all", response_model=TopicsListResponse)
async def get_all_topics():
    """Get all topics for all modules."""
    try:
        service = await get_service()
        cursor = service.topics.find({})
        all_docs = await cursor.to_list(length=None)
        
        modules = []
        for doc in all_docs:
            modules.append(TopicResponse(
                program=doc.get("program", "unknown"),
                level=doc.get("level", "unknown"),
                course=doc.get("course", "unknown"),
                module=doc.get("module", "unknown"),
                module_order=doc.get("module_order", 999),
                topics=doc.get("topics", []),
                last_updated=doc.get("last_updated")
            ))
        
        return TopicsListResponse(
            total_modules=len(modules),
            modules=modules
        )
        
    except Exception as e:
        logger.error(f"Error retrieving all topics: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail="An error occurred while retrieving topics"
        )

@router.get("/topics/by-course/{course}", response_model=TopicsListResponse)
async def get_topics_for_course(course: str,):
    """Get all topics for all modules in a specific course."""
    try:
        service = await get_service()
        cursor = service.topics.find({"course": course})
        course_docs = await cursor.to_list(length=None)
        
        if not course_docs:
            raise HTTPException(
                status_code=404, 
                detail=f"No topics found for course '{course}'"
            )
        
        modules = []
        for doc in course_docs:
            modules.append(TopicResponse(
                program=doc.get("program", "unknown"),
                level=doc.get("level", "unknown"),
                course=doc.get("course", "unknown"),
                module=doc.get("module", "unknown"),
                module_order=doc.get("module_order", 999),
                topics=doc.get("topics", []),
                last_updated=doc.get("last_updated")
            ))
        
        return TopicsListResponse(
            total_modules=len(modules),
            modules=modules
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving topics for course '{course}': {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail="An error occurred while retrieving topics"
        )

@router.post("/topics/search", response_model=TopicsListResponse)
async def search_topics_by_request(request: TopicRequest):
    """Search topics using POST request with TopicRequest model."""
    try:
        topics = await get_module_topics(request.course, request.module)
        
        if not topics:
            raise HTTPException(
                status_code=404, 
                detail=f"No topics found for module '{request.module}' in course '{request.course}'"
            )
        
        # Get additional metadata
        service = await get_service()
        doc = await service.topics.find_one({
            "course": request.course, 
            "module": request.module
        })
        
        topic_response = TopicResponse(
            program=doc.get("program", "unknown") if doc else "unknown",
            level=doc.get("level", "unknown") if doc else "unknown",
            course=request.course,
            module=request.module,
            module_order=doc.get("module_order", 999) if doc else 999,
            topics=topics,
            last_updated=doc.get("last_updated") if doc else None
        )
        
        return TopicsListResponse(
            total_modules=1,
            modules=[topic_response]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error searching topics: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail="An error occurred while searching topics"
        )

@router.get("/courses-with-ordered-modules/{program}/{level}")
async def get_courses_with_ordered_modules(program: str, level: str):
    """Get all courses with their modules ordered by module_order for frontend course progression."""
    try:
        courses_data = await get_course_modules_with_order(program, level)
        
        if not courses_data:
            raise HTTPException(
                status_code=404, 
                detail=f"No courses found for program '{program}' level '{level}'"
            )
        
        return {
            "program": program,
            "level": level,
            "courses": courses_data,
            "total_courses": len(courses_data)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving ordered courses for program '{program}' level '{level}': {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail="An error occurred while retrieving ordered courses"
        )


@router.get("/dashboard/global", response_model=GlobalStatsResponse)
async def get_global_stats(_: str = Depends(verify_admin_access)):
    """
    Get global user statistics for admin dashboard.
    """
    try:
        user_stats = await admin_analytics_service.get_user_stats()
        
        return GlobalStatsResponse(
            user_stats=user_stats,
            timestamp=datetime.datetime.now().isoformat(),
            success=True
        )
        
    except Exception as e:
        logger.error(f"Error getting global stats: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve global statistics"
        )

@router.get("/dashboard/evaluations", response_model=EvaluationStatsResponse)
async def get_evaluation_stats(_: str = Depends(verify_admin_access)):
    """
    Get evaluation statistics by type.
    """
    try:
        evaluation_stats = await admin_analytics_service.get_evaluation_stats()
        
        return EvaluationStatsResponse(
            evaluation_stats=evaluation_stats,
            timestamp=datetime.datetime.now().isoformat(),
            success=True
        )
        
    except Exception as e:
        logger.error(f"Error getting evaluation stats: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve evaluation statistics"
        )

@router.get("/dashboard/courses", response_model=CourseStatsResponse)
async def get_course_stats(
    limit: int = 10,
    _: str = Depends(verify_admin_access)
):
    """
    Get course statistics and rankings.
    
    Args:
        limit: Maximum number of courses to return (default: 10, max: 50)
    """
    try:
        # Validate limit
        limit = min(max(limit, 1), 50)
        
        course_stats = await admin_analytics_service.get_course_stats(limit_courses=limit)
        
        return CourseStatsResponse(
            course_stats=course_stats,
            timestamp=datetime.datetime.now().isoformat(),
            success=True
        )
        
    except Exception as e:
        logger.error(f"Error getting course stats: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve course statistics"
        )

@router.get("/dashboard/insights", response_model=InsightsResponse)
async def get_insights(_: str = Depends(verify_admin_access)):
    """
    Get insights and alerts for admin dashboard.
    """
    try:
        user_stats = await admin_analytics_service.get_user_stats()
        evaluation_stats = await admin_analytics_service.get_evaluation_stats()
        course_stats = await admin_analytics_service.get_course_stats()
        
        insights_data = await admin_analytics_service.generate_insights(
            user_stats, evaluation_stats, course_stats
        )
        
        return InsightsResponse(
            insights_data=insights_data,
            timestamp=datetime.datetime.now().isoformat(),
            success=True
        )
        
    except Exception as e:
        logger.error(f"Error getting insights: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve insights"
        )

@router.post("/dashboard/complete", response_model=DashboardResponse)
async def get_complete_dashboard(
    request: AdminDashboardRequest,
    _: str = Depends(verify_admin_access)
):
    """
    Get complete dashboard data with optional filters.
    
    Args:
        request: Dashboard request with filters and options
    """
    try:
        dashboard_data = await admin_analytics_service.get_dashboard_data(
            filters=request.filters,
            include_insights=request.include_insights,
            limit_courses=request.limit_courses
        )
        
        return dashboard_data
        
    except Exception as e:
        logger.error(f"Error getting complete dashboard: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dashboard data"
        )

@router.post("/admin-registry/add")
async def add_admin_email(
    email: str,
    username: str = None,
    role: str = "admin",
    #_: str = Depends(verify_admin_access)
):
    """
    Add email to admin registry.
    
    Args:
        email: Email to add to admin registry
        username: Optional username
        role: Admin role (admin or super_admin)
    """
    try:
        admin_collection = AdminCollection()
        admin_id = await admin_collection.add_admin_email(email, username, role)
        
        return {
            "success": True,
            "message": f"Admin email {email} added successfully",
            "admin_id": admin_id
        }
        
    except Exception as e:
        logger.error(f"Error adding admin email: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to add admin email: {str(e)}"
        )

@router.delete("/admin-registry/remove")
async def remove_admin_email(
    email: str,
    _: str = Depends(verify_admin_access)
):
    """
    Remove email from admin registry.
    
    Args:
        email: Email to remove from admin registry
    """
    try:
        admin_collection = AdminCollection()
        success = await admin_collection.remove_admin_email(email)
        
        if success:
            return {
                "success": True,
                "message": f"Admin email {email} removed successfully"
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Admin email not found"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing admin email: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to remove admin email: {str(e)}"
        )

@router.get("/admin-registry/list")
async def list_admin_emails(_: str = Depends(verify_admin_access)):
    """
    List all registered admin emails.
    """
    try:
        admin_collection = AdminCollection()
        admin_emails = await admin_collection.get_admin_emails()
        
        return {
            "success": True,
            "admin_emails": admin_emails,
            "total_admins": len(admin_emails)
        }
        
    except Exception as e:
        logger.error(f"Error listing admin emails: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve admin emails"
        )
