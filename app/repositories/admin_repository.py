from datetime import datetime
import logging
from typing import List, Dict, Any, Optional

from app.services.database.mongo_utils import get_service

logger = logging.getLogger(__name__)


class AdminCollectionError(Exception):
    """
    Custom exception for admin collection errors.
    """
    pass


class AdminCollection:
    """
    Admin registry manager for identifying admin users and excluding them from student statistics.
    This collection serves as a simple registry of admin emails, not a separate user system.
    """
    
    def __init__(self):
        """
        Initialize admin collection.
        """
        logger.debug("AdminCollection initialized")
    
    async def add_admin_email(self, email: str, username: str = None, role: str = "admin") -> str:
        """
        Add email to admin registry.
        
        Args:
            email: Admin email (@skema.edu)
            username: Optional username for reference
            role: Admin role (admin or super_admin)
            
        Returns:
            Created admin registry ID
            
        Raises:
            AdminCollectionError: On creation error
        """
        try:
            if not email.endswith("@skema.edu"):
                raise AdminCollectionError("Admin email must be from @skema.edu domain")
            
            service = await get_service()
            existing_admin = await service.find_admin_by_email(email)
            if existing_admin:
                logger.warning(f"Admin email already registered: {email}")
                return str(existing_admin["_id"])
            
            admin_data = {
                "email": email,
                "username": username or email.split("@")[0],
                "role": role,
                "created_at": datetime.now(),
                "is_active": True
            }
            
            admin_id = await service.create_admin(admin_data)
            logger.info(f"Admin email registered: {email}")
            return admin_id
            
        except AdminCollectionError:
            raise
        except Exception as e:
            logger.error(f"Error adding admin email: {str(e)}")
            raise AdminCollectionError(f"Error adding admin email: {str(e)}")
    
    async def is_admin(self, email: str) -> bool:
        """
        Check if email is registered as admin.
        
        Args:
            email: Email to check
            
        Returns:
            True if email is admin, False otherwise
        """
        try:
            service = await get_service()
            admin = await service.find_admin_by_email(email)
            return admin is not None and admin.get("is_active", True)
            
        except Exception as e:
            logger.error(f"Error checking admin status: {str(e)}")
            return False
    
    async def get_admin_user_ids(self) -> List[str]:
        """
        Get user IDs of all users who are admins (for excluding from student statistics).
        
        Returns:
            List of user IDs that are admins
        """
        try:
            service = await get_service()
            
            admins = await service.find_all_admins()
            admin_emails = [admin["email"] for admin in admins if admin.get("is_active", True)]
            
            if not admin_emails:
                return []
            
            admin_user_ids = []
            for email in admin_emails:
                user = await service.find_user_by_email(email)
                if user:
                    admin_user_ids.append(str(user["_id"]))
            
            logger.debug(f"Found {len(admin_user_ids)} admin user IDs")
            return admin_user_ids
            
        except Exception as e:
            logger.error(f"Error getting admin user IDs: {str(e)}")
            return []
    
    async def get_admin_emails(self) -> List[str]:
        """
        Get all registered admin emails.
        
        Returns:
            List of admin emails
        """
        try:
            service = await get_service()
            admins = await service.find_all_admins()
            return [admin["email"] for admin in admins if admin.get("is_active", True)]
            
        except Exception as e:
            logger.error(f"Error getting admin emails: {str(e)}")
            return []
    
    async def remove_admin_email(self, email: str) -> bool:
        """
        Remove email from admin registry (deactivate).
        
        Args:
            email: Admin email to remove
            
        Returns:
            True if removal successful, False otherwise
        """
        try:
            service = await get_service()
            admin = await service.find_admin_by_email(email)
            
            if not admin:
                logger.warning(f"Admin email not found: {email}")
                return False
            
            result = await service.update_admin(str(admin["_id"]), {"is_active": False})
            
            if result:
                logger.info(f"Admin email deactivated: {email}")
                return True
            else:
                logger.warning(f"Failed to deactivate admin email: {email}")
                return False
            
        except Exception as e:
            logger.error(f"Error removing admin email: {str(e)}")
            return False
    
    async def get_admin_info_by_user_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get admin info for a specific user ID (if user is admin).
        
        Args:
            user_id: User ID to check
            
        Returns:
            Admin info dict or None if user is not admin
        """
        try:
            service = await get_service()
            
            user = await service.get_user_by_id(user_id)
            if not user:
                return None
            
            admin = await service.find_admin_by_email(user["email"])
            if admin and admin.get("is_active", True):
                return {
                    "admin_id": str(admin["_id"]),
                    "email": admin["email"],
                    "role": admin.get("role", "admin"),
                    "username": admin.get("username"),
                    "created_at": admin.get("created_at")
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting admin info for user {user_id}: {str(e)}")
            return None
    
    async def get_non_admin_users_count(self) -> int:
        """
        Get count of users who are NOT admins (for student statistics).
        
        Returns:
            Number of non-admin users
        """
        try:
            service = await get_service()
            
            all_users = await service.find_all_users()
            total_users = len(all_users)
            
            admin_user_ids = await self.get_admin_user_ids()
            admin_count = len(admin_user_ids)
            
            student_count = total_users - admin_count
            logger.debug(f"Total users: {total_users}, Admins: {admin_count}, Students: {student_count}")
            
            return max(0, student_count)
            
        except Exception as e:
            logger.error(f"Error getting non-admin users count: {str(e)}")
            return 0
