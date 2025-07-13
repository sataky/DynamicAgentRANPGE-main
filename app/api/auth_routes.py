import os
import json
import base64
from urllib.parse import urlparse
from fastapi import APIRouter, HTTPException, Request , Depends
from fastapi.responses import JSONResponse, RedirectResponse
from app.models.schemas.auth_models import (
    RefreshTokenRequest,
    TokenResponse,
    LogoutResponse
)
from app.services.external.auth_service import auth_service
from app.repositories.user_repository import UserCollection
from app.services.external.azure_auth_service import azure_auth_service

from app.logs import logger

router = APIRouter(prefix="/api/auth", tags=["authentication"])

async def get_user_collection() -> UserCollection:
    """
    Dependency function to provide an instance of UserCollection repository.
    
    Returns:
        UserCollection: A new instance of the user repository.
    """
    return UserCollection()

def determine_frontend_url(referer: str, origin: str) -> str:
    user_frontend_url = os.getenv("USER_FRONTEND_URL")
    admin_frontend_url = os.getenv("ADMIN_FRONTEND_URL")
    
    source = origin or referer
    
    if admin_frontend_url and admin_frontend_url in source:
        return admin_frontend_url
    
    return user_frontend_url

def encode_state_with_frontend(original_state: str, frontend_url: str) -> str:
    state_data = {
        "original_state": original_state,
        "frontend_url": frontend_url
    }
    return base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

def decode_state_with_frontend(encoded_state: str) -> tuple:
    try:
        state_data = json.loads(base64.urlsafe_b64decode(encoded_state.encode()).decode())
        return state_data["original_state"], state_data["frontend_url"]
    except:
        return encoded_state, None

@router.get("/azure/login")
async def azure_login(request: Request):
    """Initiate Azure AD OAuth2 authentication flow."""
    try:
        referer = request.headers.get("referer", "")
        origin = request.headers.get("origin", "")
        frontend_url = determine_frontend_url(referer, origin)

        auth_url, original_state = azure_auth_service.generate_authorization_url()
        encoded_state = encode_state_with_frontend(original_state, frontend_url)
        auth_url = auth_url.replace(f"state={original_state}", f"state={encoded_state}")
        
        logger.info(f"Redirecting to Azure AD for authentication with state: {encoded_state}")
        return RedirectResponse(url=auth_url, status_code=302)
        
    except Exception as e:
        logger.error(f"Error initiating Azure authentication: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to initiate Azure authentication")


@router.get("/azure/callback")
async def azure_callback(
    request: Request,
    user_collection: UserCollection = Depends(get_user_collection)
):
    """Handle Azure AD OAuth2 callback and complete authentication."""
    try:
        # Get frontend URL from environment variable
        default_frontend_url = os.getenv("USER_FRONTEND_URL")
        
        query_params = dict(request.query_params)
        code = query_params.get('code')
        encoded_state = query_params.get('state')
        error = query_params.get('error')

        original_state, frontend_url = decode_state_with_frontend(encoded_state)
        
        if not frontend_url:
            frontend_url = default_frontend_url
        
        if error:
            logger.error(f"Azure AD returned error: {error}")
            frontend_error_url = f"{frontend_url}/login?error=azure_auth_failed"
            return RedirectResponse(url=frontend_error_url, status_code=302)
        
        if not code or not original_state:
            logger.error("Missing code or state parameter in Azure callback")
            frontend_error_url = f"{frontend_url}/login?error=missing_parameters"
            return RedirectResponse(url=frontend_error_url, status_code=302)
        
        azure_user_info = await azure_auth_service.complete_oauth_flow(code, original_state)
        
        if not azure_user_info:
            logger.error("Failed to complete Azure OAuth flow")
            frontend_error_url = f"{frontend_url}/login?error=oauth_failed"
            return RedirectResponse(url=frontend_error_url, status_code=302)
        
        email = azure_user_info['email']
        display_name = azure_user_info['display_name']
        
        user_info = await user_collection.get_user_by_email(email)
        
        if not user_info:
            from app.models.entities.user import UserCreate
            
            username = display_name if display_name else email.split('@')[0].replace('.', ' ').title()
            
            new_user_data = UserCreate(email=email, username=username)
            user_id = await user_collection.create_user(new_user_data)
            
            logger.info(f"New user created from Azure SSO: {email}")
            user_info = await user_collection.get_user_by_id(user_id)
            await user_collection.update_last_login(str(user_info.id))
        else:
            await user_collection.update_last_login(str(user_info.id))
            logger.info(f"Existing user logged in via Azure SSO: {email}")
        
        tokens = auth_service.create_tokens(str(user_info.id))
        if not tokens:
            logger.error("Failed to generate authentication tokens")
            frontend_error_url = f"{frontend_url}/login?error=token_generation_failed"
            return RedirectResponse(url=frontend_error_url, status_code=302)
        
        frontend_success_url = (
            f"{frontend_url}/?"
            f"access_token={tokens['access_token']}&"
            f"refresh_token={tokens['refresh_token']}&"
            f"token_type={tokens['token_type']}&"
            f"access_token_expires={tokens['access_token_expires']}&"
            f"refresh_token_expires={tokens['refresh_token_expires']}&"
            f"user_id={str(user_info.id)}"
        )
        
        return RedirectResponse(url=frontend_success_url, status_code=302)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in Azure callback: {str(e)}")
        default_frontend_url = os.getenv("USER_FRONTEND_URL")
        frontend_error_url = f"{default_frontend_url}/login?error=server_error"
        return RedirectResponse(url=frontend_error_url, status_code=302)


@router.post("/refresh-token", response_model=TokenResponse)
async def refresh_token(
    request: RefreshTokenRequest
    ):
    """Refresh access token using refresh token."""
    try:
        new_tokens = auth_service.refresh_access_token(request.refresh_token)
        
        if not new_tokens:
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
        
        return TokenResponse(**new_tokens)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error refreshing token: {str(e)}")
        raise HTTPException(status_code=500, detail="An error occurred while refreshing token")

@router.post("/logout", response_model=LogoutResponse)
async def logout(
    current_user_id: str = Depends(auth_service.get_current_user)
    ):
    """Logout user by revoking all tokens."""
    try:
        success = auth_service.revoke_all_tokens(current_user_id)
        
        if success:
            return LogoutResponse(message="Successfully logged out", status=True)
        else:
            return LogoutResponse(message="No active tokens found", status=True)
            
    except Exception as e:
        logger.error(f"Error during logout: {str(e)}")
        raise HTTPException(status_code=500, detail="An error occurred during logout")

@router.get("/me")
async def get_current_user_info(
    current_user_id: str = Depends(auth_service.get_current_user),
    user_collection: UserCollection = Depends(get_user_collection)
):
    """Get current authenticated user information."""
    try:
        user_info = await user_collection.get_user_by_id(current_user_id)
        if not user_info:
            raise HTTPException(status_code=404, detail="User not found")
        
        user_dict = user_info.model_dump() if hasattr(user_info, 'dict') else user_info
        
        if user_dict.get('created_at'):
            user_dict['created_at'] = user_dict['created_at'].isoformat()
        
        if user_dict.get('last_login'):
            user_dict['last_login'] = user_dict['last_login'].isoformat()
        elif user_dict.get('created_at'):
            user_dict['last_login'] = user_dict['created_at']
        
        user_dict["progression_initialized"] = bool(user_dict.get("course_progress"))

        return user_dict
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting user info: {str(e)}")
        raise HTTPException(status_code=500, detail="An error occurred while fetching user information")

