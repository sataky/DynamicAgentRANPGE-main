import json
import base64
import secrets
import requests
import hmac
import hashlib
import time
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlencode, parse_qs, urlparse
import logging
from app.config import (
    AZURE_CLIENT_ID,
    AZURE_CLIENT_SECRET,
    AZURE_TENANT_ID,
    AZURE_REDIRECT_URI
)

logger = logging.getLogger(__name__)

class AzureAuthService:
    """Service for Azure AD OAuth2 Authorization Code Flow authentication"""
    
    def __init__(self):
        self.client_id = AZURE_CLIENT_ID
        self.client_secret = AZURE_CLIENT_SECRET
        self.tenant_id = AZURE_TENANT_ID
        self.redirect_uri = AZURE_REDIRECT_URI
        
        if not all([self.client_id, self.client_secret, self.tenant_id, self.redirect_uri]):
            raise ValueError("Missing required Azure AD configuration in environment variables")
        
        self.authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        self.graph_endpoint = "https://graph.microsoft.com/v1.0"
        
        self.state_secret = (self.client_secret + "SKEMA_STATE_SECRET").encode()

    def decode_state_if_encoded(self, state: str) -> str:
        """
        Decode state if it's encoded, otherwise return original state.
        
        Args:
            state: State parameter (could be encoded or original)
            
        Returns:
            Original state for validation
        """
        try:
            state_data = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
            if isinstance(state_data, dict) and 'original_state' in state_data:
                return state_data['original_state']
        except:
            pass
        return state
    
    def _create_signed_state(self) -> str:
        """Create cryptographically signed state that can be validated without storage."""
        timestamp = int(time.time())
        nonce = secrets.token_urlsafe(16)
        
        payload = {
            "ts": timestamp,
            "nonce": nonce
        }
        
        payload_json = json.dumps(payload, separators=(',', ':'))
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')
        
        signature = hmac.new(
            self.state_secret,
            payload_b64.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f"{payload_b64}.{signature}"
    
    def _validate_signed_state(self, state: str, max_age_seconds: int = 900) -> bool:
        """Validate cryptographically signed state."""
        try:
            if '.' not in state:
                return False
                
            payload_b64, received_signature = state.split('.', 1)
            
            expected_signature = hmac.new(
                self.state_secret,
                payload_b64.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(received_signature, expected_signature):
                return False
            
            payload_b64_padded = payload_b64 + '=' * (4 - len(payload_b64) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64_padded).decode()
            payload = json.loads(payload_json)
            
            timestamp = payload.get('ts')
            if not timestamp:
                return False
                
            age = time.time() - timestamp
            if age > max_age_seconds:
                return False
                
            return True
            
        except Exception as e:
            logger.warning(f"State validation error: {str(e)}")
            return False
    
    def generate_authorization_url(self, prompt: str = "select_account") -> Tuple[str, str]:
        """
        Generate Azure AD authorization URL for OAuth2 flow.
        
        Args:
            prompt: Azure AD prompt parameter ('select_account', 'none', 'login', 'consent')
            
        Returns:
            Tuple of (authorization_url, state) where state is cryptographically signed
        """
        state = self._create_signed_state()
        
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": "openid profile email User.Read",
            "state": state,
            "prompt": prompt,
            "response_mode": "query"
        }
        
        auth_url = f"{self.authority}/oauth2/v2.0/authorize?" + urlencode(params)
        
        logger.info(f"Generated authorization URL with state: {state}")
        
        return auth_url, state

    def validate_state(self, state: str) -> bool:
        """
        Validate state parameter to prevent CSRF attacks.
        
        Args:
            state: State parameter received from callback (could be encoded)
            
        Returns:
            True if state is valid, False otherwise
        """
        original_state = self.decode_state_if_encoded(state)
        return self._validate_signed_state(original_state, max_age_seconds=900)
        
    async def exchange_code_for_tokens(self, code: str, state: str) -> Optional[Dict[str, Any]]:
        """
        Exchange authorization code for access and ID tokens.
        
        Args:
            code: Authorization code received from Azure AD
            state: State parameter for validation (could be encoded)
            
        Returns:
            Token response dict or None if exchange failed
        """
        if not self.validate_state(state):
            logger.warning("Invalid state parameter in token exchange")
            return None
        
        token_url = f"{self.authority}/oauth2/v2.0/token"
        
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
            "scope": "openid profile email User.Read"
        }
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        try:
            response = requests.post(token_url, data=data, headers=headers, timeout=10)
            
            if response.status_code != 200:
                logger.error(f"Token exchange failed: {response.status_code} - {response.text}")
                return None
            
            tokens = response.json()
            logger.info("Successfully exchanged authorization code for tokens")
            return tokens
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error during token exchange: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in token exchange: {str(e)}")
            return None
    
    async def get_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        """
        Get user information from Microsoft Graph API using access token.
        
        Args:
            access_token: Azure AD access token
            
        Returns:
            User information dict or None if request failed
        """
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.get(
                f"{self.graph_endpoint}/me",
                headers=headers,
                timeout=10
            )
            
            if response.status_code != 200:
                logger.error(f"Microsoft Graph API failed: {response.status_code} - {response.text}")
                return None
            
            user_info = response.json()
            
            email = user_info.get('mail') or user_info.get('userPrincipalName')
            if not email:
                logger.warning("No email found in user profile")
                return None
            
            if not email.lower().endswith('@skema.edu'):
                logger.warning(f"Invalid email domain: {email}")
                return None
            
            logger.info(f"Successfully retrieved user info for: {email}")
            
            return {
                'email': email.lower(),
                'display_name': user_info.get('displayName', ''),
                'given_name': user_info.get('givenName', ''),
                'surname': user_info.get('surname', ''),
                'user_principal_name': user_info.get('userPrincipalName', ''),
                'azure_user_id': user_info.get('id', '')
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error calling Microsoft Graph API: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting user info: {str(e)}")
            return None
    
    async def complete_oauth_flow(self, code: str, state: str) -> Optional[Dict[str, Any]]:
        """
        Complete the full OAuth2 flow: exchange code for tokens and get user info.
        
        Args:
            code: Authorization code from Azure AD callback
            state: State parameter for validation
            
        Returns:
            User information dict or None if flow failed
        """
        tokens = await self.exchange_code_for_tokens(code, state)
        if not tokens:
            return None
        
        access_token = tokens.get('access_token')
        if not access_token:
            logger.error("No access token in token response")
            return None
        
        user_info = await self.get_user_info(access_token)
        if not user_info:
            return None
        
        user_info['tokens'] = tokens
        return user_info

azure_auth_service = AzureAuthService()
