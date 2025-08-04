"""
Minimal utility module for Attack Paths MCP server.
Contains only the RaptorAPIClient needed for API calls.
"""
from typing import Dict, Any, Optional
import urllib.parse
import requests
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv(override=True)


class RaptorAPIClient:
    """Encapsulated API client for Raptor API calls."""
    
    def __init__(self, base_url: Optional[str] = None, token: Optional[str] = None):
        self._base_url = base_url
        self._access_token = token
        self._headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
    
    def call(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Make an API call to the Raptor API.
        
        Args:
            endpoint: The API endpoint to call
            params: Optional parameters for the API call
        
        Returns:
            Dict containing the API response or error information
        """
        if not self._access_token:
            return {"error": "Access token is not set."}
        
        # Properly encode the access token
        encoded_token = urllib.parse.quote(self._access_token)
        
        # Build URL with encoded access token as query parameter
        url = f"{self._base_url}/{endpoint}?access_token={encoded_token}"
        
        # Prepare request body with parameters
        body = self._prepare_body(params)
        
        try:
            # Use POST with JSON body
            response = requests.post(url, json=body, headers=self._headers)
            response.raise_for_status()
            return {"response": response.json()}
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
    
    def _prepare_body(self, params: Optional[Dict]) -> Dict:
        """Prepare request body by filtering out empty parameters."""
        if not params:
            return {}
        return {k: v for k, v in params.items() if v is not None and v != ""}
