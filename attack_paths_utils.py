"""
Utility module for Attack Paths MCP server.
Contains API client and SignalR client for Raptor API integration.
"""
from typing import Dict, Any, Optional, List
import urllib.parse
import requests
import json
import asyncio
import uuid
from dotenv import load_dotenv

# Load environment variables
load_dotenv(override=True)

# SignalR client imports
try:
    from signalrcore.hub_connection_builder import HubConnectionBuilder
    SIGNALR_AVAILABLE = True
except ImportError:
    SIGNALR_AVAILABLE = False


class RaptorAPIClient:
    """Encapsulated API client for Raptor API calls."""
    
    def __init__(self, base_url: Optional[str] = None, token: Optional[str] = None):
        self._base_url = base_url
        self._access_token = token
        self._headers = {"Content-Type": "application/json", "Accept": "application/json"}
    
    def call(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Make an API call to the Raptor API."""
        if not self._access_token:
            return {"error": "Access token is not set."}
        
        encoded_token = urllib.parse.quote(self._access_token)
        url = f"{self._base_url}/{endpoint}?access_token={encoded_token}"
        body = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
        
        try:
            response = requests.post(url, json=body, headers=self._headers)
            response.raise_for_status()
            return {"response": response.json()}
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}


class SignalRAttackPathClient:
    """SignalR client for streaming attack path summaries from Raptor API Hub."""
    
    def __init__(self, hub_url: str, access_token: str):
        self.hub_url = hub_url
        self.access_token = access_token
        self.connection = None
        self.streaming_results = []
        self.is_connected = False
        
    async def connect(self) -> bool:
        """Connect to the SignalR hub."""
        if not SIGNALR_AVAILABLE:
            raise ImportError("signalrcore package required. Install with: pip install signalrcore")
        
        try:
            encoded_token = urllib.parse.quote(self.access_token)
            connection_url = f"{self.hub_url}?access_token={encoded_token}"
            
            self.connection = HubConnectionBuilder() \
                .with_url(connection_url) \
                .with_automatic_reconnect({
                    "type": "raw", "keep_alive_interval": 10,
                    "reconnect_interval": 5, "max_attempts": 3
                }) \
                .build()
            
            # Register event handlers
            self.connection.on("QueryResult", self._handle_query_result)
            self.connection.on_open(lambda: setattr(self, 'is_connected', True))
            self.connection.on_close(lambda: setattr(self, 'is_connected', False))
            self.connection.on_error(lambda data: print(f"SignalR error: {data}"))
            
            start_result = self.connection.start()
            if asyncio.iscoroutine(start_result):
                await start_result
            
            await asyncio.sleep(2)  # Wait for connection to establish
            return self.is_connected
            
        except Exception:
            return False
    
    async def disconnect(self):
        """Disconnect from the SignalR hub."""
        if self.connection:
            await self.connection.stop()
            self.is_connected = False
    
    def _handle_query_result(self, message):
        """Handle incoming QueryResult messages from the hub."""
        try:
            if isinstance(message, list) and len(message) > 0:
                json_string = message[0]
                if isinstance(json_string, str):
                    parsed_message = json.loads(json_string)
                    if isinstance(parsed_message, dict) and "SummaryMessage" in parsed_message:
                        summary_message = parsed_message["SummaryMessage"]
                        if "AttackPathId" in summary_message and "Content" in summary_message:
                            content = summary_message.get("Content", "")
                            if content.strip():  # Only add non-empty content
                                self.streaming_results.append(summary_message)
        except Exception:
            pass  # Silently ignore parsing errors
    
    async def get_attack_path_summary(self, summary_parameters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Call GetAttackPathSummary method and collect streaming results."""
        if not self.is_connected:
            raise ConnectionError("Not connected to SignalR hub")
        
        self.streaming_results = []
        
        try:
            send_result = self.connection.send("GetAttackPathSummary", [summary_parameters])
            if asyncio.iscoroutine(send_result):
                await send_result
            
            # Wait for streaming results with timeout and stability check
            max_wait_time, wait_interval = 60, 0.5
            elapsed_time = last_result_count = stable_count = 0
            
            while elapsed_time < max_wait_time:
                await asyncio.sleep(wait_interval)
                elapsed_time += wait_interval
                
                current_count = len(self.streaming_results)
                if current_count == last_result_count:
                    stable_count += 1
                    if stable_count >= 10:  # 5 seconds of stability
                        break
                else:
                    stable_count = 0
                    last_result_count = current_count
            
            return self.streaming_results.copy()
            
        except Exception as e:
            raise Exception(f"Failed to get attack path summary: {str(e)}")
