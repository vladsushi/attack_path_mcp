from typing import Dict, Any, List, Optional
import os
from fastmcp import FastMCP
import datetime
import asyncio
import json
import uuid
import sys
import argparse
from raptor_utils import RaptorAPIClient

# SignalR client imports
try:
    import signalrcore
    from signalrcore.hub_connection_builder import HubConnectionBuilder
    from signalrcore.protocol.json_hub_protocol import JsonHubProtocol
    SIGNALR_AVAILABLE = True
except ImportError:
    SIGNALR_AVAILABLE = False


class SignalRAttackPathClient:
    """SignalR client for connecting to the Raptor API Hub and streaming attack path summaries."""
    
    def __init__(self, hub_url: str, access_token: str):
        self.hub_url = hub_url
        self.access_token = access_token
        self.connection = None
        self.streaming_results = []
        self.is_connected = False
        self.current_summary_id = None
        
    async def connect(self) -> bool:
        """Connect to the SignalR hub."""
        if not SIGNALR_AVAILABLE:
            raise ImportError("signalrcore package is required for SignalR functionality. Install with: pip install signalrcore")
        
        try:
            # Build the connection URL with access token as query parameter
            connection_url = f"{self.hub_url}?access_token={self.access_token}"
            print(f"Connecting to: {connection_url}")
            
            # Build the connection with authentication
            self.connection = HubConnectionBuilder() \
                .with_url(connection_url) \
                .with_automatic_reconnect({
                    "type": "raw",
                    "keep_alive_interval": 10,
                    "reconnect_interval": 5,
                    "max_attempts": 3
                }) \
                .build()
            
            # Register event handlers
            self.connection.on("QueryResult", self._handle_query_result)
            self.connection.on_open(self._on_connected)
            self.connection.on_close(self._on_disconnected)
            self.connection.on_error(self._on_error)
            
            print("Starting SignalR connection...")
            # Start the connection
            start_result = self.connection.start()
            if asyncio.iscoroutine(start_result):
                await start_result
            
            # Wait a moment for connection to establish
            await asyncio.sleep(2)
            
            print(f"Connection established: {self.is_connected}")
            return self.is_connected
            
        except Exception as e:
            print(f"Failed to connect to SignalR hub: {str(e)}")
            print(f"Exception type: {type(e).__name__}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            return False
    
    async def disconnect(self):
        """Disconnect from the SignalR hub."""
        if self.connection:
            await self.connection.stop()
            self.is_connected = False
    
    def _on_connected(self):
        """Handle connection established."""
        self.is_connected = True
        print("Connected to SignalR hub")
    
    def _on_disconnected(self):
        """Handle connection closed."""
        self.is_connected = False
        print("Disconnected from SignalR hub")
    
    def _on_error(self, data):
        """Handle connection errors."""
        print(f"SignalR connection error: {data}")
    
    def _handle_query_result(self, message):
        """Handle incoming QueryResult messages from the hub."""
        try:
            # Handle the message format: it's a list containing a JSON string
            if isinstance(message, list) and len(message) > 0:
                # Extract the JSON string from the list
                json_string = message[0]
                if isinstance(json_string, str):
                    # Parse the JSON string
                    parsed_message = json.loads(json_string)
                    
                    # Extract the SummaryMessage from the parsed structure
                    if isinstance(parsed_message, dict) and "SummaryMessage" in parsed_message:
                        summary_message = parsed_message["SummaryMessage"]
                        
                        # Check if this has the expected fields
                        if "AttackPathId" in summary_message and "Content" in summary_message:
                            # Only add messages with actual content (not empty strings)
                            content = summary_message.get("Content", "")
                            if content.strip():  # Only add non-empty content
                                self.streaming_results.append(summary_message)
                                print(f"✅ Added streaming content ({len(content)} chars): {content[:100]}...")
                            
                            # Check for finish reason
                            finish_reason = summary_message.get("FinishReason")
                            if finish_reason:
                                print(f"🏁 Received finish reason: {finish_reason}")
                        else:
                            print(f"⚠️ SummaryMessage missing expected fields. Keys: {list(summary_message.keys())}")
                    else:
                        print(f"⚠️ Message doesn't contain SummaryMessage. Keys: {list(parsed_message.keys()) if isinstance(parsed_message, dict) else 'Not a dict'}")
                else:
                    print(f"⚠️ List item is not a string: {type(json_string)}")
            else:
                print(f"⚠️ Message is not a list or is empty: {type(message)}")
                
        except Exception as e:
            print(f"Error handling QueryResult: {str(e)}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
    
    async def get_attack_path_summary(self, summary_parameters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Call the GetAttackPathSummary method and collect streaming results."""
        if not self.is_connected:
            raise ConnectionError("Not connected to SignalR hub")
        
        # Clear previous results
        self.streaming_results = []
        self.current_summary_id = summary_parameters.get("SummaryId", str(uuid.uuid4()))
        
        try:
            print(f"Sending GetAttackPathSummary request with SummaryId: {self.current_summary_id}")
            
            # Invoke the GetAttackPathSummary method
            send_result = self.connection.send("GetAttackPathSummary", [summary_parameters])
            
            # Handle the send result properly - don't await it if it's not a coroutine
            if asyncio.iscoroutine(send_result):
                await send_result
            
            print("Request sent, waiting for streaming results...")
            
            # Wait for streaming results to complete
            # We'll wait up to 60 seconds for the LLM to finish streaming
            max_wait_time = 60
            wait_interval = 0.5
            elapsed_time = 0
            last_result_count = 0
            stable_count = 0
            
            while elapsed_time < max_wait_time:
                await asyncio.sleep(wait_interval)
                elapsed_time += wait_interval
                
                # Check if we're still receiving results
                current_count = len(self.streaming_results)
                if current_count == last_result_count:
                    stable_count += 1
                    # If no new results for 5 seconds, assume streaming is complete
                    if stable_count >= 10:  # 10 * 0.5s = 5 seconds
                        print(f"No new results for 5 seconds, assuming complete. Total messages: {current_count}")
                        break
                else:
                    stable_count = 0
                    last_result_count = current_count
                    print(f"Received {current_count} messages so far...")
            
            print(f"Streaming completed with {len(self.streaming_results)} total messages")
            return self.streaming_results.copy()
            
        except Exception as e:
            print(f"Exception in get_attack_path_summary: {str(e)}")
            print(f"Exception type: {type(e).__name__}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            raise Exception(f"Failed to get attack path summary: {str(e)}")


class AttackPathsMCPServer:
    """Encapsulated MCP server for Attack Path Analysis operations using SignalR."""
    
    def __init__(self, raptor_token: Optional[str] = None, raptor_url: Optional[str] = None, hub_path: Optional[str] = None):
        name = "Attack Paths Analysis Server"
        desc = """
            This server provides structured attack path analysis through the Raptor SignalR API.
            
            The server connects to a SignalR hub to stream real-time attack path summaries
            generated by LLM analysis of complex attack path data.
            """
        
        self.mcp = FastMCP(
            name=name,
            instructions=desc
        )
        
        # Configure SignalR connection
        self._raptor_token = raptor_token or os.getenv("RAPTOR_TOKEN")
        self._raptor_url = raptor_url or "http://localhost:5000"
        self._hub_path = hub_path or "/api"  # Correct hub path
        # Convert HTTP URL to WebSocket URL for SignalR
        ws_url = self._raptor_url.replace("http://", "ws://").replace("https://", "wss://")
        self._hub_url = f"{ws_url}{self._hub_path}"
        
        # Initialize API client for determine_attack_paths call
        self._api_client = RaptorAPIClient(f"{self._raptor_url}/v1", self._raptor_token)
        self._signalr_client = None
        self._register_tools()
    
    async def _get_signalr_client(self) -> SignalRAttackPathClient:
        """Get or create SignalR client connection."""
        if not self._signalr_client:
            self._signalr_client = SignalRAttackPathClient(self._hub_url, self._raptor_token)
            
        if not self._signalr_client.is_connected:
            connected = await self._signalr_client.connect()
            if not connected:
                raise ConnectionError("Failed to connect to SignalR hub")
                
        return self._signalr_client
    
    def _register_tools(self) -> None:
        """Register all MCP tools."""
        self._register_attack_path_tools()
    
    def _register_attack_path_tools(self) -> None:
        """Register attack path analysis tools."""
        
        @self.mcp.tool()
        async def structured_attack_path_analysis(
            domain_filter: Optional[List[str]] = None,
            zone_filter: Optional[List[str]] = None,
            zero_cost_paths: bool = False,
            include_blowout_paths: bool = True,
            return_principals_only: bool = True,
            zero_cost_only: bool = False,
            blowout_paths: int = 250,
            attacker_oid: str = "",
            target_oid: str = "",
            summary_id: Optional[str] = None,
            force_refresh: bool = False
        ) -> Dict[str, Any]:
            """
            **Role**: Performs comprehensive structured analysis of attack paths with AI-powered summaries
            
            This tool first calls determine_attack_paths to get attack path data, then takes the first attack path
            and connects to the SignalR hub to stream real-time LLM-generated summaries of that attack path.
            It provides detailed, human-readable analysis of complex attack paths to help security analysts
            understand the implications and steps involved in potential security breaches.
            
            **Inputs**:
            - domain_filter: List of Active Directory domain names to include in analysis. When provided, 
              only objects from these domains will be considered. If None, all domains are included.
            - zone_filter: List of security zone IDs to include in analysis. When provided, only objects 
              from these zones will be considered. If None, all zones are included.
            - zero_cost_paths: Boolean flag to include all zero-cost (immediate) attack paths. Default False.
              When True, paths with no security barriers are included in the analysis.
            - include_blowout_paths: Boolean flag to include additional path variations when complexity 
              limit is reached. Default True. When False, only paths discovered before hitting the limit.
            - return_principals_only: Boolean flag to analyze only paths ending at security principals. 
              Default True. When False, paths ending at any object type are analyzed.
            - zero_cost_only: Boolean flag to analyze only zero-cost attack paths. Default False. 
              When True, only immediate attack vectors are analyzed.
            - blowout_paths: Maximum number of attack paths to analyze before stopping. Default 250. 
              Prevents excessive computation for complex environments.
            - attacker_oid: Object identifier of the starting point for attack simulation. When provided, 
              only paths from this specific object are analyzed. If empty, all potential attackers considered.
            - target_oid: Object identifier of the attack target. When provided, only paths to this 
              specific object are analyzed. If empty, all Tier 0 assets are considered targets.
            - summary_id: Optional unique identifier for the summary request. If not provided, one will be generated.
            - force_refresh: Boolean flag to force a refresh of the summary even if cached. Default False.
            
            **Outputs**:
            - attack_paths_response: The full response from determine_attack_paths call
            - first_attack_path: The first attack path that was analyzed
            - streaming_summary: Complete LLM-generated summary content assembled from streaming responses
            - summary_metadata: Metadata about the summary including timing and message count
            - attack_path_info: Processed information about the attack path being analyzed
            - analysis_completed: Boolean indicating if the analysis completed successfully
            """
            
            if not SIGNALR_AVAILABLE:
                return {
                    "error": "SignalR functionality not available. Please install signalrcore: pip install signalrcore",
                    "attack_paths_response": None,
                    "first_attack_path": None,
                    "streaming_summary": None,
                    "summary_metadata": None,
                    "attack_path_info": None,
                    "analysis_completed": False
                }
            
            try:
                # Step 1: Call determine_attack_paths to get attack path data
                attack_path_params = self._build_attack_path_params(
                    domain_filter, zone_filter, zero_cost_paths, include_blowout_paths,
                    return_principals_only, zero_cost_only, blowout_paths, attacker_oid, target_oid
                )
                
                attack_paths_response = self._api_client.call("DetermineAttackPaths", attack_path_params)
                
                # Check for API errors
                if "error" in attack_paths_response:
                    return {
                        "error": f"Failed to determine attack paths: {attack_paths_response['error']}",
                        "attack_paths_response": attack_paths_response,
                        "first_attack_path": None,
                        "streaming_summary": None,
                        "summary_metadata": None,
                        "attack_path_info": None,
                        "analysis_completed": False
                    }
                
                # Extract attack paths from response
                response_data = attack_paths_response.get("response", {})
                attack_paths = response_data.get("AttackPaths", [])
                
                # Check if zero_cost_paths was requested and use appropriate field
                if zero_cost_paths and "ZeroCostAttackPaths" in response_data:
                    attack_paths = response_data.get("ZeroCostAttackPaths", [])
                
                if not attack_paths:
                    return {
                        "error": "No attack paths found in the response",
                        "attack_paths_response": attack_paths_response,
                        "first_attack_path": None,
                        "streaming_summary": None,
                        "summary_metadata": None,
                        "attack_path_info": None,
                        "analysis_completed": False
                    }
                
                # Step 2: Take the first attack path for summary analysis
                first_attack_path = attack_paths[0]
                
                # Generate summary ID if not provided
                if not summary_id:
                    summary_id = str(uuid.uuid4())
                
                # Build the SummaryParameters structure
                summary_parameters = {
                    "SummaryId": summary_id,
                    "SummaryAttackPath": first_attack_path,
                    "ForceRefresh": force_refresh
                }
                
                # Step 3: Get SignalR client and connect
                signalr_client = await self._get_signalr_client()
                
                # Step 4: Request attack path summary
                streaming_results = await signalr_client.get_attack_path_summary(summary_parameters)
                
                # Process the streaming results
                summary_content = self._process_streaming_results(streaming_results)
                
                # Extract attack path information for context
                attack_path_info = self._extract_attack_path_info(first_attack_path)
                
                # Build metadata
                summary_metadata = {
                    "summary_id": summary_id,
                    "timestamp": datetime.datetime.now().isoformat(),
                    "message_count": len(streaming_results),
                    "force_refresh": force_refresh,
                    "streaming_completed": True,
                    "total_attack_paths_found": len(attack_paths),
                    "analyzed_path_index": 0
                }
                
                return {
                    "attack_paths_response": attack_paths_response,
                    "first_attack_path": first_attack_path,
                    "streaming_summary": summary_content,
                    "summary_metadata": summary_metadata,
                    "attack_path_info": attack_path_info,
                    "analysis_completed": True
                }
                
            except Exception as e:
                return {
                    "error": f"Failed to complete attack path analysis: {str(e)}",
                    "attack_paths_response": None,
                    "first_attack_path": None,
                    "streaming_summary": None,
                    "summary_metadata": {
                        "summary_id": summary_id if 'summary_id' in locals() else None,
                        "timestamp": datetime.datetime.now().isoformat(),
                        "error": str(e),
                        "streaming_completed": False
                    },
                    "attack_path_info": None,
                    "analysis_completed": False
                }
    
    def _process_streaming_results(self, streaming_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Process the streaming results from SignalR into a structured summary."""
        if not streaming_results:
            return {
                "content": "No summary content received",
                "finish_reason": "no_content",
                "total_chunks": 0
            }
        
        # Combine all content chunks
        full_content = ""
        finish_reason = "unknown"
        
        for result in streaming_results:
            content = result.get("Content", "")
            if content:
                full_content += content
            
            # Check for finish reason in the last message
            if result.get("FinishReason"):
                finish_reason = result.get("FinishReason")
        
        return {
            "content": full_content,
            "finish_reason": finish_reason,
            "total_chunks": len(streaming_results),
            "raw_messages": streaming_results
        }
    
    def _extract_attack_path_info(self, attack_path_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key information from the attack path data for context."""
        if not attack_path_data:
            return {}
        
        info = {
            "attack_path_id": attack_path_data.get("Id"),
            "cost": attack_path_data.get("Cost"),
            "risk_score": attack_path_data.get("RiskScore"),
            "blowout": attack_path_data.get("Blowout"),
            "source_info": {},
            "target_info": {},
            "path_summary": {}
        }
        
        # Extract source information
        source = attack_path_data.get("Source", {})
        if source:
            info["source_info"] = {
                "id": source.get("id"),
                "type": source.get("type"),
                "label": source.get("label"),
                "domain": source.get("domain"),
                "zone": source.get("zone")
            }
        
        # Extract target information
        target = attack_path_data.get("Target", {})
        if target:
            info["target_info"] = {
                "id": target.get("id"),
                "type": target.get("type"),
                "label": target.get("label"),
                "domain": target.get("domain"),
                "zone": target.get("zone")
            }
        
        # Extract path summary
        path = attack_path_data.get("Path", {})
        if path:
            nodes = path.get("nodes", [])
            links = path.get("links", [])
            info["path_summary"] = {
                "node_count": len(nodes) if nodes else 0,
                "link_count": len(links) if links else 0
            }
        
        return info
    
    def _build_attack_path_params(self, domain_filter: Optional[List[str]], 
                                 zone_filter: Optional[List[str]], 
                                 zero_cost_paths: bool,
                                 include_blowout_paths: bool,
                                 return_principals_only: bool,
                                 zero_cost_only: bool,
                                 blowout_paths: int,
                                 attacker_oid: str,
                                 target_oid: str) -> Dict[str, Any]:
        """Build parameters for attack path-related API calls."""
        params = {}
        if domain_filter is not None:
            params["DomainFilter"] = domain_filter
        if zone_filter is not None:
            params["ZoneFilter"] = zone_filter
        params["ZeroCostPaths"] = zero_cost_paths
        params["IncludeBlowoutPaths"] = include_blowout_paths
        params["ReturnPrincipalsOnly"] = return_principals_only
        params["ZeroCostOnly"] = zero_cost_only
        params["BlowoutPaths"] = blowout_paths
        if attacker_oid:
            params["AttackerID"] = attacker_oid
        if target_oid:
            params["TargetID"] = target_oid
        return params
    
    def run(self, transport: str = 'streamable-http', host: str = '127.0.0.1', port: int = 8001, path: str = '/mcp') -> None:
        """Run the MCP server with HTTP transport.
        
        Args:
            transport: Transport method to use (default: 'streamable-http')
            host: Host to bind the server to (default: '127.0.0.1')
            port: Port to bind the server to (default: 8001)
            path: URL path for the MCP endpoint (default: '/mcp')
        """
        self.mcp.run(transport=transport, host=host, port=port, path=path)


# Create singleton instance for backward compatibility
_server_instance = None


def get_server_instance() -> AttackPathsMCPServer:
    """Get or create the singleton server instance."""
    global _server_instance
    if _server_instance is None:
        _server_instance = AttackPathsMCPServer()
    return _server_instance


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Attack Paths MCP Server (SignalR)")
    parser.add_argument("-raptor_token", type=str, default=None, help="Override RAPTOR_TOKEN for API access")
    parser.add_argument("-raptor_url", type=str, default="http://localhost:5000", help="Override RAPTOR_URL for SignalR hub access")
    parser.add_argument("-host", type=str, default="127.0.0.1", help="Host to bind the server to (default: 127.0.0.1)")
    parser.add_argument("-port", type=int, default=8003, help="Port to bind the server to (default: 8003)")
    parser.add_argument("-path", type=str, default="/mcp", help="URL path for the MCP endpoint (default: /mcp)")
    args = parser.parse_args()

    # Create and run the server with optional token, url, host, port, and path override
    server = AttackPathsMCPServer(raptor_token=args.raptor_token, raptor_url=args.raptor_url)
    server.run(transport='streamable-http', host=args.host, port=args.port, path=args.path)
