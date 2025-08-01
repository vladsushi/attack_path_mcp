from typing import Dict, Any, List, Optional
import os
from fastmcp import FastMCP
import datetime
import asyncio
import json
import uuid
import sys
import argparse

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
            # Build the connection with authentication
            self.connection = HubConnectionBuilder() \
                .with_url(self.hub_url, options={
                    "access_token_factory": lambda: self.access_token,
                    "headers": {
                        "Authorization": f"Bearer {self.access_token}"
                    }
                }) \
                .with_automatic_reconnect({
                    "type": "raw",
                    "keep_alive_interval": 10,
                    "reconnect_interval": 5,
                    "max_attempts": 5
                }) \
                .build()
            
            # Register event handlers
            self.connection.on("QueryResult", self._handle_query_result)
            self.connection.on_open(lambda: self._on_connected())
            self.connection.on_close(lambda: self._on_disconnected())
            self.connection.on_error(lambda data: self._on_error(data))
            
            # Start the connection
            await self.connection.start()
            
            # Wait a moment for connection to establish
            await asyncio.sleep(1)
            
            return self.is_connected
            
        except Exception as e:
            print(f"Failed to connect to SignalR hub: {str(e)}")
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
            # Parse the JSON message
            if isinstance(message, str):
                parsed_message = json.loads(message)
            else:
                parsed_message = message
            
            # Check if this is an AttackPathSummaryResponse
            if "AttackPathId" in parsed_message and "Content" in parsed_message:
                self.streaming_results.append(parsed_message)
                print(f"Received streaming content: {parsed_message.get('Content', '')[:100]}...")
                
        except Exception as e:
            print(f"Error handling QueryResult: {str(e)}")
    
    async def get_attack_path_summary(self, summary_parameters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Call the GetAttackPathSummary method and collect streaming results."""
        if not self.is_connected:
            raise ConnectionError("Not connected to SignalR hub")
        
        # Clear previous results
        self.streaming_results = []
        self.current_summary_id = summary_parameters.get("SummaryId", str(uuid.uuid4()))
        
        try:
            # Invoke the GetAttackPathSummary method
            await self.connection.send("GetAttackPathSummary", [summary_parameters])
            
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
                        break
                else:
                    stable_count = 0
                    last_result_count = current_count
            
            return self.streaming_results.copy()
            
        except Exception as e:
            raise Exception(f"Failed to get attack path summary: {str(e)}")


class AttackPathsMCPServer:
    """Encapsulated MCP server for Attack Path Analysis operations using SignalR."""
    
    def __init__(self, raptor_token: Optional[str] = None, raptor_url: Optional[str] = None):
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
        self._hub_url = f"{self._raptor_url}/api/hub"  # Typical SignalR hub endpoint
        
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
            attack_path_data: Dict[str, Any],
            summary_id: Optional[str] = None,
            force_refresh: bool = False
        ) -> Dict[str, Any]:
            """
            **Role**: Performs comprehensive structured analysis of a specific attack path with AI-powered summaries
            
            This tool connects to the SignalR hub to stream real-time LLM-generated summaries of attack path data.
            It provides detailed, human-readable analysis of complex attack paths to help security analysts
            understand the implications and steps involved in potential security breaches.
            
            **Inputs**:
            - attack_path_data: Complete attack path data structure containing:
              - Id: Numeric identifier of the attack path
              - Target: VertexProperties of the target node (id, type, label, domain, zone, etc.)
              - Source: VertexProperties of the source node  
              - Cost: Double representing the attack cost/difficulty
              - RiskScore: Double representing the risk assessment
              - Path: GraphData containing the complete attack path with:
                - nodes: Collection of VertexProperties for all objects in the path
                - links: Collection of EdgeProperties for all relationships in the path
              - Blowout: String indicating if path analysis was terminated due to complexity
            - summary_id: Optional unique identifier for the summary request. If not provided, one will be generated.
            - force_refresh: Boolean flag to force a refresh of the summary even if cached. Default False.
            
            **Outputs**:
            - streaming_summary: Complete LLM-generated summary content assembled from streaming responses
            - summary_metadata: Metadata about the summary including timing and message count
            - attack_path_info: Processed information about the attack path being analyzed
            - analysis_completed: Boolean indicating if the analysis completed successfully
            """
            
            if not SIGNALR_AVAILABLE:
                return {
                    "error": "SignalR functionality not available. Please install signalrcore: pip install signalrcore",
                    "streaming_summary": None,
                    "summary_metadata": None,
                    "attack_path_info": None,
                    "analysis_completed": False
                }
            
            # Validate required attack path data
            if not attack_path_data:
                return {
                    "error": "attack_path_data is required",
                    "streaming_summary": None,
                    "summary_metadata": None,
                    "attack_path_info": None,
                    "analysis_completed": False
                }
            
            # Generate summary ID if not provided
            if not summary_id:
                summary_id = str(uuid.uuid4())
            
            # Build the SummaryParameters structure
            summary_parameters = {
                "SummaryId": summary_id,
                "SummaryAttackPath": attack_path_data,
                "ForceRefresh": force_refresh
            }
            
            try:
                # Get SignalR client and connect
                signalr_client = await self._get_signalr_client()
                
                # Request attack path summary
                streaming_results = await signalr_client.get_attack_path_summary(summary_parameters)
                
                # Process the streaming results
                summary_content = self._process_streaming_results(streaming_results)
                
                # Extract attack path information for context
                attack_path_info = self._extract_attack_path_info(attack_path_data)
                
                # Build metadata
                summary_metadata = {
                    "summary_id": summary_id,
                    "timestamp": datetime.datetime.now().isoformat(),
                    "message_count": len(streaming_results),
                    "force_refresh": force_refresh,
                    "streaming_completed": True
                }
                
                return {
                    "streaming_summary": summary_content,
                    "summary_metadata": summary_metadata,
                    "attack_path_info": attack_path_info,
                    "analysis_completed": True
                }
                
            except Exception as e:
                return {
                    "error": f"Failed to get attack path summary: {str(e)}",
                    "streaming_summary": None,
                    "summary_metadata": {
                        "summary_id": summary_id,
                        "timestamp": datetime.datetime.now().isoformat(),
                        "error": str(e),
                        "streaming_completed": False
                    },
                    "attack_path_info": self._extract_attack_path_info(attack_path_data) if attack_path_data else None,
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
    parser.add_argument("-port", type=int, default=8001, help="Port to bind the server to (default: 8001)")
    parser.add_argument("-path", type=str, default="/mcp", help="URL path for the MCP endpoint (default: /mcp)")
    args = parser.parse_args()

    # Create and run the server with optional token, url, host, port, and path override
    server = AttackPathsMCPServer(raptor_token=args.raptor_token, raptor_url=args.raptor_url)
    server.run(transport='streamable-http', host=args.host, port=args.port, path=args.path)
