from typing import Dict, Any, List, Optional
import os
from fastmcp import FastMCP
import datetime
from raptor_utils import RaptorAPIClient, VectorStoreManager, TokenCounter
from raptor_utils import find_object, get_node_oid_by_label
from raptor_utils import calculate_object_stats, calculate_node_stats
import sys
import argparse


class RaptorMCPServer:
    """Encapsulated MCP server for Raptor API operations."""
    def __init__(self, raptor_token: Optional[str] = None, raptor_url: Optional[str] = None):
        name = "Identity Graph query server"
        desc ="""
            This server provides comprehensive tools for identity graph analysis and attack path discovery 
            through the Raptor API.

            YOU MUST USE THE THINK TOOL IF YOUR REASONING INVOLVES TWO OR MORE TOOL CALLS. 
            YOU MUST ALSO USE THE THINK TOOL BEFORE GENERATING THE FINAL ANSWER.

            NEVER USE THE SAME TOOL WITH THE SAME PARAMETERS TWICE IN A SINGLE QUERY, EXCEPT FOR THE THINK TOOL.

            DON'T DO TOO MUCH VERIFICATIONS, TRUST THE TOOLS.
            DON'T MAKE MORE THAN 10 TOOLS CALLS FOR ONE QUERY.
            """
        self.mcp = FastMCP(
                    name = name,
                    instructions = desc
                    )
        self._raptor_url = raptor_url
        # Use direct token retrieval: from argument or environment
        self._raptor_token = raptor_token or os.getenv("RAPTOR_TOKEN")
        self._api_client = self._initialize_api_client()
        self._vectorstore_manager = VectorStoreManager()
        self._token_counter = TokenCounter()
        self._register_tools()
    
    def _initialize_api_client(self) -> RaptorAPIClient:
        """Initialize the API client with configuration."""
        base_url = self._raptor_url
        token = self._raptor_token
        return RaptorAPIClient(base_url, token)
    
    def _register_tools(self) -> None:
        """Register all MCP tools."""
        # Register API tools
        self._register_api_tools()
        # Register memory tools
        self._register_memory_tools()
        # Register thinking tools
        self._register_thinking_tools()
    
    def _register_api_tools(self) -> None:
        """Register all Raptor API tools."""

        #######################
        ## Health and Environment
        
        @self.mcp.tool()
        async def ping() -> Dict[str, Any]:
            """
            **Role**: Simple health check endpoint to verify API responsiveness and service availability  
            **Inputs**: None  
            **Outputs**:  
            - Status: HTTP status code (200 for success)
            """   
            return self._api_client.call("Ping", {})
        
        @self.mcp.tool()
        async def get_environment_metadata() -> Dict[str, Any]:
            """
            **Role**: Retrieves comprehensive environment metadata including synchronization settings, security zones, UI display mappings, and available custom collector configurations for the identity environment  
            **Inputs**: None  
            **Outputs**:  
            - If no identity data exists:
                - SyncSettings: default synchronization configuration
                - DisplayMappings: UI field display mapping configurations
                - CustomCollectorConfigurations: available custom data collector settings
            - If identity data exists:
                - SyncSettings: current environment sync configuration and metadata
                - ZoneList: dictionary of security zones with their properties (ID, name, criticality, color)
                - DisplayMappings: UI field mapping configurations for data presentation
                - CustomCollectorConfigurations: configured custom collector settings
            """
            return self._api_client.call("GetEnvironmentMetadata", {})
        
        @self.mcp.tool()
        async def get_sync_progress() -> Dict[str, Any]:
            """
            **Role**: Returns real-time status and progress information for ongoing or recent data synchronization operations with external identity systems  
            **Inputs**: None  
            **Outputs**:  
            - SyncProgress: dictionary of collector-specific statistics with:
              - Processing counts (objects collected, processed, errors)
              - Timing information (start time, duration, completion status)
              - Performance metrics for each data source
            - FinalizingSync: boolean indicating if sync is in final processing stage
            - DeviceAuthenticationCode: current device authentication details for Azure integration including:
              - User code for device authentication flow
              - Verification URL and expiration details
            """
            return self._api_client.call("GetSyncProgress", {})
        

        #######################
        ## Graph Management
        
        @self.mcp.tool()
        async def reset_graph() -> Dict[str, Any]:
            """
            **Role**: Performs complete reset of the identity graph database, removing all collected identity data, relationships, and analysis results  
            **Inputs**: None  
            **Outputs**:  
            - Status: HTTP status code (200 for successful data clearance)
            """
            return self._api_client.call("ResetGraph", {})
        
        @self.mcp.tool()
        async def export_graph(
            num_layers: int = 1,
            domain_filter: Optional[List[str]] = None,
            zone_filter: Optional[List[str]] = None,
            show_whole_graph: bool = False,
            expansion_node_id: Optional[str] = None
        ) -> Dict[str, Any]:
            """
            **Role**: Exports filtered identity graph data to a file for external analysis, backup, or integration with other security tools  
            **Inputs**:  
            - NumLayers: Number of relationship layers to include in the export. Controls the depth of relationships to be included in the exported data. A value of 1 includes only direct relationships, while higher values include more distant relationships.
            - DomainFilter: List of Active Directory domain names to include in the export. When provided, only objects from these domains will be included. If set to None, objects from all domains will be included.
            - ZoneFilter: List of security zone IDs to include in the export. When provided, only objects from these security zones will be included. If set to None, objects from all security zones will be included.
            - ShowWholeGraph: Boolean flag that determines whether to export the complete graph regardless of other filters. When set to True, all other filters are ignored and the entire graph is exported. Default is False.
            - ExpansionNodeId: Specific node ID for focused expansion queries. When provided, the export will focus on this node and its relationships according to the specified number of layers.
            **Outputs**:  
            - ExportComplete: boolean indicating successful export
            - ExportPath: file system path to the exported graph data file
            """
            params = self._build_graph_params(num_layers, domain_filter, zone_filter, show_whole_graph, expansion_node_id)
            return self._api_client.call("ExportGraph", params)
        
        @self.mcp.tool()
        async def query_graph(
            num_layers: int = 1,
            domain_filter: Optional[List[str]] = None,
            zone_filter: Optional[List[str]] = None,
            show_whole_graph: bool = False,
            expansion_node_id: Optional[str] = None
        ) -> Dict[str, Any]:
            """
            **Role**: Performs flexible querying of the identity graph with advanced filtering options to retrieve specific subsets of identity data and relationships  
            **Inputs**:
            - NumLayers: Depth of graph traversal for relationship discovery. Controls how many relationship hops to include in the query results. A value of 1 includes only direct relationships, while higher values include more distant relationships.
            - DomainFilter: List of Active Directory domain names to restrict the query scope. When provided, only objects from these domains will be included in the results. If set to None, objects from all domains will be included.
            - ZoneFilter: List of security zone IDs to limit query results. When provided, only objects from these security zones will be included in the results. If set to None, objects from all security zones will be included.
            - ShowWholeGraph: Boolean flag that determines whether to return complete graph data ignoring other filters. When set to True, all other filters are ignored and the entire graph is returned. Default is False.
            - ExpansionNodeId: Specific node ID for focused expansion from a particular identity object. When provided, the query will focus on this node and its relationships according to the specified number of layers.
            **Outputs**:  
            - For general queries:
              - Data: GraphData object with nodes and links representing identity objects and relationships
              - NodeCount: total number of identity objects in result set
              - LinkCount: total number of relationships in result set
              - _token_info: metadata about token usage and truncation (if applicable)
            - For expansion queries:
              - Same structure as above but focused on specific node expansion
            """
            params = self._build_graph_params(num_layers, domain_filter, zone_filter, show_whole_graph, expansion_node_id)
            
            # Make the API call
            response = self._api_client.call("QueryGraph", params)
            
            # Apply token counting and truncation if needed
            if "response" in response and "Data" in response.get("response", {}):
                response = self._token_counter.truncate_graph_query(response)
            
            return response
        
        @self.mcp.tool()
        async def update_graph(
            zone_id: Optional[str] = None,
            nodes: Optional[List[str]] = None
        ) -> Dict[str, Any]:
            """
            **Role**: Updates security zone assignments for specific identity objects in the graph, allowing administrators to classify objects into different security tiers  
            **Inputs**:
            - ZoneID: Target security zone identifier where nodes should be assigned. This is the unique identifier of the security zone to which the specified nodes will be moved.
            - Nodes: List of node identifiers (OIDs) to move to the specified zone. Each identifier represents a specific identity object in the graph that will be assigned to the target security zone.
            **Outputs**:  
            - Indicates UI clients should refresh their data to reflect zone changes
            """
            params = {}
            if zone_id is not None:
                params["ZoneID"] = zone_id
            if nodes is not None:
                params["Nodes"] = nodes
            return self._api_client.call("UpdateGraph", params)



        ########################
        ## Zone Management

        @self.mcp.tool()
        async def get_zones() -> Dict[str, Any]:
            """
            **Role**: Retrieves complete list of all defined security zones in the environment for access control and risk segmentation  
            **Inputs**: None  
            **Outputs**:  
            - ZoneList: dictionary mapping zone IDs to ZoneProperties objects with:
                - Zone name and display properties
                - Criticality level (security importance rating)
                - Color coding for UI representation
                - Member count and configuration details
            """
            return self._api_client.call("GetZones", {})
        
        @self.mcp.tool()
        async def get_zone_isolation_scores(
            domain_filter: Optional[List[str]] = None,
            zone_filter: Optional[List[str]] = None
        ) -> Dict[str, Any]:
            """
            **Role**: Calculates security isolation scores between zones to measure the effectiveness of security boundaries and identify potential cross-zone attack vectors  
            **Inputs**:
            - ZoneFilter: List of zone IDs to calculate isolation scores for. When provided, isolation scores will be calculated only for these zones. If set to None or an empty array, scores will be calculated for all zones.
            - DomainFilter: List of domain names to include in isolation calculations. When provided, only objects from these domains will be considered in the isolation score calculations. If set to None, objects from all domains will be included.
            **Outputs**:  
            - Stream of objects (one per zone pair) containing:
              - ZoneIsolationDetails: detailed isolation metrics including:
                - Source and target zone information
                - Isolation score (0.0 = no isolation, 1.0 = complete isolation)
                - Attack path count between zones
                - Risk assessment metrics
            """
            params = {}
            if domain_filter is not None:
                params["DomainFilter"] = domain_filter
            if zone_filter is not None:
                params["ZoneFilter"] = zone_filter
            return self._api_client.call("GetZoneIsolationScores", params)
        
        @self.mcp.tool()
        async def create_zone(
            zone_id: str = "",
            zone_name: str = "",
            criticality: float = 1.0,
            colour: str = ""
        ) -> Dict[str, Any]:
            """
            **Role**: Creates a new security zone with specified properties for logical grouping and risk classification of identity objects  
            **Inputs**:
            - ZoneId: Unique identifier for the new zone. This identifier must be unique across the entire environment and will be used to reference this zone in other operations.
            - ZoneName: Human-readable display name for the zone. This name will be shown in the user interface and reports to identify the zone.
            - Criticality: Security criticality level as a float value. Default is 1.0. Higher values indicate greater security importance. This value affects risk calculations and security assessments.
            - Colour: Hexadecimal color code for UI representation and visual identification. This color will be used to represent the zone in graphical interfaces and reports.
            **Outputs**:  
            - Indicates clients should refresh zone list to display new zone
            """
            params = self._build_zone_params(zone_id, zone_name, criticality, colour)
            return self._api_client.call("CreateZone", params)
        
        @self.mcp.tool()
        async def remove_zone(
            zone_id: str = ""
        ) -> Dict[str, Any]:
            """
            **Role**: Permanently deletes an existing security zone and removes zone assignments from all member objects  
            **Inputs**: 
            - ZoneId: Unique identifier of the zone to be deleted. This is the primary identifier used to determine which zone should be removed from the system.
            **Outputs**:  
            - Indicates clients should refresh both zone list and graph data due to membership changes
            """
            params = {}
            if zone_id:
                params["ZoneId"] = zone_id
            return self._api_client.call("RemoveZone", params)
        
        @self.mcp.tool()
        async def edit_zone(
            zone_id: str = "",
            zone_name: str = "",
            criticality: float = 1.0,
            colour: str = ""
        ) -> Dict[str, Any]:
            """
            **Role**: Modifies properties of an existing security zone including display name, criticality level, and visual appearance  
            **Inputs**: 
            - ZoneId: Unique identifier of the zone to be modified. This identifier specifies which zone will have its properties updated.
            - ZoneName: New human-readable display name for the zone. This will replace the current name shown in the user interface and reports.
            - Criticality: New security criticality level as a float value. Default is 1.0. Higher values indicate greater security importance. This value affects risk calculations.
            - Colour: New hexadecimal color code for UI representation. This color will replace the current color used to represent the zone in graphical interfaces.
            **Outputs**:  
            - Indicates clients should refresh zone list to reflect property changes
            """
            params = self._build_zone_params(zone_id, zone_name, criticality, colour)
            return self._api_client.call("EditZone", params)
        
        @self.mcp.tool()
        async def get_zone_data(
            zone_id: str = ""
        ) -> Dict[str, Any]:
            """
            **Role**: Retrieves complete list of all identity objects currently assigned to a specific security zone  
            **Inputs**: 
            - ZoneId: Unique identifier of the zone for which to retrieve member objects. This identifier specifies which zone's data will be returned.
            **Outputs**:  
            - ZoneData: list of VertexProperties objects for all zone members including:
              - Object identifiers and names
              - Object types and security attributes  
              - Domain membership and organizational details
              - Security-relevant properties and timestamps
            """
            params = {}
            if zone_id:            params["ZoneId"] = zone_id
            return self._api_client.call("GetZoneData", params)
        
        @self.mcp.tool()
        async def set_initial_tier0(
            tier0_objects: Optional[List[str]] = None
        ) -> Dict[str, Any]:
            """
            **Role**: Designates critical high-privilege identity objects as Tier 0 assets, marking them as the most sensitive security targets requiring special protection  
            **Inputs**:
            - Tier0Objects: List of object identifiers (OIDs) to classify as Tier 0 assets. These are typically high-value security targets such as domain controllers, enterprise admins, and other privileged accounts that require the highest level of protection.
            **Outputs**:  
            - Indicates clients should refresh data to reflect new Tier 0 classifications
            """
            params = {}
            if tier0_objects is not None:
                params["Tier0Objects"] = tier0_objects
            return self._api_client.call("SetInitialTier0", params)
        

        #######################
        ## Data Synchronization
        
        @self.mcp.tool()
        async def sync(
            custom_collectors: Optional[List[Dict[str, Any]]] = None,
            azure_access_tokens: Optional[List[Dict[str, Any]]] = None
        ) -> Dict[str, Any]:
            """
            **Role**: Performs comprehensive data synchronization with external identity systems (Active Directory, Azure AD, custom sources) to collect and update identity graph information  
            **Inputs**:
            - CustomCollectors: List of custom collector configuration objects. Each collector object contains:
              - Name: Identifier string for the collector type that determines which data collection logic to use
              - Configuration: Dictionary of settings specific to this collector instance, containing connection parameters and filtering options
            - AzureAccessTokens: List of Azure authentication token objects for Microsoft Graph API access. Each token object contains:
              - access_token: Valid OAuth2 access token string for authenticating with Azure Graph API
              - refresh_token: Token string used to obtain a new access token when the current one expires
              - expires_in: Token lifetime in seconds before expiration (default: -1 if unknown)
              - origin_header: Optional string specifying the HTTP origin header to include in API requests
              - instance_url: Optional string to override the default Azure API endpoint URL
            **Outputs**:  
            - SyncComplete: boolean indicating successful completion
            - SyncProgress: dictionary of collector statistics with processing counts and timing
            - SyncSettings: updated environment metadata after sync
            - ZoneList: updated security zones after data collection
            """
            params = self._build_sync_params(custom_collectors, azure_access_tokens)
            return self._api_client.call("Sync", params)
        

        #######################
        ## Attack Path Analysis
        
        @self.mcp.tool()
        async def determine_attack_paths(
            domain_filter: Optional[List[str]] = None,
            zone_filter: Optional[List[str]] = None,
            zero_cost_paths: bool = False,
            include_blowout_paths: bool = True,
            return_principals_only: bool = True,
            zero_cost_only: bool = False,
            blowout_paths: int = 250,
            attacker_oid: str = "",
            target_oid: str = ""
        ) -> Dict[str, Any]:
            """
            **Role**: This is the main tool for the attack paths analysis. It calculates and analyzes potential attack paths between specified attackers and targets, identifying security vulnerabilities and privilege escalation routes through the identity infrastructure  
            **Inputs**:
            - BlowoutPaths: Maximum number of attack paths to analyze before stopping the analysis. Default is 250. This limit prevents excessive computation for complex environments with many possible attack paths.
            - AttackerOID: Object identifier string of the starting point for attack simulation. When provided, only attack paths originating from this specific object will be analyzed. If empty, all potential attackers in the environment will be considered.
            - TargetOID: Object identifier string of the attack target. When provided, only attack paths targeting this specific object will be analyzed. If empty, all Tier 0 assets will be considered as potential targets.
            - DomainFilter: List of domain names to include in path calculation. When provided, only objects from these domains will be considered in attack path analysis. If set to None, objects from all domains will be included.
            - ZoneFilter: List of security zone IDs to include in path analysis. When provided, only objects from these security zones will be considered in attack path analysis. If set to None, objects from all zones will be included.
            - ZeroCostPaths: Boolean flag to return ALL zero-cost attack paths. Default is False. When True, all immediate attack vectors with no security barriers will be included in the results.
            - IncludeBlowoutPaths: Boolean flag to include additional path variations when complexity limit is reached. Default is True. When False, only the paths discovered before hitting the complexity limit will be returned.
            - ReturnPrincipalsOnly: Boolean flag to return only paths ending at security principals. Default is True. When False, paths ending at any object type will be included in the results.
            - ZeroCostOnly: Boolean flag to return only zero-cost attack paths among those analyzed. Default is False. When True, only immediate attack vectors will be included in the results.
            **Outputs**:  
            - For general analysis:
              - AttackPaths: list of AttackPathData objects with:
                - Id: unique identifier for the path
                - Target: VertexProperties of the attack target with object details
                - Source: VertexProperties of the attack source with object details  
                - Cost: numeric cost of the attack path (lower = easier)
                - RiskScore: calculated risk score based on criticality and path feasibility
                - Path: GraphData containing detailed path with nodes and relationships
                - Blowout: identifier if path analysis was terminated due to complexity
              - SummariesAvailable: boolean indicating if LLM-generated summaries are available
              - _token_info: metadata about token usage and truncation (if applicable)
            - For zero-cost analysis:
              - ZeroCostAttackPaths: same structure as AttackPaths but focused on immediate attack vectors
            **Note**: Use this tool as the primary method for attack path analysis. The response will automatically be truncated if it exceeds the token limit, keeping only the paths with the highest risk scores.
            """
            params = self._build_attack_path_params(
                domain_filter, zone_filter, zero_cost_paths, include_blowout_paths,
                return_principals_only, zero_cost_only, blowout_paths, attacker_oid, target_oid
            )
            
            # Make the API call
            response = self._api_client.call("DetermineAttackPaths", params)
            
            # Apply token counting and truncation if needed
            # Check for the appropriate field name based on zero_cost_paths parameter
            response_data = response.get("response", {})
            if "response" in response:
                if zero_cost_paths and "ZeroCostAttackPaths" in response_data:
                    response = self._token_counter.truncate_attack_paths_by_risk(response, field_name="ZeroCostAttackPaths")
                elif "AttackPaths" in response_data:
                    response = self._token_counter.truncate_attack_paths_by_risk(response, field_name="AttackPaths")
            
            return response
        
        @self.mcp.tool()
        async def reachability_report(
            domain_filter: Optional[List[str]] = None,
            zone_filter: Optional[List[str]] = None,
            zero_cost_paths: bool = False,
            include_blowout_paths: bool = True,
            return_principals_only: bool = True,
            zero_cost_only: bool = False,
            blowout_paths: int = 250,
            reachability_by_group: bool = False,
        ) -> Dict[str, Any]:
            """
            **Role**: Generates comprehensive reachability analysis showing what assets different objects can access or control within the environment, useful for privilege impact assessment  
            **Inputs**: 
            - DomainFilter: List of domain names to include in reachability analysis. When provided, only objects from these domains will be considered. If set to None, objects from all domains will be included.
            - ZoneFilter: List of security zone IDs to include in reachability analysis. When provided, only objects from these security zones will be considered. If set to None, objects from all zones will be included.
            - ZeroCostPaths: Boolean flag to include all zero-cost (immediate) access paths in the analysis. Default is False. When True, all paths with no security barriers will be included.
            - IncludeBlowoutPaths: Boolean flag to include additional path variations when complexity limit is reached. Default is True. When False, only the paths discovered before hitting the complexity limit will be included.
            - ReturnPrincipalsOnly: Boolean flag to analyze reachability only to security principals. Default is True. When False, reachability to all object types will be analyzed.
            - ZeroCostOnly: Boolean flag to analyze only zero-cost (immediate) access paths. Default is False. When True, only paths with no security barriers will be analyzed.
            - BlowoutPaths: Maximum number of paths to analyze before stopping due to complexity. Default is 250. This prevents excessive computation for complex environments.
            - ReachabilityByGroup: Boolean flag to analyze reachability through group membership relationships. Default is False. When True, group memberships will be considered as potential access paths.
            **Outputs**:  
            - ReachabilityReport: list of ReachabilityResults objects with:
              - NodeId: identifier of source object (attacker) whose reachability is analyzed
              - ObjectProperties: detailed properties of object (name, type, domain, etc.)
              - ReachabilityScore: numeric score indicating ease of access
              - PathCount: number of different paths to reach the object
            - _token_info: metadata about token usage and truncation (if applicable)
            """
            params = self._build_attack_path_params(
                domain_filter, zone_filter, zero_cost_paths, include_blowout_paths,
                return_principals_only, zero_cost_only, blowout_paths, "", ""
            )
            if reachability_by_group is not None:
                params["ReachabilityByGroup"] = reachability_by_group
            
            # Make the API call
            response = self._api_client.call("ReachabilityReport", params)
            
            # Apply token counting and truncation if needed
            if "response" in response and "ReachabilityReport" in response.get("response", {}):
                response = self._token_counter.truncate_reachability_report_by_risk(response)
            
            return response
        
        @self.mcp.tool()
        async def node_reachability(
            domain_filter: Optional[List[str]] = None,
            zone_filter: Optional[List[str]] = None,
            zero_cost_paths: bool = False,
            include_blowout_paths: bool = True,
            return_principals_only: bool = True,
            zero_cost_only: bool = False,
            blowout_paths: int = 250,
            attacker_oid: str = "",
            target_oid: str = "",
            reachability_by_group: bool = False,
            reachability_node: str = "",
        ) -> Dict[str, Any]:
            """
            **Role**: Analyzes and returns specific attack paths showing how a particular node can reach high-value targets, providing detailed path information for security assessment  
            **Inputs**:
            - DomainFilter: List of domain names to include in reachability analysis. When provided, only objects from these domains will be considered. If set to None, objects from all domains will be included.
            - ZoneFilter: List of security zone IDs to include in reachability analysis. When provided, only objects from these security zones will be considered. If set to None, objects from all zones will be included.
            - ZeroCostPaths: Boolean flag to include all zero-cost (immediate) access paths in the analysis. Default is False. When True, all paths with no security barriers will be included.
            - IncludeBlowoutPaths: Boolean flag to include additional path variations when complexity limit is reached. Default is True. When False, only the paths discovered before hitting the complexity limit will be included.
            - ReturnPrincipalsOnly: Boolean flag to analyze reachability only to security principals. Default is True. When False, reachability to all object types will be analyzed.
            - ZeroCostOnly: Boolean flag to analyze only zero-cost (immediate) access paths. Default is False. When True, only paths with no security barriers will be analyzed.
            - BlowoutPaths: Maximum number of paths to analyze before stopping due to complexity. Default is 250. This prevents excessive computation for complex environments.
            - AttackerOID: Object identifier string of the starting point for attack simulation. When provided, only attack paths originating from this specific object will be analyzed. If empty, all potential attackers in the environment will be considered.
            - TargetOID: Object identifier string of the attack target. When provided, only attack paths targeting this specific object will be analyzed. If empty, all Tier 0 assets will be considered as potential targets.
            - ReachabilityByGroup: Boolean flag to analyze reachability through group membership relationships. Default is False. When True, group memberships will be considered as potential access paths.
            - ReachabilityNode: Specific node identifier for which to analyze reachability. This parameter specifies the node whose reachability to other objects will be analyzed.
            **Outputs**:  
            - AttackPaths: detailed list of AttackPathData showing specific paths from the node to reachable targets
            - SummariesAvailable: boolean indicating availability of AI-generated path summaries for easier analysis
            - _token_info: metadata about token usage and truncation (if applicable)
            """
            params = self._build_attack_path_params(
                domain_filter, zone_filter, zero_cost_paths, include_blowout_paths,
                return_principals_only, zero_cost_only, blowout_paths, attacker_oid, target_oid
            )
            if reachability_by_group is not None:
                params["ReachabilityByGroup"] = reachability_by_group
            if reachability_node:
                params["ReachabilityNode"] = reachability_node
            
            # Make the API call
            response = self._api_client.call("NodeReachability", params)
            
            # Apply token counting and truncation if needed
            if "response" in response and "AttackPaths" in response.get("response", {}):
                response = self._token_counter.truncate_attack_paths_by_risk(response, field_name="AttackPaths")
            
            return response
        
        @self.mcp.tool()
        async def find_risk_reduction(
            domain_filter: Optional[List[str]] = None,
            zone_filter: Optional[List[str]] = None,
            zero_cost_paths: bool = False,
            include_blowout_paths: bool = True,
            return_principals_only: bool = True,
            zero_cost_only: bool = False,
            blowout_paths: int = 250,
            attacker_oid: str = "",
            target_oid: str = "",
            by_node: bool = False,
            by_right: bool = False,
            zone_id: str = ""
        ) -> Dict[str, Any]:
            """
            **Role**: Identifies specific security measures and recommendations to reduce risk exposure by analyzing which nodes or permissions, if modified, would most effectively break attack paths  
            **Inputs**:
            - DomainFilter: List of domain names to include in risk reduction analysis. When provided, only objects from these domains will be considered. If set to None, objects from all domains will be included.
            - ZoneFilter: List of security zone IDs to include in risk reduction analysis. When provided, only objects from these security zones will be considered. If set to None, objects from all zones will be included.
            - ZeroCostPaths: Boolean flag to include all zero-cost (immediate) attack paths in the analysis. Default is False. When True, all paths with no security barriers will be included.
            - IncludeBlowoutPaths: Boolean flag to include additional path variations when complexity limit is reached. Default is True. When False, only the paths discovered before hitting the complexity limit will be included.
            - ReturnPrincipalsOnly: Boolean flag to analyze only paths ending at security principals. Default is True. When False, paths ending at any object type will be analyzed.
            - ZeroCostOnly: Boolean flag to analyze only zero-cost attack paths. Default is False. When True, only immediate attack vectors will be analyzed.
            - BlowoutPaths: Maximum number of paths to analyze before stopping due to complexity. Default is 250. This prevents excessive computation for complex environments.
            - AttackerOID: Object identifier string of the starting point for attack simulation. When provided, only attack paths originating from this specific object will be analyzed. If empty, all potential attackers in the environment will be considered.
            - TargetOID: Object identifier string of the attack target. When provided, only attack paths targeting this specific object will be analyzed. If empty, all Tier 0 assets will be considered as potential targets.
            - ByNode: Boolean flag to analyze risk reduction by removing or protecting individual nodes. Default is False. When True, the analysis will identify which nodes, if protected, would most effectively reduce risk.
            - ByRight: Boolean flag to analyze risk reduction by removing specific permissions or rights. Default is False. When True, the analysis will identify which permissions, if removed, would most effectively reduce risk.
            - ZoneId: Specific security zone identifier to focus risk reduction analysis on. When provided, the analysis will focus on reducing risk specifically for this security zone.
            **Outputs**:  
            - NodeRiskReduction: list of nodes whose protection would reduce risk most
            - RightRiskReduction: list of permissions whose removal would reduce risk most
            - Impact metrics showing attack path reduction for each recommendation
            - _token_info: metadata about token usage and truncation (if applicable)
            """
            params = self._build_attack_path_params(
                domain_filter, zone_filter, zero_cost_paths, include_blowout_paths,
                return_principals_only, zero_cost_only, blowout_paths, attacker_oid, target_oid
            )
            if by_node is not None:
                params["ByNode"] = by_node
            if by_right is not None:
                params["ByRight"] = by_right
            if zone_id:
                params["ZoneId"] = zone_id
            # Make the API call
            response = self._api_client.call("FindRiskReduction", params)
            
            # Apply token counting and truncation if needed
            if "response" in response and ("NodeRiskReduction" in response.get("response", {}) or "RightRiskReduction" in response.get("response", {})):
                response = self._token_counter.truncate_risk_reduction_by_risk(response)
            
            return response
        
        @self.mcp.tool()
        async def export_attack_paths(
            domain_filter: Optional[List[str]] = None,
            zone_filter: Optional[List[str]] = None,
            zero_cost_paths: bool = False,
            include_blowout_paths: bool = True,
            return_principals_only: bool = True,
            zero_cost_only: bool = False,
            blowout_paths: int = 250,
            attacker_oid: str = "",
            target_oid: str = ""
        ) -> Dict[str, Any]:
            """
            **Role**: Exports calculated attack path data to external files for offline analysis, reporting, or integration with other security tools and SIEM systems  
            **Inputs**:
            - DomainFilter: List of domain names to include in attack path export. When provided, only objects from these domains will be included in the exported paths. If set to None, objects from all domains will be included.
            - ZoneFilter: List of security zone IDs to include in attack path export. When provided, only objects from these security zones will be included in the exported paths. If set to None, objects from all zones will be included.
            - ZeroCostPaths: Boolean flag to include all zero-cost (immediate) attack paths in the export. Default is False. When True, all paths with no security barriers will be included.
            - IncludeBlowoutPaths: Boolean flag to include additional path variations when complexity limit is reached. Default is True. When False, only the paths discovered before hitting the complexity limit will be exported.
            - ReturnPrincipalsOnly: Boolean flag to export only paths ending at security principals. Default is True. When False, paths ending at any object type will be included in the export.
            - ZeroCostOnly: Boolean flag to export only zero-cost attack paths. Default is False. When True, only immediate attack vectors will be exported.
            - BlowoutPaths: Maximum number of paths to analyze before stopping due to complexity. Default is 250. This prevents excessive computation for complex environments.
            - AttackerOID: Object identifier string of the starting point for attack simulation. When provided, only attack paths originating from this specific object will be exported. If empty, all potential attackers in the environment will be considered.
            - TargetOID: Object identifier string of the attack target. When provided, only attack paths targeting this specific object will be exported. If empty, all Tier 0 assets will be considered as potential targets.
            **Outputs**:  
            - ExportComplete: boolean indicating successful export completion
            - ExportPath: file system path to exported attack path data in structured format
            """
            params = self._build_attack_path_params(
                domain_filter, zone_filter, zero_cost_paths, include_blowout_paths,
                return_principals_only, zero_cost_only, blowout_paths, attacker_oid, target_oid
            )
            return self._api_client.call("ExportAttackPaths", params)
        
        @self.mcp.tool()
        async def find_and_classify_zero_cost_paths(
            domain_filter: Optional[List[str]] = None,
            zone_filter: Optional[List[str]] = None,
            zero_cost_paths: bool = False,
            include_blowout_paths: bool = True,
            return_principals_only: bool = True,
            zero_cost_only: bool = False,
            blowout_paths: int = 250,
            attacker_oid: str = "",
            target_oid: str = ""
        ) -> Dict[str, Any]:
            """
            **Role**: Identifies zero-cost (immediate) attack paths and automatically classifies all objects in these paths as Tier 0 risks, helping administrators quickly identify critical security gaps  
            **Inputs**:
            - DomainFilter: List of domain names to include in zero-cost path analysis. When provided, only objects from these domains will be considered. If set to None, objects from all domains will be included.
            - ZoneFilter: List of security zone IDs to include in zero-cost path analysis. When provided, only objects from these security zones will be considered. If set to None, objects from all zones will be included.
            - ZeroCostPaths: Boolean flag to include all zero-cost (immediate) attack paths in the analysis. Default is False. When True, all paths with no security barriers will be included.
            - IncludeBlowoutPaths: Boolean flag to include additional path variations when complexity limit is reached. Default is True. When False, only the paths discovered before hitting the complexity limit will be analyzed.
            - ReturnPrincipalsOnly: Boolean flag to analyze only paths ending at security principals. Default is True. When False, paths ending at any object type will be analyzed.
            - ZeroCostOnly: Boolean flag to analyze only zero-cost attack paths. Default is False. When True, only immediate attack vectors will be analyzed.
            - BlowoutPaths: Maximum number of paths to analyze before stopping due to complexity. Default is 250. This prevents excessive computation for complex environments.
            - AttackerOID: Object identifier string of the starting point for attack simulation. When provided, only attack paths originating from this specific object will be analyzed. If empty, all potential attackers in the environment will be considered.
            - TargetOID: Object identifier string of the attack target. When provided, only attack paths targeting this specific object will be analyzed. If empty, all Tier 0 assets will be considered as potential targets.
            **Outputs**:  
            - Indicates clients should refresh data to reflect new Tier 0 classifications from zero-cost path analysis
            """
            params = self._build_attack_path_params(
                domain_filter, zone_filter, zero_cost_paths, include_blowout_paths,
                return_principals_only, zero_cost_only, blowout_paths, attacker_oid, target_oid
            )
            return self._api_client.call("FindAndClassifyZeroCostPaths", params)

        ########################
        ## Object Queries

        @self.mcp.tool()
        async def query_object_by_oid(
            OID: Optional[str] = None
        ) -> Dict[str, Any]:
            """
            **Role**: Retrieves identity object information by filtering all objects based on the Object Identifier (OID). The object is retieved from Protobuff.
            **Inputs**:
            - OID: Unique object identifier string to search for. This is typically an Active Directory ObjectGUID or Azure ObjectId that uniquely identifies the target object in the identity system.
            **Outputs**:
            - If object found: Object information with incoming/outgoing relationships, properties, and security attributes
            - If object not found: Error message indicating the object was not found
            """
            # Get all objects from the API using QueryAll
            all_objects_response = self._api_client.call("QueryAll", {})
            if "error" in all_objects_response:
                return {
                    "error": f"Failed to retrieve all objects: {all_objects_response['error']}",
                    "object": None
                }
            objects = all_objects_response.get("response", [])
            return find_object(objects, OID, "oid")
        
        @self.mcp.tool()
        async def query_node_by_oid(
            oid: Optional[str] = None
        ) -> Dict[str, Any]:
            """
            **Role**: Retrieves detailed information for multiple identity objects simultaneously using their Object Identifiers, enabling efficient batch queries.
            The objects are retieved from Trinity DataBase.
            **Inputs**:
            - OID: Unique object identifier string (Active Directory ObjectGUID or Azure ObjectId) of the target object to query. This identifier uniquely identifies the object in the identity system database.
            **Outputs**:  
            - QueryByOIDResult: QueryData object with complete object information including:
              - Object properties (name, type, domain, security attributes)
              - Group memberships and nested relationships  
              - Permissions and access rights
              - Zone classification and security metadata
            """
            params = {}
            if oid is not None:
                params["OID"] = oid
            return self._api_client.call("QueryByOID", params)
        
        @self.mcp.tool()
        async def query_object_by_label(
            label: Optional[str] = None
        ) -> Dict[str, Any]:
            """
            **Role**: Retrieves identity object information by filtering all objects based on the label. The object is retieved from Protobuff.
            **Inputs**:
            - label: Human-readable name or label string of the object to search for. This is typically the display name of the identity object such as a username, group name, or computer name.
            **Outputs**:
            - If object found: Object information with incoming/outgoing relationships, properties, and security attributes
            - If object not found: Error message indicating the object was not found

            **Note**: USE THIS TOOL ONLY WHEN OID IS NOT AVAILABLE. If OID is known, use `query_object_by_oid` instead.
            """
            # Get all objects from the API using QueryAll
            all_objects_response = self._api_client.call("QueryAll", {})
            if "error" in all_objects_response:
                return {
                    "error": f"Failed to retrieve all objects: {all_objects_response['error']}",
                    "object": None
                }
            objects = all_objects_response.get("response", [])
            return find_object(objects, label, "label")
            
        @self.mcp.tool()
        async def query_node_by_label(
            node_label: Optional[str] = None
        ) -> Dict[str, Any]:
            """
            **Role**: Retrieves detailed information about a specific identity object by filtering all nodes based on label field. The objects are retieved from Trinity DataBase.
            **Inputs**:
            - node_label: Human-readable name or label string of the node to search for. This is typically the display name of the identity object such as a username, group name, or computer name in the graph database.
            **Outputs**:
            - If node found: Complete node information including all properties (id, type, label, domain, zone, oid, etc.)
            - If node not found: Error message indicating the node was not found

            **Note**: USE THIS TOOL ONLY WHEN OID IS NOT AVAILABLE. If OID is known, use `query_node_by_oid` instead.
            """
            # 1. Call QueryAllNodes
            all_nodes_response = self._api_client.call("QueryAllNodes", {})
            if "error" in all_nodes_response:
                return {
                    "error": f"Failed to retrieve all nodes: {all_nodes_response['error']}",
                    "node": None
                }
            response_data = all_nodes_response.get("response", {})
            nodes = response_data.get("Data", {}).get("nodes", [])
            # 2. Use helper to get OID
            oid_result = get_node_oid_by_label(nodes, node_label)
            if not oid_result.get("success"):
                return oid_result
            oid = oid_result["oid"]
            # 3. Call QueryByOID with the found OID
            query_oid_response = self._api_client.call("QueryByOID", {"OID": oid})
            return query_oid_response
        
        @self.mcp.tool()
        async def get_object_stats() -> Dict[str, Any]:
            """
            **Role**: Analyzes object data from all repository types in the system and returns comprehensive statistics about the identity environment. The objects are retieved from Protobuff.  
            **Inputs**: None
            **Outputs**:  
            - Comprehensive object statistics including:
              - total_object_count: Total number of objects in the system
              - objectclass_distribution: Count of objects by class (user, group, computer, etc.)
              - domain_distribution: Count of objects by domain
              - admin_objects: Statistics on administrative objects (admincount=1)
              - object_age: Statistics on object creation dates
              - relationship_statistics: Analysis of incoming and outgoing relationships
              - timestamp_analysis: Analysis of whenchanged and lastlogon timestamps
              - security_metrics: Security-relevant statistics from object properties
            """
            # Get all objects from the API
            api_result = self._api_client.call("QueryAll", {})
            
            # The API returns a list of objects in api_result["response"]
            objects = api_result.get("response", [])
            
            if not objects:
                return {
                    "error": "No objects found in the system",
                    "total_object_count": 0
                }
            
            # Use utility function for stats calculation
            return calculate_object_stats(objects)
        
        @self.mcp.tool()
        async def get_node_stats() -> Dict[str, Any]:
            """
            **Role**: Analyzes node data from the graph database and returns comprehensive statistics about the identity environment. The nodes are retieved from Trinity DataBase.  
            **Inputs**: None
            **Outputs**:  
            - Comprehensive node statistics including:
              - total_node_count: Total number of nodes in the graph
              - type_distribution: Count of nodes by type (user, group, computer, container, etc.)
              - domain_distribution: Count of nodes by domain
              - zone_distribution: Count of nodes by security zone
              - account_status: Statistics on account status (enabled, disabled, etc.)
              - password_age: Statistics on password age (never set, recent, old)
              - edge_statistics: Analysis of relationship edges between nodes
              - timestamp_analysis: Analysis of whenchanged and lastlogon timestamps
              - security_metrics: Security-relevant statistics from node properties
            """
            # Get all nodes from the API
            api_result = self._api_client.call("QueryAllNodes", {})
            
            # The API returns nodes in api_result["response"]["Data"]["nodes"]
            nodes = api_result.get("response", {}).get("Data", {}).get("nodes", [])
            
            if not nodes:
                return {
                    "error": "No nodes found in the graph database",
                    "total_node_count": 0
                }
            
            # Use utility function for stats calculation
            return calculate_node_stats(nodes)       
        
    
    def _register_memory_tools(self) -> None:
        """Register memory management tools."""
        
        @self.mcp.tool()
        async def save_memory(
            user_query: str,
            agent_response: str,
            api_calls: Optional[List[Dict[str, Any]]] = None
        ) -> Dict[str, Any]:
            """
            **Role**: Saves a conversation exchange to long-term memory for future reference and to improve response quality for similar queries
            **Inputs**:
            - user_query: Text string containing the original question or request from the user that should be saved to memory
            - agent_response: Text string containing the complete response provided by the agent that should be associated with the user query
            - api_calls: Optional list of API call records made during the interaction. Each record is a dictionary containing details about the API calls that were executed to generate the response
            **Outputs**:
            - Success status indicating whether the memory was saved successfully
            - Message providing additional details about the operation result
            """
            try:
                # Call the synchronous save operation directly
                result = self._vectorstore_manager.save(
                    user_query, 
                    agent_response, 
                    api_calls
                )
                
                if isinstance(result, bool) and result:
                    return {
                        "success": True,
                        "message": "Memory saved successfully"
                    }
                else:
                    return {
                        "success": False,
                        "message": result if isinstance(result, str) else "Failed to save memory"
                    }
            except Exception as e:
                return {
                    "success": False,
                    "message": f"Error saving memory: {str(e)}"
                }
        
        @self.mcp.tool()
        async def retrieve_memory(
            query: str
        ) -> Dict[str, Any]:
            """
            **Role**: Retrieves relevant memories from long-term storage based on semantic similarity to the provided query
            **Inputs**:
            - query: Text string to search for in the memory store. The system will find semantically similar previous interactions based on this query text
            **Outputs**:
            - Retrieved memories that match the query, including previous user questions and agent responses
            - Metadata about the retrieval operation including match count and relevance scores
            """
            try:
                # Call the synchronous retrieve operation directly
                result = self._vectorstore_manager.retrieve(query)
                
                return {
                    "success": True,
                    "memories": result["documents"][0] if result["documents"] and result["documents"][0] else [],
                    "count": len(result["documents"][0]) if result["documents"] and result["documents"][0] else 0
                }
            except Exception as e:
                return {
                    "success": False,
                    "error": str(e),
                    "memories": [],
                    "count": 0
                }
        
        @self.mcp.tool()
        async def clear_memory() -> Dict[str, Any]:
            """
            **Role**: Erases all stored conversation memories and reinitializes the vector storage system
            **Inputs**: None
            **Outputs**:
            - Success status indicating whether the memory was cleared successfully
            - Message providing additional details about the operation result
            """
            try:
                # Call the synchronous clear operation directly
                success = self._vectorstore_manager.clear()
                
                return {
                    "success": success,
                    "message": "Memory cleared successfully" if success else "Failed to clear memory"
                }
            except Exception as e:
                return {
                    "success": False,
                    "message": f"Error clearing memory: {str(e)}"
                }
        
        @self.mcp.tool()
        async def get_vectorstore_stats() -> Dict[str, Any]:
            """
            **Role**: Retrieves diagnostic information and usage statistics about the vector storage system used for memory management
            **Inputs**: None
            **Outputs**:
            - Vectorstore configuration details including embedding model and storage type
            - Availability status of the vectorstore service
            - Document counts and memory usage statistics
            - Error information if the vectorstore is unavailable or malfunctioning
            """
            try:
                # Call the synchronous stats operation directly
                stats = self._vectorstore_manager.get_stats()
                
                return {
                    "success": True,
                    **stats
                }
            except Exception as e:
                return {
                    "success": False,
                    "error": f"Error retrieving vectorstore stats: {str(e)}",
                    "vectorstore_available": False
                }
    
    def _register_thinking_tools(self) -> None:
        """Register thinking and reasoning tools."""
        
        @self.mcp.tool()
        async def think(
            summary: str,
            plan: str
        ) -> Dict[str, Any]:
            """
            **Role**: Enables structured reasoning and planning for complex analysis tasks without making any system changes
            **Inputs**:
            - summary: Text string containing a clear summary of the current context related to the query. This should capture all relevant details and findings from previous tool calls without discussing future actions.
            - plan: Text string containing a clear plan of the next steps to take. This should outline the logical sequence of actions needed to complete the analysis or answer the user's query.
            **Outputs**:
            - Confirmation that the reasoning process has been logged
            - Timestamp of when the thinking occurred
            - Success status of the operation
            
            YOU MUST USE THIS TOOL IF YOUR REASONING INVOLVES TWO OR MORE TOOL CALLS. 
            YOU MUST ALSO USE THIS TOOL BEFORE GENERATING THE FINAL ANSWER.

            DON'T GATHER TOO MUCH INFORMATION, ANSWER PRECISELY THE USER QUERY.

            NEVER USE THE SAME TOOL WITH THE SAME PARAMETERS TWICE IN A SINGLE QUERY, EXCEPT FOR THIS ONE. 
            THIS TOOL CAN BE CALLED MULTIPLE TIMES WHILE ANSWERING ONE QUERY

            Use this tool to think through complex analysis before taking actions or responding to users. 
            Namely, use this tool when you need to:
            - Analyze all the previous tool call results before taking further actions
            - Determine if the collected information answers the user query or you need to take further actions
            - Plan a sequence of actions based on current data
            - Reason through attack path data to identify critical vulnerabilities

            Example thinking patterns:
            - When analyzing attack paths: Have you used the determine_attack_paths tool with the proper parameters?
            - When managing zones: Use get_zones to check if the zone management action has happened correctly
            
            The tool logs your reasoning process but doesn't change any data or make API calls.
            
            Args:
                summary: Clear summary of the current context in terms of the current query. Summarize all the details but don't talk about the next steps here.
                plan: Clear plan of the next steps to take.
            
            Returns:
                The confirmation that the tool ran smoothly.
            """

            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Log the thought with timestamp for potential debugging/analysis
            # print(f"[{timestamp}] \n SUMMARY: {summary} \n PLAN: {plan}")
            return {
                "success": True,
                "timestamp": timestamp,
                "message": "The context summary and the plan have been logged successfully. Take them into account in your reasoning."
            }
    
    def _build_graph_params(self, num_layers: int,
                           domain_filter: Optional[List[str]], 
                           zone_filter: Optional[List[str]], 
                           show_whole_graph: bool,
                           expansion_node_id: Optional[str]) -> Dict[str, Any]:
        """Build parameters for graph-related API calls."""
        params = {}
        params["NumLayers"] = num_layers
        if domain_filter is not None:
            params["DomainFilter"] = domain_filter
        if zone_filter is not None:
            params["ZoneFilter"] = zone_filter
        params["ShowWholeGraph"] = show_whole_graph
        if expansion_node_id is not None:
            params["ExpansionNodeId"] = expansion_node_id
        return params
    
    def _build_attack_path_params(self, domain_filter: Optional[List[str]], 
                                 zone_filter: Optional[List[str]], 
                                 zero_cost_paths: bool,
                                 include_blowout_paths: bool,
                                 return_principals_only: bool,
                                 zero_cost_only: bool,
                                 blowout_paths: int,
                                 attacker_id: str,
                                 target_id: str) -> Dict[str, Any]:
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
        if attacker_id:
            params["AttackerID"] = attacker_id
        if target_id:
            params["TargetID"] = target_id
        return params
    
    def _build_zone_params(self, zone_id: str, zone_name: str, 
                          criticality: float, colour: str) -> Dict[str, Any]:
        """Build parameters for zone-related API calls."""
        params = {}
        if zone_id:
            params["ZoneId"] = zone_id
        if zone_name:
            params["ZoneName"] = zone_name
        params["Criticality"] = criticality
        if colour:
            params["Colour"] = colour
        return params
    
    def _build_sync_params(self, custom_collectors: Optional[List[Dict[str, Any]]], 
                          azure_access_tokens: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Build parameters for sync API call."""
        params = {}
        
        if custom_collectors is not None:
            # Format custom collectors to match SyncParameters structure
            formatted_collectors = []
            for collector in custom_collectors:
                if isinstance(collector, dict) and "name" in collector:
                    formatted_collector = {
                        "Name": collector["name"],
                        "Configuration": collector.get("configuration", {})
                    }
                    formatted_collectors.append(formatted_collector)
            params["CustomCollectors"] = formatted_collectors
        
        if azure_access_tokens is not None:
            # Format Azure access tokens to match TokenResponse structure
            formatted_tokens = []
            for token in azure_access_tokens:
                if isinstance(token, dict) and "access_token" in token:
                    formatted_token = {
                        "access_token": token["access_token"],
                        "refresh_token": token.get("refresh_token", ""),
                        "expires_in": token.get("expires_in", -1),
                        "origin_header": token.get("origin_header"),
                        "instance_url": token.get("instance_url")
                    }
                    formatted_tokens.append(formatted_token)
            params["AzureAccessTokens"] = formatted_tokens
        
        return params
    
    def run(self, transport: str = 'streamable-http', host: str = '127.0.0.1', port: int = 8000, path: str = '/mcp') -> None:
        """Run the MCP server with HTTP transport.
        
        Args:
            transport: Transport method to use (default: 'streamable-http')
            host: Host to bind the server to (default: '127.0.0.1')
            port: Port to bind the server to (default: 8000)
            path: URL path for the MCP endpoint (default: '/mcp')
        """
        self.mcp.run(transport=transport, host=host, port=port, path=path)


# Create singleton instance for backward compatibility
_server_instance = None


def get_server_instance() -> RaptorMCPServer:
    """Get or create the singleton server instance."""
    global _server_instance
    if _server_instance is None:
        _server_instance = RaptorMCPServer()
    return _server_instance


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Raptor MCP Server")
    parser.add_argument("-raptor_token", type=str, default=None, help="Override RAPTOR_TOKEN for API access")
    parser.add_argument("-raptor_url", type=str, default="http://localhost:5000/v1", help="Override RAPTOR_URL for API access")
    parser.add_argument("-host", type=str, default="127.0.0.1", help="Host to bind the server to (default: 127.0.0.1)")
    parser.add_argument("-port", type=int, default=8000, help="Port to bind the server to (default: 8000)")
    parser.add_argument("-path", type=str, default="/mcp", help="URL path for the MCP endpoint (default: /mcp)")
    args = parser.parse_args()

    # Create and run the server with optional token, url, host, port, and path override
    server = RaptorMCPServer(raptor_token=args.raptor_token, raptor_url=args.raptor_url)
    server.run(transport='streamable-http', host=args.host, port=args.port, path=args.path)
