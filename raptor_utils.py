"""
Utility module for Raptor MCP server.
Contains encapsulated helper classes for API calls, vectorstore operations, and memory management.
"""
from typing import Dict, Any, List, Optional, Union, Tuple
import os
import urllib.parse
import requests
from openai import AzureOpenAI
import json
import datetime
import uuid
from azure.search.documents import SearchClient
from azure.search.documents.models import VectorizedQuery
from azure.core.credentials import AzureKeyCredential
from azure.search.documents.indexes import SearchIndexClient
from dotenv import load_dotenv
import psutil
import tiktoken
from fuzzywuzzy import fuzz, process

# Load environment variables
load_dotenv(override=True)


class TokenCounter:
    """Utility class for counting tokens in text and JSON responses."""
    
    # Class variable for token limit - hardcoded for easy modification if needed
    MAX_RESPONSE_TOKENS = 50000
    
    def __init__(self, model_name: str = "gpt-4"):
        """Initialize token counter with specified model encoding.
        
        Args:
            model_name: The model name to use for token encoding (default: gpt-4)
        """
        try:
            self._encoding = tiktoken.encoding_for_model(model_name)
        except KeyError:
            # Fallback to cl100k_base encoding if model not found
            self._encoding = tiktoken.get_encoding("cl100k_base")
    
    def count_tokens(self, text: str) -> int:
        """Count tokens in a text string.
        
        Args:
            text: The text to count tokens for
            
        Returns:
            Number of tokens in the text
        """
        if not text:
            return 0
        return len(self._encoding.encode(str(text)))
    
    def count_json_tokens(self, data: Any) -> int:
        """Count tokens in a JSON-serializable object.
        
        Args:
            data: The data structure to count tokens for
            
        Returns:
            Number of tokens in the JSON representation
        """
        if data is None:
            return 0
        try:
            json_str = json.dumps(data, ensure_ascii=False)
            return self.count_tokens(json_str)
        except (TypeError, ValueError):
            # If can't serialize to JSON, convert to string and count
            return self.count_tokens(str(data))
    
    def truncate_by_risk_score(self, response: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generic truncation method for responses containing risk-scored items.
        Always prioritizes items by risk score, regardless of response length.
        
        Args:
            response: The full API response
            config: Configuration dictionary with:
                - fields: List of field configurations, each containing:
                  - name: Field name in the response
                  - priority: Priority order (lower = higher priority)
                  - count_key: Key name for item count in _token_info
                  - error_msg: Error message if field is empty
                - message: Custom truncation message
                
        Returns:
            Response with items prioritized by risk score (truncated if necessary)
        """
        # Count tokens in the full response
        total_tokens = self.count_json_tokens(response)
        response_data = response.get("response", {})
        
        # Extract and validate items from all fields, always sorting by risk score
        field_items = []
        for field_config in config["fields"]:
            field_name = field_config["name"]
            items = response_data.get(field_name, [])
            if items:
                # Sort items by RiskScore in descending order and add field info
                sorted_items = sorted(items, key=lambda x: x.get("RiskScore", 0), reverse=True)
                for item in sorted_items:
                    field_items.append({
                        "item": item,
                        "field_name": field_name,
                        "priority": field_config["priority"],
                        "risk_score": item.get("RiskScore", 0)
                    })
        
        # Check if any items were found
        if not field_items:
            token_info = {
                "total_tokens": total_tokens,
                "max_tokens": self.MAX_RESPONSE_TOKENS,
                "truncated": False,
                "error": "No risk-scored items found in response"
            }
            # Add zero counts for each field
            for field_config in config["fields"]:
                count_key = field_config["count_key"]
                token_info[count_key] = 0
            return {**response, "_token_info": token_info}
        
        # Sort all items by priority first, then by risk score (always prioritize by risk)
        field_items.sort(key=lambda x: (x["priority"], -x["risk_score"]))
        
        # Determine if truncation is needed
        needs_truncation = total_tokens > self.MAX_RESPONSE_TOKENS
        
        # Build response with risk-prioritized items (truncate if necessary)
        selected_items_by_field = {}
        for field_config in config["fields"]:
            selected_items_by_field[field_config["name"]] = []
        
        if needs_truncation:
            # Calculate base response size for truncation
            base_response = {**response}
            base_response["response"] = {**response_data}
            for field_config in config["fields"]:
                base_response["response"][field_config["name"]] = []
            current_tokens = self.count_json_tokens(base_response)
            
            # Add items one by one until we approach the token limit
            for field_item in field_items:
                item_tokens = self.count_json_tokens(field_item["item"])
                if current_tokens + item_tokens > self.MAX_RESPONSE_TOKENS:
                    break
                selected_items_by_field[field_item["field_name"]].append(field_item["item"])
                current_tokens += item_tokens
        else:
            # No truncation needed, but still prioritize by risk score
            for field_item in field_items:
                selected_items_by_field[field_item["field_name"]].append(field_item["item"])
        
        # Build the final response
        final_response = {**response}
        final_response["response"] = {**response_data}
        for field_name, selected_items in selected_items_by_field.items():
            final_response["response"][field_name] = selected_items
        
        # Build token information
        final_tokens = self.count_json_tokens(final_response)
        token_info = {
            "total_tokens": final_tokens,
            "max_tokens": self.MAX_RESPONSE_TOKENS,
            "truncated": needs_truncation,
            "prioritized_by_risk": True
        }
        
        if needs_truncation:
            token_info["message"] = config["message"]
        
        # Add detailed statistics for each field
        for field_config in config["fields"]:
            field_name = field_config["name"]
            count_key = field_config["count_key"]
            original_items = response_data.get(field_name, [])
            selected_items = selected_items_by_field[field_name]
            
            # Add counts
            if needs_truncation:
                token_info[f"original_{count_key}"] = len(original_items)
                token_info[f"truncated_{count_key}"] = len(selected_items)
            else:
                token_info[count_key] = len(selected_items)
            
            # Add risk score ranges if items exist
            if selected_items:
                token_info[f"highest_{field_name.lower()}_risk_score"] = selected_items[0].get("RiskScore", 0)
                token_info[f"lowest_{field_name.lower()}_risk_score"] = selected_items[-1].get("RiskScore", 0)
            else:
                token_info[f"highest_{field_name.lower()}_risk_score"] = 0
                token_info[f"lowest_{field_name.lower()}_risk_score"] = 0
        
        final_response["_token_info"] = token_info
        return final_response
    
    def truncate_attack_paths_by_risk(self, attack_paths_response: Dict[str, Any], field_name: str = "AttackPaths", max_tokens: Optional[int] = None) -> Dict[str, Any]:
        """Truncate attack paths response to fit within token limit, keeping highest risk paths."""
        # Use provided max_tokens or class default
        original_max_tokens = self.MAX_RESPONSE_TOKENS
        if max_tokens is not None:
            self.MAX_RESPONSE_TOKENS = max_tokens
        
        try:
            config = {
                "fields": [
                    {
                        "name": field_name,
                        "priority": 1,
                        "count_key": "attack_path_count",
                        "error_msg": f"No attack paths found in response field '{field_name}'"
                    }
                ],
                "message": f"ATTENTION! The response was truncated to fit within token limit, and only the most critical attack paths were output from field '{field_name}'."
            }
            return self.truncate_by_risk_score(attack_paths_response, config)
        finally:
            # Restore original max_tokens
            self.MAX_RESPONSE_TOKENS = original_max_tokens
    
    def truncate_reachability_report_by_risk(self, reachability_response: Dict[str, Any]) -> Dict[str, Any]:
        """Truncate reachability report response to fit within token limit, keeping highest risk items."""
        config = {
            "fields": [
                {
                    "name": "ReachabilityReport",
                    "priority": 1,
                    "count_key": "reachability_item_count",
                    "error_msg": "No reachability items found in response"
                }
            ],
            "message": "ATTENTION! The response was truncated to fit within token limit, and only the highest risk reachability items were output."
        }
        return self.truncate_by_risk_score(reachability_response, config)
    
    def truncate_risk_reduction_by_risk(self, risk_reduction_response: Dict[str, Any]) -> Dict[str, Any]:
        """Truncate risk reduction response to fit within token limit, keeping highest risk items."""
        config = {
            "fields": [
                {
                    "name": "NodeRiskReduction",
                    "priority": 1,  # Higher priority (processed first)
                    "count_key": "node_risk_item_count",
                    "error_msg": "No node risk reduction items found in response"
                },
                {
                    "name": "RightRiskReduction", 
                    "priority": 2,  # Lower priority (processed second)
                    "count_key": "right_risk_item_count",
                    "error_msg": "No right risk reduction items found in response"
                }
            ],
            "message": "ATTENTION! The response was truncated to fit within token limit, and only the highest risk reduction items were output."
        }
        return self.truncate_by_risk_score(risk_reduction_response, config)
    
    def truncate_graph_query(self, graph_response: Dict[str, Any], max_tokens: Optional[int] = None) -> Dict[str, Any]:
        """Truncate graph query response to fit within token limit.
        
        Args:
            graph_response: The full graph query response from the API
            max_tokens: Optional maximum token limit (uses class default if not provided)
            
        Returns:
            Truncated response with warning message if truncated
        """
        # Use provided max_tokens or class default
        effective_max_tokens = max_tokens if max_tokens is not None else self.MAX_RESPONSE_TOKENS
        
        # Count tokens in the full response
        total_tokens = self.count_json_tokens(graph_response)
        
        if total_tokens <= effective_max_tokens:
            # Response is already within limits
            return {
                **graph_response,
                "_token_info": {
                    "total_tokens": total_tokens,
                    "max_tokens": effective_max_tokens,
                    "truncated": False
                }
            }
        
        # Extract graph data
        response_data = graph_response.get("response", {})
        graph_data = response_data.get("Data", {})
        nodes = graph_data.get("nodes", [])
        links = graph_data.get("links", [])
        
        if not nodes and not links:
            return {
                **graph_response,
                "_token_info": {
                    "total_tokens": total_tokens,
                    "max_tokens": self.MAX_RESPONSE_TOKENS,
                    "truncated": False,
                    "error": "No graph data found in response"
                }
            }
        
        # Calculate base response size (without nodes and links)
        base_response = {**graph_response}
        base_response["response"] = {**response_data}
        base_response["response"]["Data"] = {**graph_data}
        base_response["response"]["Data"]["nodes"] = []
        base_response["response"]["Data"]["links"] = []
        base_tokens = self.count_json_tokens(base_response)
        
        # Calculate available tokens for nodes and links
        available_tokens = effective_max_tokens - base_tokens
        
        # Prioritize nodes over links (nodes are more important for understanding the graph)
        # First, add as many nodes as possible
        selected_nodes = []
        current_tokens = base_tokens
        node_ids = set()
        
        for node in nodes:
            node_tokens = self.count_json_tokens(node)
            
            # Check if adding this node would exceed the limit
            if current_tokens + node_tokens > effective_max_tokens:
                break
                
            selected_nodes.append(node)
            node_ids.add(node.get("id"))
            current_tokens += node_tokens
        
        # Then, add links that connect the selected nodes
        selected_links = []
        
        for link in links:
            # Only include links where both source and target are in the selected nodes
            if link.get("source") in node_ids and link.get("target") in node_ids:
                link_tokens = self.count_json_tokens(link)
                
                # Check if adding this link would exceed the limit
                if current_tokens + link_tokens > effective_max_tokens:
                    break
                    
                selected_links.append(link)
                current_tokens += link_tokens
        
        # Build the truncated response
        truncated_response = {**graph_response}
        truncated_response["response"] = {**response_data}
        truncated_response["response"]["Data"] = {**graph_data}
        truncated_response["response"]["Data"]["nodes"] = selected_nodes
        truncated_response["response"]["Data"]["links"] = selected_links
        
        # Update node and link counts
        if "NodeCount" in response_data:
            truncated_response["response"]["NodeCount"] = len(selected_nodes)
        if "LinkCount" in response_data:
            truncated_response["response"]["LinkCount"] = len(selected_links)
        
        # Add token information
        final_tokens = self.count_json_tokens(truncated_response)
        truncated_response["_token_info"] = {
            "total_tokens": final_tokens,
            "max_tokens": effective_max_tokens,
            "truncated": True,
            "original_node_count": len(nodes),
            "truncated_node_count": len(selected_nodes),
            "original_link_count": len(links),
            "truncated_link_count": len(selected_links),
            "message": f"ATTENTION! The response was truncated to fit within the {effective_max_tokens} token limit. Please modify your query parameters to get a smaller result set. Consider using more specific filters such as domain_filter, zone_filter, or reducing num_layers."
        }
        
        return truncated_response


class RaptorAPIClient:
    """Encapsulated API client for Raptor API calls."""
    
    def __init__(self, base_url: Optional[str] = None, token: Optional[str] = None):
        self._base_url = base_url
        # Use provided token or environment variable
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


class VectorStoreManager:
    """Manages vectorstore operations for memory storage and retrieval."""
    
    # Class-level constants (private)
    _SEARCH_INDEX_NAME = "mcp-vectorstore-test"
    _EMBEDDING_DEPLOYMENT = "text-embedding-3-small"
    _EMBEDDING_DIMENSION = 1536
    _SIMILARITY_THRESHOLD = 0.85
    _MEMORY_RETRIEVAL_COUNT = 5
    
    def __init__(self):
        self._search_client: Optional[SearchClient] = None
        self._openai_client: Optional[AzureOpenAI] = None
        self._is_warmed_up = False
        self._initialize_clients()
        self._warmup_embedding_client()
    
    def _initialize_clients(self) -> None:
        """Initialize Azure Search and OpenAI clients."""
        # Initialize OpenAI client
        azure_endpoint = os.getenv("AZURE_API_BASE", "")
        api_key = os.getenv("AZURE_API_KEY", "")
        api_version = os.getenv("AZURE_API_VERSION", "2024-12-01-preview")
        
        if azure_endpoint and api_key:
            self._openai_client = AzureOpenAI(
                azure_endpoint=azure_endpoint,
                api_key=api_key,
                api_version=api_version,
                max_retries=2,  # Add retry logic
                timeout=30.0    # Add explicit timeout
            )
        
        # Initialize Search client
        search_endpoint = os.environ.get('AZURE_SEARCH_SERVICE')
        search_key = os.environ.get('AZURE_SEARCH_KEY')
        
        if search_endpoint and search_key:
            search_credential = AzureKeyCredential(search_key)
            self._search_client = SearchClient(
                endpoint=search_endpoint,
                index_name=self._SEARCH_INDEX_NAME,
                credential=search_credential
            )
    
    def _warmup_embedding_client(self) -> None:
        """Warm up the embedding client with a test request."""
        if self._openai_client and not self._is_warmed_up:
            try:
                # Make a small test embedding request to warm up the connection
                self._openai_client.embeddings.create(
                    input="test",
                    model=self._EMBEDDING_DEPLOYMENT
                )
                self._is_warmed_up = True
            except Exception:
                # Silently ignore warmup failures
                pass
    
    def save(self, user_query: str, agent_response: str, api_calls: Optional[List[Dict]] = None) -> Union[bool, str]:
        """Save a conversation exchange to vectorstore.
        
        Args:
            user_query: The user's query
            agent_response: The agent's response
            api_calls: Optional list of API calls made
        
        Returns:
            True if successful, error message string if not
        """
        if not self._search_client or not self._openai_client:
            return "Vectorstore clients not initialized"
        
        # Format the timestamp
        # Use timezone-aware datetime to avoid deprecation warning
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # Generate embedding for the new entry
        combined_text = f"{user_query} {agent_response} Timestamp: {timestamp}"
        new_embedding = self._generate_embeddings(combined_text)
        
        if not new_embedding:
            return "Failed to generate embeddings"
        
        # Check for similar entries before saving
        if self._check_similarity(new_embedding, user_query, agent_response):
            return "Similar entry already exists. Memory not updated"
        
        # Create and upload document
        document = self._create_document(user_query, agent_response, api_calls, timestamp, new_embedding)
        
        try:
            result = self._search_client.upload_documents(documents=[document])
            return result[0].succeeded
        except Exception as e:
            return f"Failed to upload document: {str(e)}"
    
    def retrieve(self, query: str) -> Dict[str, Any]:
        """Retrieve relevant conversations from vectorstore.
        
        Args:
            query: The search query
        
        Returns:
            Dict containing retrieved documents
        """
        if not self._search_client or not self._openai_client:
            return {"documents": [[]]}
        
        # Generate query embedding
        query_embedding = self._generate_embeddings(query)
        if not query_embedding:
            return {"documents": [[]]}
        
        # Create and execute vector query
        vector_query = VectorizedQuery(
            vector=query_embedding,
            k_nearest_neighbors=self._MEMORY_RETRIEVAL_COUNT,
            fields="embedding"
        )
        
        try:
            results = self._search_client.search(
                search_text=None,
                vector_queries=[vector_query],
                select=["id", "user_query", "agent_response", "timestamp", "api_calls"],
                top=self._MEMORY_RETRIEVAL_COUNT
            )
            
            # Process results
            documents = self._process_search_results(results)
            return {"documents": [documents]}
        except Exception:
            return {"documents": [[]]}
    
    def clear(self) -> bool:
        """Clear all memory by deleting all documents from the index.
        
        Returns:
            True if successful, False otherwise
        """
        if not self._search_client:
            return False
        
        try:
            # Get all document IDs
            results = self._search_client.search(
                search_text="*",
                select=["id"],
                top=1000  # Adjust if expecting more documents
            )
            
            # Collect all document IDs
            document_ids = [{"id": result["id"]} for result in results]
            
            if document_ids:
                # Delete all documents
                self._search_client.delete_documents(documents=document_ids)
            
            return True
        except Exception:
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get basic statistics about the vectorstore.
        
        Returns:
            Dict containing vectorstore statistics and status information
        """
        stats = {
            "vectorstore_available": False,
            "openai_client_available": False,
            "search_client_available": False,
            "total_documents": 0,
            "index_name": self._SEARCH_INDEX_NAME,
            "embedding_model": self._EMBEDDING_DEPLOYMENT,
            "embedding_dimension": self._EMBEDDING_DIMENSION,
            "similarity_threshold": self._SIMILARITY_THRESHOLD,
            "retrieval_count": self._MEMORY_RETRIEVAL_COUNT,
            "client_warmed_up": self._is_warmed_up,
            "error": None
        }
        
        # Check client availability
        stats["search_client_available"] = self._search_client is not None
        stats["openai_client_available"] = self._openai_client is not None
        stats["vectorstore_available"] = stats["search_client_available"] and stats["openai_client_available"]
        
        if not stats["vectorstore_available"]:
            if not stats["search_client_available"]:
                stats["error"] = "Azure Search client not configured - check AZURE_SEARCH_SERVICE and AZURE_SEARCH_KEY"
            elif not stats["openai_client_available"]:
                stats["error"] = "Azure OpenAI client not configured - check AZURE_API_BASE and AZURE_API_KEY"
            return stats
        
        # Get document count and sample data
        try:
            results = self._search_client.search(
                search_text="*",
                select=["id", "timestamp"],
                top=1000  # Adjust if expecting more documents
            )
            
            documents = list(results)
            stats["total_documents"] = len(documents)
            
            if documents:
                # Get oldest and newest timestamps
                timestamps = [doc.get("timestamp", "") for doc in documents if doc.get("timestamp")]
                if timestamps:
                    timestamps.sort()
                    stats["oldest_memory"] = timestamps[0]
                    stats["newest_memory"] = timestamps[-1]
            
        except Exception as e:
            stats["error"] = f"Failed to retrieve statistics: {str(e)}"
            stats["total_documents"] = "unknown"
        
        return stats
    
    def _generate_embeddings(self, text: str) -> Optional[List[float]]:
        """Generate embeddings for the input text."""
        if not self._openai_client:
            return None
        
        try:
            # Ensure client is warmed up
            if not self._is_warmed_up:
                self._warmup_embedding_client()
            
            response = self._openai_client.embeddings.create(
                input=text,
                model=self._EMBEDDING_DEPLOYMENT
            )
            return response.data[0].embedding
        except Exception as e:
            # Log the error for debugging
            print(f"Embedding generation error: {str(e)}")
            return None
    
    def _check_similarity(self, embedding: List[float], user_query: str, agent_response: str) -> bool:
        """Check if a similar entry already exists."""
        vector_query = VectorizedQuery(
            vector=embedding,
            k_nearest_neighbors=5,
            fields="embedding"
        )
        
        try:
            similar_results = self._search_client.search(
                search_text=None,
                vector_queries=[vector_query],
                select=["id", "user_query", "agent_response", "timestamp"],
                top=5
            )
            
            # Check if any existing entry is too similar
            for result in similar_results:
                similarity_score = result.get('@search.score', 0)
                if similarity_score > self._SIMILARITY_THRESHOLD:
                    return True
            
            return False
        except Exception:
            return False
    
    def _create_document(self, user_query: str, agent_response: str, 
                        api_calls: Optional[List[Dict]], timestamp: str, 
                        embedding: List[float]) -> Dict[str, Any]:
        """Create a document for vectorstore."""
        return {
            "id": str(uuid.uuid4()),
            "user_query": user_query,
            "agent_response": agent_response,
            "api_calls": json.dumps(api_calls) if api_calls else "[]",
            "timestamp": timestamp,
            "embedding": embedding
        }
    
    def _process_search_results(self, results) -> List[str]:
        """Process search results into formatted memory entries."""
        documents = []
        
        for result in results:
            timestamp = result.get("timestamp", "")
            
            memory_entry = (
                f"Timestamp: {timestamp}\n"
                f"User asked: '{result['user_query']}'\n"
                f"Response: '{result['agent_response']}'"
            )
            
            documents.append(memory_entry)
        
        return documents


def calculate_object_stats(objects):
    """Calculate comprehensive statistics about identity objects."""
    import datetime
    # Initialize statistics containers
    stats = {
        "total_object_count": len(objects),
        "objectclass_distribution": {},
        "domain_distribution": {},
        "admin_objects": {
            "total": 0,
            "by_objectclass": {}
        },
        "object_age": {
            "created_last_30_days": 0,
            "created_last_90_days": 0,
            "created_last_180_days": 0,
            "created_last_year": 0,
            "created_older": 0,
            "no_creation_date": 0
        },
        "relationship_statistics": {
            "total_incoming_relationships": 0,
            "total_outgoing_relationships": 0,
            "avg_incoming_relationships": 0,
            "avg_outgoing_relationships": 0,
            "max_incoming_relationships": 0,
            "max_outgoing_relationships": 0,
            "objects_with_high_incoming": 0,
            "objects_with_high_outgoing": 0
        },
        "timestamp_analysis": {
            "changed_last_30_days": 0,
            "changed_last_90_days": 0,
            "changed_last_180_days": 0,
            "changed_older": 0,
            "no_change_data": 0,
            "logon_last_30_days": 0,
            "logon_last_90_days": 0,
            "logon_last_180_days": 0,
            "logon_older": 0,
            "never_logged_on": 0
        },
        "security_metrics": {
            "privileged_accounts": 0,
            "service_accounts": 0,
            "groups_with_nested_admins": 0
        }
    }
    current_time = datetime.datetime.now()

    def parse_timestamp(timestamp_str):
        if not timestamp_str or timestamp_str == "0":
            return None
        try:
            return datetime.datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, TypeError):
            try:
                if isinstance(timestamp_str, (int, float)) or (isinstance(timestamp_str, str) and timestamp_str.isdigit()):
                    filetime = int(timestamp_str)
                    if filetime > 0:
                        seconds_since_unix_epoch = filetime / 10000000 - 11644473600
                        return datetime.datetime.fromtimestamp(seconds_since_unix_epoch)
            except (ValueError, TypeError, OverflowError):
                pass
        return None

    def count_relationships(relationships):
        if not relationships:
            return 0
        if isinstance(relationships, list):
            return len(relationships)
        return 0

    total_incoming = 0
    total_outgoing = 0
    max_incoming = 0
    max_outgoing = 0

    for obj in objects:
        objectclass = obj.get("Objectclass", "unknown").lower()
        stats["objectclass_distribution"][objectclass] = stats["objectclass_distribution"].get(objectclass, 0) + 1

        domain = obj.get("Domain", "unknown")
        stats["domain_distribution"][domain] = stats["domain_distribution"].get(domain, 0) + 1

        admincount = obj.get("Admincount", 0)
        if admincount == 1:
            stats["admin_objects"]["total"] += 1
            stats["admin_objects"]["by_objectclass"][objectclass] = stats["admin_objects"]["by_objectclass"].get(objectclass, 0) + 1

        whencreated = obj.get("Whencreated", "")
        creation_timestamp = parse_timestamp(whencreated)
        if creation_timestamp:
            age_days = (current_time - creation_timestamp).days
            if age_days <= 30:
                stats["object_age"]["created_last_30_days"] += 1
            elif age_days <= 90:
                stats["object_age"]["created_last_90_days"] += 1
            elif age_days <= 180:
                stats["object_age"]["created_last_180_days"] += 1
            elif age_days <= 365:
                stats["object_age"]["created_last_year"] += 1
            else:
                stats["object_age"]["created_older"] += 1
        else:
            stats["object_age"]["no_creation_date"] += 1

        incoming_count = count_relationships(obj.get("Incoming", []))
        outgoing_count = count_relationships(obj.get("Outgoing", []))

        total_incoming += incoming_count
        total_outgoing += outgoing_count

        max_incoming = max(max_incoming, incoming_count)
        max_outgoing = max(max_outgoing, outgoing_count)

        if incoming_count > 10:
            stats["relationship_statistics"]["objects_with_high_incoming"] += 1

        if outgoing_count > 10:
            stats["relationship_statistics"]["objects_with_high_outgoing"] += 1

        whenchanged = obj.get("Whenchanged", "")
        lastlogon = obj.get("Lastlogontimestamp", 0)

        change_timestamp = parse_timestamp(whenchanged)
        if change_timestamp:
            age_days = (current_time - change_timestamp).days
            if age_days <= 30:
                stats["timestamp_analysis"]["changed_last_30_days"] += 1
            elif age_days <= 90:
                stats["timestamp_analysis"]["changed_last_90_days"] += 1
            elif age_days <= 180:
                stats["timestamp_analysis"]["changed_last_180_days"] += 1
            else:
                stats["timestamp_analysis"]["changed_older"] += 1
        else:
            stats["timestamp_analysis"]["no_change_data"] += 1

        logon_timestamp = parse_timestamp(lastlogon)
        if logon_timestamp:
            age_days = (current_time - logon_timestamp).days
            if age_days <= 30:
                stats["timestamp_analysis"]["logon_last_30_days"] += 1
            elif age_days <= 90:
                stats["timestamp_analysis"]["logon_last_90_days"] += 1
            elif age_days <= 180:
                stats["timestamp_analysis"]["logon_last_180_days"] += 1
            else:
                stats["timestamp_analysis"]["logon_older"] += 1
        else:
            stats["timestamp_analysis"]["never_logged_on"] += 1

        name = obj.get("Name", "").lower()
        samaccountname = obj.get("Samaccountname", "").lower()
        description = obj.get("Description", "").lower()

        privileged_indicators = ["admin", "administrator", "root", "superuser", "supervisor"]
        if any(indicator in name for indicator in privileged_indicators) or \
           any(indicator in samaccountname for indicator in privileged_indicators):
            stats["security_metrics"]["privileged_accounts"] += 1

        service_indicators = ["svc", "service", "srv", "system", "auto"]
        if any(indicator in name for indicator in service_indicators) or \
           any(indicator in samaccountname for indicator in service_indicators) or \
           "service account" in description:
            stats["security_metrics"]["service_accounts"] += 1

    if stats["total_object_count"] > 0:
        stats["relationship_statistics"]["avg_incoming_relationships"] = total_incoming / stats["total_object_count"]
        stats["relationship_statistics"]["avg_outgoing_relationships"] = total_outgoing / stats["total_object_count"]

    stats["relationship_statistics"]["max_incoming_relationships"] = max_incoming
    stats["relationship_statistics"]["max_outgoing_relationships"] = max_outgoing
    stats["relationship_statistics"]["total_incoming_relationships"] = total_incoming
    stats["relationship_statistics"]["total_outgoing_relationships"] = total_outgoing

    admin_containing_groups = 0
    for obj in objects:
        if obj.get("Objectclass", "").lower() == "group":
            outgoing_relationships = obj.get("Outgoing", [])
            if isinstance(outgoing_relationships, list) and outgoing_relationships:
                if len(outgoing_relationships) > 5:
                    admin_containing_groups += 1

    stats["security_metrics"]["groups_with_nested_admins"] = admin_containing_groups

    return stats

def calculate_node_stats(nodes):
    """Calculate comprehensive statistics about identity graph nodes."""
    import datetime
    stats = {
        "total_node_count": len(nodes),
        "type_distribution": {},
        "domain_distribution": {},
        "zone_distribution": {},
        "account_status": {
            "enabled": 0,
            "disabled": 0,
            "locked": 0,
            "password_expired": 0,
            "password_never_expires": 0,
            "not_applicable": 0
        },
        "password_age": {
            "never_set": 0,
            "recent_30_days": 0,
            "between_30_90_days": 0,
            "between_90_180_days": 0,
            "older_than_180_days": 0,
            "not_applicable": 0
        },
        "edge_statistics": {
            "total_incoming_edges_of_concern": 0,
            "total_unclassified_incoming_edges": 0,
            "nodes_with_incoming_edges_of_concern": 0,
            "nodes_with_unclassified_edges": 0,
            "avg_incoming_edges_of_concern": 0,
            "max_incoming_edges_of_concern": 0
        },
        "timestamp_analysis": {
            "changed_last_30_days": 0,
            "changed_last_90_days": 0,
            "changed_last_180_days": 0,
            "changed_older": 0,
            "no_change_data": 0,
            "logon_last_30_days": 0,
            "logon_last_90_days": 0,
            "logon_last_180_days": 0,
            "logon_older": 0,
            "never_logged_on": 0
        }
    }
    current_time = datetime.datetime.now()

    def parse_timestamp(timestamp_str):
        if not timestamp_str or timestamp_str == "0":
            return None
        try:
            return datetime.datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, TypeError):
            try:
                if isinstance(timestamp_str, (int, float)) or (isinstance(timestamp_str, str) and timestamp_str.isdigit()):
                    filetime = int(timestamp_str)
                    if filetime > 0:
                        seconds_since_unix_epoch = filetime / 10000000 - 11644473600
                        return datetime.datetime.fromtimestamp(seconds_since_unix_epoch)
            except (ValueError, TypeError, OverflowError):
                pass
        return None

    max_incoming_edges = 0
    total_incoming_edges = 0
    nodes_with_edges = 0

    for node in nodes:
        node_type = node.get("type", "unknown")
        stats["type_distribution"][node_type] = stats["type_distribution"].get(node_type, 0) + 1

        domain = node.get("domain", "unknown")
        stats["domain_distribution"][domain] = stats["domain_distribution"].get(domain, 0) + 1

        zone = node.get("zone", "")
        zone_name = "unassigned" if not zone else zone
        stats["zone_distribution"][zone_name] = stats["zone_distribution"].get(zone_name, 0) + 1

        if node_type == "user":
            uac = node.get("useraccountcontrol", 0)
            if isinstance(uac, str) and uac.isdigit():
                uac = int(uac)
            if uac & 0x0002:
                stats["account_status"]["disabled"] += 1
            else:
                stats["account_status"]["enabled"] += 1
            if uac & 0x0010:
                stats["account_status"]["locked"] += 1
            if uac & 0x8000:
                stats["account_status"]["password_expired"] += 1
            if uac & 0x10000:
                stats["account_status"]["password_never_expires"] += 1

            pwd_last_set = node.get("passwordlastset", 0)
            if pwd_last_set == 0:
                stats["password_age"]["never_set"] += 1
            else:
                pwd_timestamp = parse_timestamp(pwd_last_set)
                if pwd_timestamp:
                    age_days = (current_time - pwd_timestamp).days
                    if age_days <= 30:
                        stats["password_age"]["recent_30_days"] += 1
                    elif age_days <= 90:
                        stats["password_age"]["between_30_90_days"] += 1
                    elif age_days <= 180:
                        stats["password_age"]["between_90_180_days"] += 1
                    else:
                        stats["password_age"]["older_than_180_days"] += 1
                else:
                    stats["password_age"]["never_set"] += 1
        else:
            stats["account_status"]["not_applicable"] += 1
            stats["password_age"]["not_applicable"] += 1

        incoming_edges = node.get("totalIncomingEdgesOfConcern", 0)
        unclassified_edges = node.get("unClassifiedIncomingEdgesCount", 0)

        if incoming_edges > 0:
            stats["edge_statistics"]["nodes_with_incoming_edges_of_concern"] += 1
            stats["edge_statistics"]["total_incoming_edges_of_concern"] += incoming_edges
            max_incoming_edges = max(max_incoming_edges, incoming_edges)
            total_incoming_edges += incoming_edges
            nodes_with_edges += 1

        if unclassified_edges > 0:
            stats["edge_statistics"]["nodes_with_unclassified_edges"] += 1
            stats["edge_statistics"]["total_unclassified_incoming_edges"] += unclassified_edges

        whenchanged = node.get("whenchanged", "")
        lastlogon = node.get("lastlogontimestamp", 0)

        change_timestamp = parse_timestamp(whenchanged)
        if change_timestamp:
            age_days = (current_time - change_timestamp).days
            if age_days <= 30:
                stats["timestamp_analysis"]["changed_last_30_days"] += 1
            elif age_days <= 90:
                stats["timestamp_analysis"]["changed_last_90_days"] += 1
            elif age_days <= 180:
                stats["timestamp_analysis"]["changed_last_180_days"] += 1
            else:
                stats["timestamp_analysis"]["changed_older"] += 1
        else:
            stats["timestamp_analysis"]["no_change_data"] += 1

        logon_timestamp = parse_timestamp(lastlogon)
        if logon_timestamp:
            age_days = (current_time - logon_timestamp).days
            if age_days <= 30:
                stats["timestamp_analysis"]["logon_last_30_days"] += 1
            elif age_days <= 90:
                stats["timestamp_analysis"]["logon_last_90_days"] += 1
            elif age_days <= 180:
                stats["timestamp_analysis"]["logon_last_180_days"] += 1
            else:
                stats["timestamp_analysis"]["logon_older"] += 1
        else:
            stats["timestamp_analysis"]["never_logged_on"] += 1

    if nodes_with_edges > 0:
        stats["edge_statistics"]["avg_incoming_edges_of_concern"] = total_incoming_edges / nodes_with_edges
        stats["edge_statistics"]["max_incoming_edges_of_concern"] = max_incoming_edges

    stats["security_metrics"] = {
        "stale_password_percentage": (
            stats["password_age"]["older_than_180_days"] /
            (stats["total_node_count"] - stats["password_age"]["not_applicable"])
        ) * 100 if (stats["total_node_count"] - stats["password_age"]["not_applicable"]) > 0 else 0,
        "disabled_account_percentage": (
            stats["account_status"]["disabled"] /
            (stats["total_node_count"] - stats["account_status"]["not_applicable"])
        ) * 100 if (stats["total_node_count"] - stats["account_status"]["not_applicable"]) > 0 else 0,
        "inactive_account_percentage": (
            stats["timestamp_analysis"]["never_logged_on"] / stats["total_node_count"]
        ) * 100 if stats["total_node_count"] > 0 else 0,
        "recently_modified_percentage": (
            stats["timestamp_analysis"]["changed_last_30_days"] / stats["total_node_count"]
        ) * 100 if stats["total_node_count"] > 0 else 0
    }

    return stats

def fuzzy_find_best_match(items: List[Dict[str, Any]], search_term: str, field_name: str, threshold: int = 80) -> Tuple[Optional[Dict[str, Any]], int]:
    """
    Find the best fuzzy match for a search term in a list of items.
    
    Args:
        items: List of dictionaries to search through
        search_term: The term to search for
        field_name: The field name in each item to match against
        threshold: Minimum similarity score (0-100) to consider a match
        
    Returns:
        Tuple of (best_match_item, similarity_score) or (None, 0) if no match found
    """
    if not items or not search_term:
        return None, 0
    
    # Create a list of field values for fuzzy matching
    field_values = []
    for item in items:
        field_value = item.get(field_name, "")
        if field_value:
            field_values.append(field_value)
    
    if not field_values:
        return None, 0
    
    # Use fuzzywuzzy to find the best match
    best_match = process.extractOne(
        search_term, 
        field_values, 
        scorer=fuzz.ratio  # Use ratio for full string similarity matching
    )
    
    if best_match and best_match[1] >= threshold:
        best_match_value, score = best_match
        # Find the original item that matches this value
        for item in items:
            if item.get(field_name, "") == best_match_value:
                return item, score
    
    return None, 0


def _enhance_object_relationships(obj: Dict[str, Any], all_objects: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Helper function to enhance object relationships with additional information.
    
    Args:
        obj: The object to enhance
        all_objects: List of all objects for relationship lookup
        
    Returns:
        Enhanced object with detailed relationship information
    """
    enhanced_object = dict(obj)  # Create a copy to avoid modifying the original
    
    # Process incoming relationships
    if "Incoming" in enhanced_object and isinstance(enhanced_object["Incoming"], list):
        enhanced_incoming = []
        for edge in enhanced_object["Incoming"]:
            enhanced_edge = dict(edge)  # Copy the edge data
            vertex_id = edge.get("VertexId")
            if vertex_id:
                # Find the object with this ID
                for related_obj in all_objects:
                    if related_obj.get("Id") == vertex_id:
                        # Add the requested fields
                        enhanced_edge["Objectclass"] = related_obj.get("Objectclass", "")
                        enhanced_edge["OID"] = related_obj.get("OID", "")
                        enhanced_edge["DN"] = related_obj.get("DN", "")
                        enhanced_edge["Name"] = related_obj.get("Name", "")
                        enhanced_edge["Gplink"] = related_obj.get("Gplink", "")
                        enhanced_edge["Primarygroupid"] = related_obj.get("Primarygroupid", "")
                        enhanced_edge["Domain"] = related_obj.get("Domain", "")
                        break
            enhanced_incoming.append(enhanced_edge)
        enhanced_object["Incoming"] = enhanced_incoming
    
    # Process outgoing relationships
    if "Outgoing" in enhanced_object and isinstance(enhanced_object["Outgoing"], list):
        enhanced_outgoing = []
        for edge in enhanced_object["Outgoing"]:
            enhanced_edge = dict(edge)  # Copy the edge data
            vertex_id = edge.get("VertexId")
            if vertex_id:
                # Find the object with this ID
                for related_obj in all_objects:
                    if related_obj.get("Id") == vertex_id:
                        # Add the requested fields
                        enhanced_edge["Objectclass"] = related_obj.get("Objectclass", "")
                        enhanced_edge["OID"] = related_obj.get("OID", "")
                        enhanced_edge["DN"] = related_obj.get("DN", "")
                        enhanced_edge["Name"] = related_obj.get("Name", "")
                        enhanced_edge["Gplink"] = related_obj.get("Gplink", "")
                        enhanced_edge["Primarygroupid"] = related_obj.get("Primarygroupid", "")
                        enhanced_edge["Domain"] = related_obj.get("Domain", "")
                        break
            enhanced_outgoing.append(enhanced_edge)
        enhanced_object["Outgoing"] = enhanced_outgoing
    
    return enhanced_object


def find_object(objects, identifier, id_type = "label"):
    """
    Find an object by its label (with fuzzy matching) or OID (exact match only) in a list of objects.
    
    Args:
        objects: List of objects to search through
        identifier: The identifier to search for (label or OID)
        id_type: Type of identifier ("label" or "oid")
        
    Returns:
        Dictionary with search results including fuzzy match information for labels
    """
    if not objects:
        return {
            "error": "No objects found",
            "object": None
        }
    
    # Determine the field name to search
    field_name = "Name" if id_type == "label" else "OID"
    
    # First try exact match
    exact_match = None
    for obj in objects:
        if obj.get(field_name, "") == identifier:
            exact_match = obj
            break
    
    if exact_match:
        # Enhance the exact match object
        enhanced_object = _enhance_object_relationships(exact_match, objects)
        return {
            "success": True,
            "object": enhanced_object,
            "match_type": "exact",
            "similarity_score": 100
        }
    
    # For OID searches, only do exact matching - no fuzzy matching
    if id_type == "oid":
        return {
            "error": f"Object with OID '{identifier}' not found",
            "object": None,
            "total_objects_searched": len(objects)
        }
    
    # For label searches, try fuzzy matching if exact match failed
    best_match, score = fuzzy_find_best_match(objects, identifier, field_name)
    
    if best_match:
        # Enhance the fuzzy match object
        enhanced_object = _enhance_object_relationships(best_match, objects)
        return {
            "success": True,
            "object": enhanced_object,
            "match_type": "fuzzy",
            "similarity_score": score,
            "search_term": identifier,
            "matched_value": best_match.get(field_name, "")
        }
    else:
        return {
            "error": f"No suitable match found for label '{identifier}' (minimum similarity: 60%)",
            "object": None,
            "total_objects_searched": len(objects),
            "search_term": identifier,
            "match_type": "none"
        }

def get_node_oid_by_label(nodes, node_label):
    """
    Find a node's OID using fuzzy matching by its label.
    
    Args:
        nodes: List of nodes to search through
        node_label: The label to search for
        
    Returns:
        Dictionary with search results including OID and fuzzy match information
    """
    if not node_label:
        return {
            "error": "node_label must be provided",
            "oid": None
        }
    if not nodes:
        return {
            "error": "No nodes found in the graph",
            "oid": None
        }
    
    # First try exact match for backward compatibility
    for node in nodes:
        if node.get("label", "") == node_label:
            oid = node.get("oid") or node.get("id")
            if not oid:
                return {
                    "error": f"Node with label '{node_label}' does not have an OID or ID field",
                    "oid": None,
                    "node": node
                }
            return {
                "success": True, 
                "oid": oid,
                "match_type": "exact",
                "similarity_score": 100,
                "matched_label": node_label
            }
    
    # If no exact match, try fuzzy matching
    best_match, score = fuzzy_find_best_match(nodes, node_label, "label")
    
    if best_match:
        oid = best_match.get("oid") or best_match.get("id")
        if not oid:
            return {
                "error": f"Best match node with label '{best_match.get('label', '')}' does not have an OID or ID field",
                "oid": None,
                "node": best_match,
                "match_type": "fuzzy",
                "similarity_score": score
            }
        return {
            "success": True, 
            "oid": oid,
            "match_type": "fuzzy",
            "similarity_score": score,
            "search_term": node_label,
            "matched_label": best_match.get("label", "")
        }
    
    return {
        "error": f"No suitable match found for node label '{node_label}' (minimum similarity: 60%)",
        "oid": None,
        "total_nodes_searched": len(nodes),
        "search_term": node_label,
        "match_type": "none"
    }
