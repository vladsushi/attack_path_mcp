# Raptor API MCP Server

This project provides an **MCP (Model Context Protocol) server** that integrates with the Raptor API for identity graph analysis and attack path discovery.

---

## Available MCP Tools

### Core Operations
- **`ping`**: Health check for API responsiveness
- **`get_environment_metadata`**: Retrieve environment configuration
- **`reset_graph`**: Reset the identity graph database
- **`sync`**: Synchronize with external identity systems

### Zone Management
- **`get_zones`**: List all security zones
- **`create_zone`**: Create new security zones
- **`remove_zone`**: Delete existing zones
- **`edit_zone`**: Modify zone properties
- **`get_zone_data`**: Retrieve zone member details
- **`get_zone_isolation_scores`**: Calculate inter-zone security isolation

### Graph Operations
- **`query_graph`**: Flexible graph querying with filters
- **`export_graph`**: Export graph data for external analysis
- **`update_graph`**: Update node zone assignments
- **`migrate_previous_data`**: Import data from previous installations

### Identity Object Queries
- **`query_object_by_oid`**: Get object details by Object ID from Protobuff
- **`query_node_by_oid`**: Batch retrieve multiple objects from Trinity Database
- **`query_object_by_label`**: Find object by label from Protobuff
- **`query_node_by_label`**: Find node by label from Trinity Database
- **`get_object_stats`**: Get comprehensive object statistics from Protobuff
- **`get_node_stats`**: Get comprehensive node statistics from Trinity Database
- **`set_initial_tier0`**: Designate Tier 0 critical assets

### Attack Path Analysis
- **`determine_attack_paths`**: Primary attack path discovery tool
- **`reachability_report`**: Analyze object reachability scope
- **`node_reachability`**: Specific node-to-target path analysis
- **`find_risk_reduction`**: Identify security improvement opportunities
- **`export_attack_paths`**: Export attack data for reporting
- **`find_and_classify_zero_cost_paths`**: Discover immediate attack vectors
- **`get_attack_path_summary`**: Retrieve attack path summaries

### Memory Management
- **`save_memory`**: Store conversation exchanges for future reference
- **`retrieve_memory`**: Search and retrieve relevant past conversations
- **`clear_memory`**: Reset the conversation memory store
- **`get_vectorstore_stats`**: Get statistics about the vectorstore

### Synchronization
- **`get_sync_progress`**: Monitor data collection progress

### Thinking Tools
- **`think`**: Tool for complex reasoning and planning multi-step operations

---

## Using the MCP Server

> **IMPORTANT:**
> Prior to setting up the MCP server, configure access to Staraptor and make sure you have access to this page: [https://mcp.staraptor.research.semperis.cloud/](https://mcp.staraptor.research.semperis.cloud/)
> It contains your personal MCP Server location and Access Token.

---

## Testing Tools with MCP Inspector

Debug and test the server using the MCP Inspector:

1. Run the following in your terminal:

   ```bash
   npx @modelcontextprotocol/inspector
   ```
2. Open [http://127.0.0.1:6274/](http://127.0.0.1:6274/) in your browser.
3. Choose transport type **Streamable HTTP**.
4. Paste `https://mcp.staraptor.research.semperis.cloud/mcp/` in the **URL** field.
5. Click **Connect**.
6. Choose the tool you would like to test in the **Tools** tab.
7. Input the arguments and click **Run Tool**.

---

## Connecting the MCP Server to Cline (via VS Code)

1. In Cline, open the **MCP Servers** tab on the top right.
2. Click **Installed** → **Configure MCP Servers**. This will open `cline_mcp_settings.json` in your environment.
3. Paste the following configuration:

   ```json
   {
     "mcpServers": {
       "StaRaptorAPI": {
         "autoApprove": [],
         "disabled": false,
         "timeout": 60,
         "type": "streamableHttp",
         "url": "https://mcp.staraptor.research.semperis.cloud/mcp/",
         "headers": {
           "Authorization": "Bearer <your_access_token_copied_from_StaRaptor>"
         }
       }
     }
   }
   ```

4. Save `cline_mcp_settings.json`.
5. The server should appear in the list of installed servers in Cline with a green dot, indicating a successful connection.

---

## Connecting the MCP Server to GitHub Copilot (via VS Code)

1. Navigate to **Configure Tools** (small icon next to the query input window).
2. Click **Add more Tools** (bottom of the dropdown menu).
3. Select **HTTP**.
4. Paste `https://mcp.staraptor.research.semperis.cloud/mcp/`.
5. Write the server name.
6. Choose if the server should be available in the current workspace or in all the workspaces.

You will then be prompted to EntraID authentication menu. The MCP server will be functional after a successful authentication.

After authentication, the tool list should be available under the **Configure Tools** button in GitHub Copilot Agent. They can be manually activated/deactivated for the LLM.

For more details, refer to this guide: [GitHub Copilot MCP Integration](https://docs.github.com/en/copilot/customizing-copilot/using-model-context-protocol/extending-copilot-chat-with-mcp)

---

## Connecting the MCP Server to Claude Desktop

1. Navigate to **File** → **Settings** → **Developer** → **Edit Config** and open `claude_desktop_config.json`.

   Alternatively, on Windows, you can find the MCP config file under:

   ```
   C:\Users\<username>\AppData\Roaming\Claude\claude_desktop_config.json
   ```

2. Paste the following to the JSON file and save it:

   ```json
   {
     "StaRaptorAPI": {
       "command": "npx",
       "args": [
         "mcp-remote",
         "https://mcp.staraptor.research.semperis.cloud/mcp/"
       ]
     }
   }
   ```

3. Press **File** → **Exit** in Claude Desktop if it is running, and then rerun Claude Desktop. You will be prompted to EntraID authentication menu. The MCP server will be functional after a successful authentication.

For more details, refer to this guide: [Claude Desktop Quickstart](https://modelcontextprotocol.io/quickstart/user#windows)

---

## Running Tests

This project includes two main test files in the root directory:

- `test_raptor_mcp_tools.py`: Tests MCP server integration and API tools.
- `test_raptor_utils.py`: Tests utility functions and classes.

### Requirements

- All test dependencies are listed in `requirements.txt` (including `pytest` and `pytest-asyncio` if not already present).
- To install all requirements:

  ```bash
  pip install -r requirements.txt
  ```

### Running All Tests

You can run all tests in the project root using:

```bash
pytest
```

### Running a Specific Test File

To run a specific test file:

```bash
pytest test_raptor_mcp_tools.py
```

Or:

```bash
pytest test_raptor_utils.py
```

### Running a Specific Test Function

To run a single test function (e.g., `test_ping` in `test_raptor_mcp_tools.py`):

```bash
pytest test_raptor_mcp_tools.py -k test_ping
```

### Additional Options

- Add `-v` for verbose output: `pytest -v`
- Add `-s` to see print statements: `pytest -s`
