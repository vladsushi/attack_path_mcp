# Attack Paths MCP Server

This project provides an **MCP (Model Context Protocol) server** that integrates with the Raptor API for AI-powered attack path analysis using SignalR streaming.

## Overview

The Attack Paths MCP Server enables real-time analysis of security attack paths between source and target objects in identity environments. It leverages SignalR for streaming AI-generated summaries and provides structured analysis of security risks, relationships, and remediation recommendations.

## Features

- **Real-time SignalR streaming** for attack path analysis
- **AI-powered analysis** with structured JSON output
- **Flexible path selection** for multiple attack paths scenarios
- **Comprehensive security analysis** including Objects, Relationships, KeyPointsOfConcern, and Conclusions
- **Automatic path detection** and intelligent handling of single vs multiple paths

## Available MCP Tool

### `detailed_attack_path_analysis`

Performs AI-powered analysis of attack paths between source and target objects.

**Parameters:**
- `source_oid` (required): Object identifier of the attack source
- `target_oid` (required): Object identifier of the attack target
- `attack_path_id` (optional): Specific attack path ID when multiple paths exist

**Behavior:**
- **Single path found**: Automatically generates structured AI analysis
- **Multiple paths found**: Returns raw attack path data with selection prompt
- **Specific path requested**: Analyzes the selected attack path by ID
- **No paths found**: Returns descriptive error

**Analysis Output Format:**
The AI analysis provides structured JSON containing:
- **Objects**: Detailed descriptions of entities in the attack path
- **Relationships**: Security-relevant connections and permissions
- **KeyPointsOfConcern**: Critical security issues and risks identified
- **Conclusion**: Executive summary with remediation recommendations

**Response Types:**
- `attack_path_analysis`: Complete structured analysis (JSON string)
- `attack_paths_response`: Raw API response with all available paths
- `message`: User guidance for path selection
- `error`: Detailed error description with available options

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/vladsushi/attack_path_mcp.git
   cd attack_path_mcp
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables:**
   Create a `.env` file based on `.env.template`:
   ```bash
   cp .env.template .env
   ```
   
   Edit `.env` and configure:
   ```
   RAPTOR_TOKEN=your_raptor_api_token
   RAPTOR_URL=http://localhost:5000
   ```

## Running the Server

### Local Development
```bash
python attack_paths_server.py
```

### Custom Configuration
```bash
python attack_paths_server.py -raptor_token YOUR_TOKEN -raptor_url http://your-raptor-instance:5000 -host 0.0.0.0 -port 8003
```

### Command Line Options
- `-raptor_token`: Override RAPTOR_TOKEN for API access
- `-raptor_url`: Override RAPTOR_URL for SignalR hub access (default: http://localhost:5000)
- `-host`: Host to bind the server to (default: 127.0.0.1)
- `-port`: Port to bind the server to (default: 8003)
- `-path`: URL path for the MCP endpoint (default: /mcp)

## Testing with MCP Inspector

Debug and test the server using the MCP Inspector:

1. **Start the server:**
   ```bash
   python attack_paths_server.py
   ```

2. **Run MCP Inspector:**
   ```bash
   npx @modelcontextprotocol/inspector
   ```

3. **Connect to the server:**
   - Open [http://127.0.0.1:6274/](http://127.0.0.1:6274/) in your browser
   - Choose transport type **Streamable HTTP**
   - Enter URL: `http://127.0.0.1:8003/mcp`
   - Click **Connect**

4. **Test the tool:**
   - Go to the **Tools** tab
   - Select `detailed_attack_path_analysis`
   - Provide `source_oid` and `target_oid` parameters
   - Click **Run Tool**
