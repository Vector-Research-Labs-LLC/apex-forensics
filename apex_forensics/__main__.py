"""Entry point: `python3 -m apex_forensics` starts the MCP server over stdio."""
from apex_forensics.server import mcp

if __name__ == "__main__":
    mcp.run()
