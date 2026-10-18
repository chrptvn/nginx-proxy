"""HeaderProxy — a session-scoped HTTP header injection proxy.

The package runs two planes in a single process:

* a **data plane**: an asyncio forward proxy (plain HTTP and TLS-via-CONNECT
  with on-the-fly certificate generation) that rewrites request and response
  headers according to the active session's rules and forwards traffic to
  origins through a Chrome-impersonating upstream client;
* a **control plane**: a FastAPI REST API and an MCP (Model Context Protocol)
  server exposing the exact same operations as tools.
"""

__version__ = "0.1.0"
