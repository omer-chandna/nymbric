"""Reference clients for the live spear-phish target.

These connect to a running :class:`~nymbric.agents.target.live_server.ToolSessionServer`
and drive the inert target tools, demonstrating the closed-loop integration end to
end. ``reference_client`` is runnable (``python -m
nymbric.agents.target.clients.reference_client``) and supports a deterministic mock
policy (CI-safe) and a real local-model policy (Ollama).
"""
