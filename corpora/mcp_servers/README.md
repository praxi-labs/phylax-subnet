# MCP Servers Corpus

An MCP (Model Context Protocol) server is a program that exposes tools to an agent,
declared through a manifest. The defining attack surface is the **tool layer**: tools
whose descriptions manipulate the calling agent, manifests tampered from what they
claim, and tools that shadow or impersonate others.

## Artifact layout

```
mcp_servers/known-bad/poisoned-tool-desc/
├── manifest.json     declares the server's tools and their descriptions
├── server.py         the server implementation
└── label.json        the ground truth
```

The manifest is the heart of the artifact. It lists each tool, its declared schema,
and its description. The server implements those tools.

## How an MCP server is analysed

MCP servers are a **detonation track**. The miner's agent starts the server in the
sandbox, enumerates and exercises its tools, watches how it responds, and checks the
manifest for tampering and poisoned descriptions. The probe is threaded through and the
fs/network/process traces are captured.

The evidence is **dual-plane plus a protocol surface**:

- **action plane**: canonical capabilities the server exercised at runtime.
- **context plane**: instructions injected into the agent's reasoning. For MCP this is
  where poisoned tool descriptions live: a description that tells the agent to do
  something harmful is a context-plane attack.
- **mcp_surface**: the protocol-specific evidence, covering which tools are exposed,
  whether a tool's runtime behavior matches its declared schema, whether the manifest was
  tampered, and any tool poisoning, shadowing, or name-squatting.

The **evidence gate** is: probe in traces, trace hashes consistent, both planes
populated, and the tool surface inspected.

## The dual-plane point for MCP

The entire MCP attack class lives in the gap between what a tool **says** it does
(context plane: its description and schema) and what it **does** (action plane: its
observed behavior). An agent that only watches runtime side effects misses a poisoned
description that never itself acts; an agent that only reads descriptions misses a tool
whose behavior diverges from its honest-looking schema. Both planes are required.

## Finding categories for MCP servers

- `tool_poisoning`: a tool description injects instructions into the agent.
- `manifest_tamper`: the manifest differs from the server's real behavior.
- `tool_shadow`: a tool overrides or impersonates another tool.
- `schema_mismatch`: a tool's runtime behavior deviates from its declared schema.
- `context_injection`: external content pulled in by the server carries adversarial instructions.
- `overreach`: the server requests more capability than its stated purpose needs.

## known-good vs known-bad

- `known-good/`: honest servers whose tool descriptions match behavior and whose manifest
  is intact, with empty findings. Measures false positives.
- `known-bad/`: poisoned servers that should return BLOCK or WARN, with the expected
  findings and the `mcp_surface` block describing the poisoning.

See `_label.example.json` for the full label format.
