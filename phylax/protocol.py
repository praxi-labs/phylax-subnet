from __future__ import annotations

import bittensor as bt


class AgentSynapse(bt.Synapse):
    track: str = ""
    code: str = ""
    entrypoint: str = ""
    execution_api_key: str = ""
    inference_model: str = ""
    sandbox_image: str = ""
    sandbox_digest: str = ""
    agent_hash: str = ""
    signature: str = ""
