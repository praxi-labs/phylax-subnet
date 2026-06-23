from __future__ import annotations

import bittensor as bt


class TaskSynapse(bt.Synapse):
    track: str = ""
    artifact_ref: str = ""
    artifact_b64: str = ""
    nonce: str = ""
    probe: dict = {}
    sssa: dict = {}


class AgentSynapse(bt.Synapse):
    track: str = ""
    code: str = ""
    entrypoint: str = ""
    execution_api_key: str = ""
    inference_model: str = ""
    sandbox_image: str = ""
    sandbox_digest: str = ""
