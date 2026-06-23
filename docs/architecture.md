# Architecture

The subnet is the decentralized part: `neurons/miner.py` serves an axon (runs the
agent on dispatched tasks, returns the signed SSSA, serves the agent for reruns),
`neurons/validator.py` dispatches tasks, verifies, scores, reruns a sample, and
sets weights, `phylax/protocol.py` defines the synapses, and `phylax/analysis/`
holds the scoring and proof code the validator runs. The separate phylax-server is
product only and never in the protocol path.

The full module map and the data flow are in the canonical docs:

https://docs.phyi.dev/system/architecture
