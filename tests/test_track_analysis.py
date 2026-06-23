from phylax.analysis import (
    capability,
    mcp,
    packages,
    proof,
    repositories,
    scoring,
    skills,
    tracks,
)


def _valid_evidence(probe, capabilities, injected):
    return {
        "proof_of_execution": {
            "probe_evidence": probe.expected_probe_evidence(),
            "traces": {
                "filesystem": {"hash": "", "events": [{"path": probe.file_path}]},
                "network": {"hash": "", "events": [{"domain": probe.dns_host}]},
                "process": {"hash": "", "events": [{"cmd": "echo", "args": [probe.process_echo]}]},
            },
        },
        "action_plane": {"capabilities": capabilities},
        "context_plane": {"injected_instructions": injected},
        "capability_manifest": [c["capability"] if isinstance(c, dict) else c for c in capabilities],
    }


def test_capability_track_isolation():
    assert capability.is_valid_for("packages", "INSTALL_HOOK_EXEC")
    assert not capability.is_valid_for("skills", "INSTALL_HOOK_EXEC")
    assert capability.severity_for("WRITE_SHELL_PROFILE") == 0.85
    assert capability.vocabulary_for("repositories") == frozenset()


def test_proof_roundtrip_and_tamper():
    probe = proof.derive_probe(proof.new_nonce())
    ev = _valid_evidence(probe, ["POST_WEB"], [{"text": "leak"}])
    assert proof.verify_proof_of_execution(probe, ev, detonation=True).passed
    ev["proof_of_execution"]["probe_evidence"]["canary"] = "tampered"
    assert not proof.verify_proof_of_execution(probe, ev, detonation=True).passed


def test_skills_correct_verdict_scores_and_manifest():
    probe = proof.derive_probe(proof.new_nonce())
    ev = _valid_evidence(probe, ["WRITE_SHELL_PROFILE", "POST_WEB"], [{"text": "exfil"}])
    out = skills.evaluate(ev, "BLOCK", label="malicious", probe=probe)
    assert out.result.gate_passed
    assert out.result.score > 0.5
    assert len(out.capability_manifest) == 2


def test_skills_wrong_verdict_scores_lower():
    probe = proof.derive_probe(proof.new_nonce())
    ev = _valid_evidence(probe, ["WRITE_SHELL_PROFILE"], [{"text": "exfil"}])
    right = skills.evaluate(ev, "BLOCK", label="malicious", probe=probe).result.score
    wrong = skills.evaluate(ev, "ALLOW", label="malicious", probe=probe).result.score
    assert wrong < right


def test_emission_weights_top3_and_track_emphasis():
    scores = {
        "skills": [("s1", 0.9), ("s2", 0.8), ("s3", 0.7), ("s4", 0.6)],
        "repositories": [("r1", 0.9), ("r2", 0.5)],
    }
    w = scoring.compute_emission_weights(scores)
    assert "s4" not in w
    assert abs(sum(w.values()) - 1.0) < 1e-9
    assert w["s1"] > w["s2"] > w["s3"]
    assert w["r1"] > w["s1"]


def test_emission_weights_empty():
    assert scoring.compute_emission_weights({}) == {}
    assert scoring.compute_emission_weights({"skills": [("a", 0.0)]}) == {}


def test_emission_weights_contribution_pool():
    scores = {"skills": [("s1", 0.9), ("s2", 0.8)], "repositories": [("r1", 0.9)]}
    base = scoring.compute_emission_weights(scores)
    withpool = scoring.compute_emission_weights(scores, contributor_hotkeys={"s2", "outsider"})
    assert abs(sum(withpool.values()) - 1.0) < 1e-9
    assert withpool["s2"] > base["s2"]
    assert withpool["s1"] < base["s1"]
    assert "outsider" not in withpool


def test_emission_weights_no_contributors_matches_base():
    scores = {"skills": [("s1", 0.9), ("s2", 0.8)]}
    assert scoring.compute_emission_weights(scores, contributor_hotkeys=set()) == scoring.compute_emission_weights(scores)


def test_skills_evidence_gate_zeroes():
    probe = proof.derive_probe(proof.new_nonce())
    no_proof = skills.evaluate({"action_plane": {}, "context_plane": {}}, "BLOCK", label="malicious", probe=probe)
    assert no_proof.result.score == 0.0 and not no_proof.result.gate_passed

    ev = _valid_evidence(probe, ["POST_WEB"], [{"text": "x"}])
    ev.pop("context_plane")
    assert skills.evaluate(ev, "BLOCK", label="malicious", probe=probe).result.score == 0.0


def test_mcp_evaluator_gate_and_score():
    probe = proof.derive_probe(proof.new_nonce())
    ev = _valid_evidence(probe, ["POST_WEB"], [{"text": "x"}])
    ev["mcp_surface"] = {
        "exposed_tools": [{"name": "t", "schema_mismatch": True}],
        "tool_poisoning": [{"tool": "t", "type": "desc"}],
    }
    out = mcp.evaluate(ev, "BLOCK", label="malicious", probe=probe)
    assert out.result.gate_passed and out.result.score > 0.4
    ev.pop("mcp_surface")
    assert mcp.evaluate(ev, "BLOCK", label="malicious", probe=probe).result.score == 0.0


def test_packages_evaluator():
    probe = proof.derive_probe(proof.new_nonce())
    base = _valid_evidence(probe, [], [])
    ev = {
        "proof_of_execution": base["proof_of_execution"],
        "action_plane": {"capabilities": ["INSTALL_HOOK_EXEC"]},
        "lifecycle": {"install_time": {"hook_executed": True, "capabilities": ["INSTALL_HOOK_EXEC"]}},
        "supply_chain": {"dependencies": [{"name": "x", "cve": ["CVE-1"]}], "typosquat": {"suspected": True}},
    }
    out = packages.evaluate(ev, "BLOCK", label="malicious", probe=probe)
    assert out.result.gate_passed and out.result.score > 0.4
    ev.pop("supply_chain")
    assert packages.evaluate(ev, "BLOCK", label="malicious", probe=probe).result.score == 0.0


def test_repositories_evaluator():
    vuln = repositories.evaluate(
        {"audit": {"files_analysed": 5}, "vulnerabilities": [{"cwe": "CWE-89", "remediation": "use params"}]},
        "BLOCK", label="vulnerable", probe=None,
    )
    assert vuln.result.gate_passed and vuln.result.score > 0.4
    clean = repositories.evaluate(
        {"audit": {"files_analysed": 5}, "vulnerabilities": []}, "ALLOW", label="clean", probe=None
    )
    assert clean.result.gate_passed
    nope = repositories.evaluate({"audit": {"files_analysed": 0}}, "ALLOW", label="clean", probe=None)
    assert nope.result.score == 0.0


def test_dispatcher_routes_each_track():
    probe = proof.derive_probe(proof.new_nonce())
    ev = _valid_evidence(probe, ["POST_WEB"], [{"text": "x"}])
    assert tracks.evaluate("skills", ev, "BLOCK", label="malicious", probe=probe).result.gate_passed
    assert tracks.evaluate("bogus", ev, "BLOCK", label="malicious", probe=probe).result.score == 0.0
