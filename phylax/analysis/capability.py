from __future__ import annotations

import enum
from dataclasses import dataclass


class ProtectionLevel(str, enum.Enum):
    NORMAL = "normal"
    DANGEROUS = "dangerous"
    SYSTEM = "system"
    REDACT = "redact"


class CapabilityGroup(str, enum.Enum):
    FILESYSTEM = "filesystem"
    PROCESS_EXECUTION = "process_execution"
    NETWORK = "network"
    SECRETS_CREDENTIALS = "secrets_credentials"
    DATABASE = "database"
    CRYPTOGRAPHY_KEYS = "cryptography_keys"
    SYSTEM_HOST = "system_host"
    CONTEXT_REASONING = "context_reasoning"
    AGENT_TOOLING = "agent_tooling"
    SOURCE_REPOSITORY = "source_repository"
    MCP_PROTOCOL = "mcp_protocol"
    SUPPLY_CHAIN = "supply_chain"


_SEVERITY: dict[ProtectionLevel, float] = {
    ProtectionLevel.NORMAL: 0.10,
    ProtectionLevel.DANGEROUS: 0.60,
    ProtectionLevel.SYSTEM: 0.85,
    ProtectionLevel.REDACT: 1.00,
}


@dataclass(frozen=True)
class Permission:
    name: str
    group: CapabilityGroup
    protection: ProtectionLevel

    @property
    def severity(self) -> float:
        return _SEVERITY[self.protection]


_N = ProtectionLevel.NORMAL
_D = ProtectionLevel.DANGEROUS
_S = ProtectionLevel.SYSTEM
_R = ProtectionLevel.REDACT

CG = CapabilityGroup

_GROUPS: dict[CapabilityGroup, tuple[tuple[str, ProtectionLevel], ...]] = {
    CG.FILESYSTEM: (
        ("READ_FILE", _N),
        ("LIST_DIRECTORY", _N),
        ("WRITE_FILE", _D),
        ("DELETE_FILE", _D),
    ),
    CG.PROCESS_EXECUTION: (
        ("START_REPL", _D),
        ("CREATE_PROCESS", _D),
        ("EXEC_SHELL", _D),
        ("RUN_CONTAINER", _D),
    ),
    CG.NETWORK: (
        ("RESOLVE_DNS", _N),
        ("FETCH_WEB", _N),
        ("POST_WEB", _D),
        ("CALL_EXTERNAL_API", _D),
        ("OPEN_SOCKET", _D),
    ),
    CG.SECRETS_CREDENTIALS: (
        ("READ_SECRETS", _R),
        ("WRITE_SECRETS", _R),
        ("READ_KEYCHAIN", _R),
        ("READ_ENV_SECRETS", _R),
    ),
    CG.DATABASE: (
        ("DB_CONNECT", _N),
        ("DB_READ", _D),
        ("DB_WRITE", _D),
        ("DB_EXPORT", _R),
    ),
    CG.CRYPTOGRAPHY_KEYS: (
        ("ENCRYPT_DATA", _N),
        ("SIGN_DATA", _D),
        ("READ_PRIVATE_KEY", _R),
        ("ACCESS_WALLET", _R),
    ),
    CG.SYSTEM_HOST: (
        ("SET_ENV_VAR", _D),
        ("WRITE_SHELL_PROFILE", _S),
        ("INSTALL_PACKAGE", _S),
        ("SCHEDULE_JOB", _S),
        ("MODIFY_HOSTS_FILE", _S),
    ),
    CG.CONTEXT_REASONING: (
        ("LOAD_EXTERNAL_CONTEXT", _D),
        ("INJECT_INSTRUCTION", _S),
        ("OVERRIDE_SYSTEM_PROMPT", _S),
        ("POISON_MEMORY", _S),
    ),
    CG.AGENT_TOOLING: (
        ("INVOKE_TOOL", _N),
        ("LOAD_CONTEXT", _N),
        ("DELEGATE_SUBAGENT", _D),
        ("MODIFY_POLICY", _S),
        ("MODIFY_HOOKS", _S),
    ),
    CG.SOURCE_REPOSITORY: (
        ("READ_SOURCE_HISTORY", _N),
        ("CLONE_REPOSITORY", _N),
        ("EXECUTE_SOURCE_CODE", _D),
        ("PUSH_COMMIT", _S),
    ),
    CG.MCP_PROTOCOL: (
        ("EXPOSE_TOOL", _N),
        ("TOOL_SCHEMA_MISMATCH", _D),
        ("TOOL_SHADOW", _D),
        ("MANIFEST_TAMPER", _S),
    ),
    CG.SUPPLY_CHAIN: (
        ("IMPORT_SIDE_EFFECT", _D),
        ("TYPOSQUAT", _D),
        ("DEPENDENCY_CONFUSION", _D),
        ("INSTALL_HOOK_EXEC", _S),
        ("POSTINSTALL_SCRIPT", _S),
    ),
}

CORE_GROUPS: tuple[CapabilityGroup, ...] = (
    CG.FILESYSTEM,
    CG.PROCESS_EXECUTION,
    CG.NETWORK,
    CG.SECRETS_CREDENTIALS,
    CG.DATABASE,
    CG.CRYPTOGRAPHY_KEYS,
    CG.SYSTEM_HOST,
    CG.CONTEXT_REASONING,
)

TRACK_GROUPS: dict[str, tuple[CapabilityGroup, ...]] = {
    "skills": CORE_GROUPS + (CG.AGENT_TOOLING, CG.SOURCE_REPOSITORY),
    "mcp_servers": CORE_GROUPS + (CG.AGENT_TOOLING, CG.MCP_PROTOCOL),
    "packages": CORE_GROUPS + (CG.SUPPLY_CHAIN,),
    "repositories": (),
}

TAXONOMY: tuple[Permission, ...] = tuple(
    Permission(name=name, group=group, protection=level)
    for group, perms in _GROUPS.items()
    for name, level in perms
)

_INDEX: dict[str, Permission] = {p.name: p for p in TAXONOMY}


def lookup(name: str) -> Permission | None:
    return _INDEX.get(name)


def is_canonical(name: str) -> bool:
    return name in _INDEX


def severity_for(name: str) -> float:
    perm = _INDEX.get(name)
    return perm.severity if perm else 0.0


def protection_for(name: str) -> ProtectionLevel | None:
    perm = _INDEX.get(name)
    return perm.protection if perm else None


def group_for(name: str) -> CapabilityGroup | None:
    perm = _INDEX.get(name)
    return perm.group if perm else None


def group_permissions(group: CapabilityGroup) -> tuple[Permission, ...]:
    return tuple(p for p in TAXONOMY if p.group is group)


def groups_for_track(track: str) -> tuple[CapabilityGroup, ...]:
    return TRACK_GROUPS.get(track, ())


def vocabulary_for(track: str) -> frozenset[str]:
    groups = set(TRACK_GROUPS.get(track, ()))
    return frozenset(p.name for p in TAXONOMY if p.group in groups)


def is_valid_for(track: str, name: str) -> bool:
    perm = _INDEX.get(name)
    return perm is not None and perm.group in TRACK_GROUPS.get(track, ())


def all_names() -> frozenset[str]:
    return frozenset(_INDEX)


def manifest_severity(capabilities: list) -> float:
    best = 0.0
    for entry in capabilities:
        name = entry if isinstance(entry, str) else entry.get("capability", "")
        best = max(best, severity_for(name))
    return best
