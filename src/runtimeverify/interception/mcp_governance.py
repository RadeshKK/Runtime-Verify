"""
Enterprise Model Context Protocol (MCP) Tool-to-Role Governance Framework for RuntimeVerify (Sprint 3).
Enforces fine-grained role-based access control (RBAC), tool scoping, and elevation gates
on MCP tool invocations within multi-agent swarms.
"""

from enum import Enum
import fnmatch
import logging
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)


class MCPGovernanceDecisionType(str, Enum):
    """Governance evaluation outcomes for MCP tool invocations."""

    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class MCPGovernanceDecision(BaseModel):
    """Structured decision rendered by the MCP governance engine."""

    model_config = ConfigDict(frozen=True)

    decision_id: str = Field(
        default_factory=lambda: f"mcp_dec_{uuid.uuid4().hex[:12]}",
        description="Unique decision ID",
    )
    decision: MCPGovernanceDecisionType = Field(..., description="ALLOW, REVIEW, or BLOCK")
    agent_id: str = Field(..., description="Agent calling the tool")
    agent_role: str = Field(..., description="Role of the agent")
    tool_name: str = Field(..., description="Target MCP tool")
    server_name: Optional[str] = Field(None, description="MCP server providing the tool")
    reason: str = Field(..., description="Justification for the decision")
    rule_matched: Optional[str] = Field(None, description="ID or description of matched rule")


class MCPRolePolicy(BaseModel):
    """RBAC policy rules assigned to an agent role for MCP tool access."""

    model_config = ConfigDict(frozen=True)

    role: str = Field(..., description="Agent role name (e.g. researcher, coder, orchestrator)")
    allowed_tools: List[str] = Field(
        default_factory=lambda: ["*"],
        description="Glob patterns of permitted MCP tools",
    )
    denied_tools: List[str] = Field(
        default_factory=list,
        description="Glob patterns of explicitly forbidden MCP tools",
    )
    require_approval_tools: List[str] = Field(
        default_factory=list,
        description="Glob patterns of MCP tools that require human dual-control approval",
    )


class MCPGovernanceEngine:
    """
    Central governance engine enforcing RBAC and dual-control elevation on MCP tool executions.
    """

    def __init__(
        self,
        policies: Optional[Dict[str, MCPRolePolicy]] = None,
        default_decision: MCPGovernanceDecisionType = MCPGovernanceDecisionType.BLOCK,
    ):
        self._policies: Dict[str, MCPRolePolicy] = policies or self._default_policies()
        self.default_decision = default_decision

    @staticmethod
    def _default_policies() -> Dict[str, MCPRolePolicy]:
        """Provides enterprise-grade secure defaults across standard swarm roles."""
        return {
            "orchestrator": MCPRolePolicy(
                role="orchestrator",
                allowed_tools=["*"],
                require_approval_tools=["*:delete_*", "*:drop_*", "*:push_*"],
            ),
            "coder": MCPRolePolicy(
                role="coder",
                allowed_tools=["fs:read_*", "fs:write_*", "git:status", "git:diff", "git:commit", "test:*"],
                denied_tools=["git:push_main", "fs:delete_root", "cloud:*"],
                require_approval_tools=["git:push*"],
            ),
            "researcher": MCPRolePolicy(
                role="researcher",
                allowed_tools=["web_search*", "fetch*", "read_*", "doc:*", "query*"],
                denied_tools=["fs:write*", "fs:delete*", "shell:*", "git:push*"],
            ),
            "tester": MCPRolePolicy(
                role="tester",
                allowed_tools=["test:*", "fs:read_*", "log:*"],
                denied_tools=["fs:delete*", "git:push*"],
            ),
            "worker": MCPRolePolicy(
                role="worker",
                allowed_tools=["read_*", "compute_*"],
                denied_tools=["shell:*", "cloud:*", "admin:*"],
            ),
        }

    def register_role_policy(self, policy: MCPRolePolicy) -> None:
        """Registers or overrides a role policy."""
        self._policies[policy.role.lower()] = policy

    def evaluate(
        self,
        agent_id: str,
        agent_role: str,
        tool_name: str,
        server_name: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> MCPGovernanceDecision:
        """
        Evaluates whether an agent with a given role is authorized to invoke an MCP tool.
        """
        role_key = agent_role.lower()
        full_tool_name = f"{server_name}:{tool_name}" if server_name else tool_name

        policy = self._policies.get(role_key)
        if policy is None:
            # Check wildcard role
            policy = self._policies.get("*")

        if policy is None:
            return MCPGovernanceDecision(
                decision=self.default_decision,
                agent_id=agent_id,
                agent_role=agent_role,
                tool_name=tool_name,
                server_name=server_name,
                reason=f"No MCP governance policy defined for role '{agent_role}'. Defaulting to {self.default_decision.value}.",
            )

        # 1. Check explicit denials (highest precedence)
        for pattern in policy.denied_tools:
            if fnmatch.fnmatch(tool_name, pattern) or fnmatch.fnmatch(full_tool_name, pattern):
                return MCPGovernanceDecision(
                    decision=MCPGovernanceDecisionType.BLOCK,
                    agent_id=agent_id,
                    agent_role=agent_role,
                    tool_name=tool_name,
                    server_name=server_name,
                    reason=f"Tool '{full_tool_name}' explicitly denied for role '{agent_role}' by pattern '{pattern}'.",
                    rule_matched=f"deny:{pattern}",
                )

        # 2. Check elevation / human approval requirement
        for pattern in policy.require_approval_tools:
            if fnmatch.fnmatch(tool_name, pattern) or fnmatch.fnmatch(full_tool_name, pattern):
                return MCPGovernanceDecision(
                    decision=MCPGovernanceDecisionType.REVIEW,
                    agent_id=agent_id,
                    agent_role=agent_role,
                    tool_name=tool_name,
                    server_name=server_name,
                    reason=f"Tool '{full_tool_name}' requires human dual-control approval for role '{agent_role}'.",
                    rule_matched=f"elevation:{pattern}",
                )

        # 3. Check allowed tools
        for pattern in policy.allowed_tools:
            if fnmatch.fnmatch(tool_name, pattern) or fnmatch.fnmatch(full_tool_name, pattern):
                return MCPGovernanceDecision(
                    decision=MCPGovernanceDecisionType.ALLOW,
                    agent_id=agent_id,
                    agent_role=agent_role,
                    tool_name=tool_name,
                    server_name=server_name,
                    reason=f"Tool '{full_tool_name}' authorized for role '{agent_role}' under pattern '{pattern}'.",
                    rule_matched=f"allow:{pattern}",
                )

        # 4. Fallback if not matched in allowed tools
        return MCPGovernanceDecision(
            decision=MCPGovernanceDecisionType.BLOCK,
            agent_id=agent_id,
            agent_role=agent_role,
            tool_name=tool_name,
            server_name=server_name,
            reason=f"Tool '{full_tool_name}' is not in allowed tools list for role '{agent_role}'.",
            rule_matched="fallback_deny",
        )
