"""
Benchmark Scenarios & Case Definitions for Security Benchmark Framework (Phase 13).
Defines the 9 canonical security scenarios and structured benchmark test cases.
"""

from enum import Enum
from typing import Any, Dict, List
from pydantic import BaseModel, Field

from runtimeverify.interception.models import Action


class BenchmarkScenario(str, Enum):
    """
    The 9 canonical security benchmark scenarios evaluated by RuntimeVerify.
    """

    NORMAL_CODING = "normal_coding"
    CREDENTIAL_ACCESS = "credential_access"
    SECRET_EXFILTRATION = "secret_exfiltration"
    DESTRUCTIVE_SHELL = "destructive_shell"
    SUSPICIOUS_NETWORK = "suspicious_network"
    PROMPT_INJECTION = "prompt_injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ABNORMAL_TOOL_USAGE = "abnormal_tool_usage"
    AGENT_TO_AGENT_ABUSE = "agent_to_agent_abuse"

    @property
    def display_name(self) -> str:
        names = {
            BenchmarkScenario.NORMAL_CODING: "Normal Coding",
            BenchmarkScenario.CREDENTIAL_ACCESS: "Credential Access",
            BenchmarkScenario.SECRET_EXFILTRATION: "Secret Exfiltration",
            BenchmarkScenario.DESTRUCTIVE_SHELL: "Destructive Shell",
            BenchmarkScenario.SUSPICIOUS_NETWORK: "Suspicious Network",
            BenchmarkScenario.PROMPT_INJECTION: "Prompt Injection",
            BenchmarkScenario.PRIVILEGE_ESCALATION: "Privilege Escalation",
            BenchmarkScenario.ABNORMAL_TOOL_USAGE: "Abnormal Tool Usage",
            BenchmarkScenario.AGENT_TO_AGENT_ABUSE: "Agent-to-Agent Abuse",
        }
        return names.get(self, self.value)

    @property
    def default_ground_truth(self) -> bool:
        """True if the scenario represents an attack or unauthorized violation."""
        return self != BenchmarkScenario.NORMAL_CODING


class BenchmarkCase(BaseModel):
    """
    A single reproducible benchmark test case comprising one or more agent actions,
    ground-truth classification, and expected verification verdicts.
    """

    case_id: str = Field(..., description="Unique case identifier (e.g. case-cred-001)")
    scenario: BenchmarkScenario = Field(..., description="Target benchmark scenario")
    name: str = Field(..., description="Short descriptive title of the case")
    description: str = Field("", description="Detailed behavioral context and rationale")
    is_attack: bool = Field(..., description="True if this represents an attack, False if benign")
    expected_verdict: str = Field("ALLOW", description="Expected policy verdict (ALLOW, BLOCK, REVIEW)")
    is_synthetic: bool = Field(True, description="True for synthetic simulation, False for real-world telemetry")
    actions: List[Action] = Field(default_factory=list, description="Sequence of actions to evaluate")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional environment or test parameters")
