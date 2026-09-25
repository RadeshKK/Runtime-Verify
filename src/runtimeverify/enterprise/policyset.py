"""
Hierarchical PolicySet Management and Ownership for Enterprise RuntimeVerify (Phase 18).
Enforces hierarchical inheritance (Tenant -> Organization -> Project -> Environment)
and immutable global enterprise guardrails.
"""

from collections import defaultdict
import copy
import hashlib
import json
import threading
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from runtimeverify.enterprise.models import Environment, PolicySet, PolicySetScope


class PolicySetResolutionResult(BaseModel):
    """
    Combined effective policies resolved across the enterprise hierarchy.
    """

    model_config = ConfigDict(frozen=True)

    tenant_id: str
    organization_id: Optional[str]
    project_id: Optional[str]
    environment: Environment
    resolved_policies: List[Dict[str, Any]] = Field(default_factory=list)
    applied_policyset_ids: List[str] = Field(default_factory=list)
    immutable_guardrails_applied: bool = Field(default=False)
    digest: str = Field(..., description="Cryptographic SHA-256 digest of the effective policy bundle")


class PolicySetManager:
    """
    Manages registration, versioning, ownership, and hierarchical resolution
    of PolicySets across multi-tenant organizations.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # Storage: id -> PolicySet
        self._policysets: Dict[str, PolicySet] = {}
        # Tenant index: tenant_id -> list of policyset ids
        self._tenant_index: Dict[str, List[str]] = defaultdict(list)

    def register_policyset(self, policyset: PolicySet) -> PolicySet:
        """Registers or updates a PolicySet."""
        with self._lock:
            # Check immutability update rule
            existing = self._policysets.get(policyset.id)
            if existing and existing.immutable and not policyset.immutable:
                raise ValueError(f"Cannot revoke immutability on PolicySet '{policyset.id}'.")

            self._policysets[policyset.id] = policyset
            if policyset.id not in self._tenant_index[policyset.tenant_id]:
                self._tenant_index[policyset.tenant_id].append(policyset.id)
            return policyset

    def get_policyset(self, policyset_id: str) -> Optional[PolicySet]:
        """Retrieves a PolicySet by ID."""
        with self._lock:
            return self._policysets.get(policyset_id)

    def list_by_tenant(self, tenant_id: str) -> List[PolicySet]:
        """Lists all PolicySets belonging to a tenant."""
        with self._lock:
            ids = self._tenant_index.get(tenant_id, [])
            return [self._policysets[pid] for pid in ids if pid in self._policysets]

    def delete_policyset(self, policyset_id: str) -> bool:
        """Deletes a PolicySet, unless it is marked immutable."""
        with self._lock:
            ps = self._policysets.get(policyset_id)
            if not ps:
                return False
            if ps.immutable:
                raise ValueError(f"Cannot delete immutable PolicySet '{policyset_id}'.")
            del self._policysets[policyset_id]
            if ps.id in self._tenant_index.get(ps.tenant_id, []):
                self._tenant_index[ps.tenant_id].remove(ps.id)
            return True

    def resolve_effective_policies(
        self,
        tenant_id: str,
        organization_id: Optional[str] = None,
        project_id: Optional[str] = None,
        environment: Environment = Environment.DEVELOPMENT,
    ) -> PolicySetResolutionResult:
        """
        Resolves effective policy rules according to strict hierarchical precedence:
        1. Tenant-level global guardrails (Scope=TENANT, immutable=True)
        2. Tenant-level standard policies (Scope=TENANT)
        3. Organization policies (Scope=ORGANIZATION, matching org_id)
        4. Project policies (Scope=PROJECT, matching proj_id)
        Each level filters by environment (applies if policyset.environment is None or matches).
        """
        with self._lock:
            tenant_sets = self.list_by_tenant(tenant_id)

        # Categorize candidates
        immutable_guardrails: List[PolicySet] = []
        tenant_policies: List[PolicySet] = []
        org_policies: List[PolicySet] = []
        project_policies: List[PolicySet] = []

        for ps in tenant_sets:
            # Check environment compatibility
            if ps.environment is not None and ps.environment != environment:
                continue

            # Scope categorization
            if ps.scope == PolicySetScope.TENANT:
                if ps.immutable:
                    immutable_guardrails.append(ps)
                else:
                    tenant_policies.append(ps)
            elif ps.scope == PolicySetScope.ORGANIZATION:
                if organization_id and ps.organization_id == organization_id:
                    org_policies.append(ps)
            elif ps.scope == PolicySetScope.PROJECT:
                if project_id and ps.project_id == project_id:
                    project_policies.append(ps)

        # Ordered merge: Tenant Immutable Guardrails -> Tenant General -> Org -> Project
        ordered_sets: List[PolicySet] = immutable_guardrails + tenant_policies + org_policies + project_policies

        resolved_policies: List[Dict[str, Any]] = []
        applied_ids: List[str] = []

        for p_set in ordered_sets:
            applied_ids.append(p_set.id)
            for rule in p_set.policies:
                rule_copy = copy.deepcopy(rule)
                rule_copy["_source_policyset_id"] = p_set.id
                rule_copy["_source_scope"] = p_set.scope.value
                rule_copy["_immutable"] = p_set.immutable
                resolved_policies.append(rule_copy)

        # Calculate cryptographic digest of effective rules
        serialized = json.dumps(resolved_policies, sort_keys=True, default=str)
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        return PolicySetResolutionResult(
            tenant_id=tenant_id,
            organization_id=organization_id,
            project_id=project_id,
            environment=environment,
            resolved_policies=resolved_policies,
            applied_policyset_ids=applied_ids,
            immutable_guardrails_applied=len(immutable_guardrails) > 0,
            digest=digest,
        )
