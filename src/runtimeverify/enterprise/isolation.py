"""
Multi-Tenant Isolation Engine and Partitioned Storage for RuntimeVerify (Phase 18).
Guarantees strict tenant data isolation, prevention of cross-tenant data leakage,
and partitioned storage primitives.
"""

from collections import defaultdict
import threading
from typing import Any, Dict, Generic, List, Optional, TypeVar
from pydantic import BaseModel, ConfigDict, Field

from runtimeverify.enterprise.context import EnterpriseContext
from runtimeverify.enterprise.models import Environment


class TenantIsolationViolationError(Exception):
    """Raised when an operation attempts unauthorized cross-tenant data access or modification."""

    pass


class TenantPartitionKey(BaseModel):
    """
    Composite key defining exact multi-tenant data partitioning boundaries.
    """

    model_config = ConfigDict(frozen=True)

    tenant_id: str
    organization_id: Optional[str] = None
    project_id: Optional[str] = None
    environment: Environment = Field(default=Environment.DEVELOPMENT)

    def to_string(self) -> str:
        return f"{self.tenant_id}:{self.organization_id or '*'}:{self.project_id or '*'}:{self.environment.value}"


class TenantIsolationEngine:
    """
    Central enforcement engine for tenant and environment isolation boundaries.
    """

    @classmethod
    def enforce_access(
        cls,
        context: Optional[EnterpriseContext],
        target_tenant_id: str,
        resource_description: str = "resource",
    ) -> None:
        """
        Enforces that the ambient context has authorization to access target_tenant_id.
        Raises TenantIsolationViolationError on mismatch.
        """
        if context is None:
            raise TenantIsolationViolationError(
                f"Missing EnterpriseContext: unauthenticated access to {resource_description} in tenant '{target_tenant_id}' rejected."
            )

        # Allow super_admin to perform system-level management if explicitly authorized
        if context.has_role("super_admin"):
            return

        if context.tenant_id != target_tenant_id:
            raise TenantIsolationViolationError(
                f"Tenant isolation violation: context tenant '{context.tenant_id}' cannot access {resource_description} in tenant '{target_tenant_id}'."
            )

    @classmethod
    def enforce_environment(
        cls,
        context: EnterpriseContext,
        target_environment: Environment,
        operation_name: str = "operation",
    ) -> None:
        """
        Enforces that operations within a context match the target environment.
        Prevents dev context from touching prod data or vice versa.
        """
        if context.environment != target_environment:
            raise TenantIsolationViolationError(
                f"Environment boundary violation: context in '{context.environment.value}' cannot perform '{operation_name}' on '{target_environment.value}'."
            )

    @classmethod
    def filter_by_context(cls, context: EnterpriseContext, items: List[Any]) -> List[Any]:
        """
        Safely filters a list of entities containing `tenant_id` to prevent cross-tenant data leakage.
        """
        if context.has_role("super_admin"):
            return items

        filtered = []
        for item in items:
            t_id = getattr(item, "tenant_id", None)
            if t_id == context.tenant_id:
                # Also filter by environment if present
                item_env = getattr(item, "environment", None)
                if item_env is None or item_env == context.environment:
                    filtered.append(item)
        return filtered


T = TypeVar("T")


class PartitionedStore(Generic[T]):
    """
    Thread-safe generic partitioned store isolated by tenant_id and environment.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # partition_key -> dict of id -> item
        self._partitions: Dict[str, Dict[str, T]] = defaultdict(dict)

    def _get_partition_id(self, tenant_id: str, environment: Environment) -> str:
        return f"{tenant_id}:{environment.value}"

    def put(self, tenant_id: str, environment: Environment, item_id: str, item: T) -> None:
        """Stores an item in the designated tenant and environment partition."""
        with self._lock:
            pid = self._get_partition_id(tenant_id, environment)
            self._partitions[pid][item_id] = item

    def get(self, tenant_id: str, environment: Environment, item_id: str) -> Optional[T]:
        """Retrieves an item from the partition."""
        with self._lock:
            pid = self._get_partition_id(tenant_id, environment)
            return self._partitions[pid].get(item_id)

    def list_all(self, tenant_id: str, environment: Environment) -> List[T]:
        """Lists all items within the specific tenant and environment partition."""
        with self._lock:
            pid = self._get_partition_id(tenant_id, environment)
            return list(self._partitions[pid].values())

    def delete(self, tenant_id: str, environment: Environment, item_id: str) -> bool:
        """Deletes an item from the partition."""
        with self._lock:
            pid = self._get_partition_id(tenant_id, environment)
            if item_id in self._partitions[pid]:
                del self._partitions[pid][item_id]
                return True
            return False

    def count(self, tenant_id: str, environment: Environment) -> int:
        """Returns the number of records in the partition."""
        with self._lock:
            pid = self._get_partition_id(tenant_id, environment)
            return len(self._partitions[pid])
