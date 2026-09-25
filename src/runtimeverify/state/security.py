import uuid
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator

from runtimeverify.state.base import StateInterface
from runtimeverify.state.categories import StateCategory
from runtimeverify.state.context import StateContext
from runtimeverify.state.hierarchy import StateHierarchy
from runtimeverify.state.metadata import StateMetadata
from runtimeverify.state.taxonomy import (
    SecurityRiskLevel,
    SecurityStateCategory,
    get_default_category,
    get_default_hierarchy,
    get_default_risk,
)


class SecurityState(BaseModel):
    """
    Normalized security state representation in RuntimeVerify.
    Implements StateInterface Protocol so it can be evaluated directly by
    Markov, SPRT, and downstream detection and policy components.
    """

    model_config = ConfigDict(
        frozen=True,
        arbitrary_types_allowed=True,
    )

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this security state instance",
    )
    name: str = Field(
        "",
        description="State name token evaluated by Markov and SPRT (defaults to security_category.value)",
    )
    security_category: SecurityStateCategory = Field(
        ...,
        description="Canonical security state category from the taxonomy",
    )
    risk_level: SecurityRiskLevel = Field(
        default=SecurityRiskLevel.INFO,
        description="Assigned security risk rating",
    )
    category: StateCategory = Field(
        default=StateCategory.SYSTEM,
        description="Operational category matching StateInterface protocol",
    )
    hierarchy: StateHierarchy = Field(
        default_factory=lambda: StateHierarchy(path=["SYSTEM", "UNKNOWN"]),
        description="Hierarchical taxonomy path matching StateInterface protocol",
    )
    context: StateContext = Field(
        ...,
        description="Execution and trace context in which this state occurred",
    )
    metadata: StateMetadata = Field(
        default_factory=StateMetadata,
        description="Risk, permission, and custom operational metadata",
    )
    confidence: float = Field(
        1.0,
        ge=0.0,
        le=1.0,
        description="Classification confidence score (1.0 for deterministic, [0,1] for semantic)",
    )
    attributes: Dict[str, Any] = Field(
        default_factory=dict,
        description="Extracted security attributes (e.g., command, domain, URL, path, tool_name)",
    )
    source_event_id: Optional[str] = Field(
        None,
        description="Identifier of the source telemetry event that triggered this state",
    )
    source_event_type: Optional[str] = Field(
        None,
        description="Event type string of the source event",
    )
    classifier_source: str = Field(
        "deterministic",
        description="Identifier of classifier or enricher chain that produced this state",
    )
    schema_version: str = Field(
        "1.0",
        description="Schema version of the SecurityState model",
    )

    @model_validator(mode="before")
    @classmethod
    def populate_defaults(cls, data: Any) -> Any:
        if isinstance(data, dict):
            sec_cat = data.get("security_category")
            if sec_cat is not None:
                if isinstance(sec_cat, str):
                    try:
                        sec_cat = SecurityStateCategory(sec_cat)
                    except ValueError:
                        sec_cat = SecurityStateCategory.UNKNOWN
                    data["security_category"] = sec_cat

                # Default name to category value if not provided
                if not data.get("name"):
                    data["name"] = sec_cat.value

                # Default risk level if not provided
                if "risk_level" not in data or data["risk_level"] is None:
                    data["risk_level"] = get_default_risk(sec_cat)

                # Default StateCategory if not provided
                if "category" not in data or data["category"] is None:
                    data["category"] = get_default_category(sec_cat)

                # Default StateHierarchy if not provided
                if "hierarchy" not in data or data["hierarchy"] is None:
                    data["hierarchy"] = get_default_hierarchy(sec_cat)

                # Default StateMetadata if not provided or missing risk_level
                if "metadata" not in data or data["metadata"] is None:
                    risk_val = data["risk_level"]
                    risk_str = risk_val.value.lower() if hasattr(risk_val, "value") else str(risk_val).lower()
                    data["metadata"] = StateMetadata(risk_level=risk_str)
        return data

    @property
    def dot_path(self) -> str:
        """Returns the dot-separated string representation of the state hierarchy path."""
        return self.hierarchy.dot_path

    @property
    def is_high_risk(self) -> bool:
        """Returns True if the state has HIGH or CRITICAL risk."""
        return self.risk_level in (SecurityRiskLevel.HIGH, SecurityRiskLevel.CRITICAL)

    @property
    def is_critical(self) -> bool:
        """Returns True if the state has CRITICAL risk."""
        return self.risk_level == SecurityRiskLevel.CRITICAL

    def with_enrichment(
        self,
        security_category: Optional[SecurityStateCategory] = None,
        risk_level: Optional[SecurityRiskLevel] = None,
        confidence: Optional[float] = None,
        classifier_source: Optional[str] = None,
        attributes_update: Optional[Dict[str, Any]] = None,
    ) -> "SecurityState":
        """
        Creates a new immutable SecurityState with updated enrichment attributes.
        Used by post-classification enrichers (e.g. semantic classifiers like Laya).
        """
        new_category = security_category or self.security_category
        new_risk = risk_level or (get_default_risk(new_category) if security_category else self.risk_level)
        new_hierarchy = get_default_hierarchy(new_category) if security_category else self.hierarchy
        new_state_cat = get_default_category(new_category) if security_category else self.category

        merged_attributes = dict(self.attributes)
        if attributes_update:
            merged_attributes.update(attributes_update)

        new_meta = StateMetadata(
            permission_level=self.metadata.permission_level,
            risk_level=new_risk.value.lower(),
            extra=dict(self.metadata.extra),
        )

        return SecurityState(
            id=self.id,
            name=new_category.value,
            security_category=new_category,
            risk_level=new_risk,
            category=new_state_cat,
            hierarchy=new_hierarchy,
            context=self.context,
            metadata=new_meta,
            confidence=confidence if confidence is not None else self.confidence,
            attributes=merged_attributes,
            source_event_id=self.source_event_id,
            source_event_type=self.source_event_type,
            classifier_source=classifier_source or self.classifier_source,
            schema_version=self.schema_version,
        )


if False:
    # Static type check that SecurityState satisfies StateInterface
    _test_state: StateInterface = SecurityState(  # type: ignore[assignment]
        security_category=SecurityStateCategory.UNKNOWN,
        context=StateContext(agent_id="", session_id=""),
    )
