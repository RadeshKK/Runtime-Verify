import uuid
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict
from runtimeverify.state.categories import StateCategory
from runtimeverify.state.hierarchy import StateHierarchy
from runtimeverify.state.context import StateContext
from runtimeverify.state.metadata import StateMetadata
from runtimeverify.state.provenance import StateProvenance


class ExecutionState(BaseModel):
    """
    Immutable representation of a semantic execution state.
    Provides the standard structure evaluated by behavior graphs and detectors.
    Fits the StateInterface protocol.
    """

    model_config = ConfigDict(
        frozen=True,
        arbitrary_types_allowed=True,
    )

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique ID for this state node")
    name: str = Field(..., description="Short name of the state (e.g. WRITE_SOURCE)")
    category: StateCategory = Field(..., description="The high-level category of execution")
    hierarchy: StateHierarchy = Field(..., description="The hierarchical path representation of the state")
    context: StateContext = Field(..., description="Active context parameters during state transition")
    metadata: StateMetadata = Field(
        default_factory=StateMetadata, description="Risk levels and other operational metadata"
    )

    schema_version: str = Field("1.0", description="Schema version of the ExecutionState model")
    encoder_version: str = Field("1.0", description="Version of the encoder that generated this state")
    provenance: Optional[StateProvenance] = Field(None, description="Provenance tracing evidence and rule details")

    @property
    def dot_path(self) -> str:
        """Returns the dot-separated string representation of the state path."""
        return self.hierarchy.dot_path
