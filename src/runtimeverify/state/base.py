from typing import Protocol, runtime_checkable
from runtimeverify.state.categories import StateCategory
from runtimeverify.state.hierarchy import StateHierarchy
from runtimeverify.state.context import StateContext
from runtimeverify.state.metadata import StateMetadata


@runtime_checkable
class StateInterface(Protocol):
    """
    Protocol describing the standard interface of any state representation.
    Ensures that custom state structures are compatible with the detector API.
    """

    @property
    def id(self) -> str:
        """Returns the unique identifier of the state instance."""
        ...

    @property
    def name(self) -> str:
        """Returns the semantic name of the state (e.g. 'WRITE_SOURCE')."""
        ...

    @property
    def category(self) -> StateCategory:
        """Returns the high-level operational category of the state."""
        ...

    @property
    def hierarchy(self) -> StateHierarchy:
        """Returns the state's hierarchy path representation."""
        ...

    @property
    def context(self) -> StateContext:
        """Returns the execution context in which this state was recorded."""
        ...

    @property
    def metadata(self) -> StateMetadata:
        """Returns the risk, permission, and custom metadata of this state."""
        ...

    @property
    def dot_path(self) -> str:
        """Returns the dot-separated string representation of the state's hierarchy path."""
        ...
