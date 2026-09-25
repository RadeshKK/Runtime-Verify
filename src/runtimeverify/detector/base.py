from abc import ABC, abstractmethod
from typing import List
from pydantic import BaseModel, Field, ConfigDict
from runtimeverify.state.base import StateInterface
from runtimeverify.detector.results import DetectorResult, DetectorExplanation


class DetectorMetadata(BaseModel):
    """Metadata describing a detector's properties and runtime requirements."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Unique name of the detector algorithm")
    version: str = Field(..., description="Semantic version of the detector configuration")
    supported_categories: List[str] = Field(
        default_factory=list, description="List of StateCategories this detector evaluates (empty means all)"
    )
    requires_training: bool = Field(
        default=True, description="True if the algorithm requires calling fit() on baseline data before use"
    )


class BaseDetector(ABC):
    """
    Abstract Base Class that all statistical detectors must implement.
    Guarantees strict separation of algorithms from execution runtime.
    """

    @abstractmethod
    def metadata(self) -> DetectorMetadata:
        """Returns the static metadata profile for this detector instance."""
        pass

    @abstractmethod
    def fit(self, sequences: List[List[StateInterface]]) -> None:
        """
        Trains/fits the detector model on historical normal state transition runs.

        Args:
            sequences: A list of state traces, where each trace is a list of ExecutionStates.
        """
        pass

    @abstractmethod
    def observe(self, state: StateInterface) -> DetectorResult:
        """
        Stream an incoming ExecutionState, update internal statistics, and yield a decision.

        Args:
            state: The current semantic state resolved from telemetry.

        Returns:
            A structured DetectorResult payload.
        """
        pass

    @abstractmethod
    def reset(self) -> None:
        """
        Resets active testing parameters.
        Retains underlying model parameters (like transition matrix weights).
        """
        pass

    @abstractmethod
    def save(self, path: str) -> None:
        """
        Serializes and saves the model's trained parameters to disk.
        """
        pass

    @abstractmethod
    def load(self, path: str) -> None:
        """
        Loads and instantiates serialized parameters from disk.
        """
        pass

    @abstractmethod
    def explain(self, result: DetectorResult) -> DetectorExplanation:
        """
        Computes detailed diagnostic information for a specific result.
        """
        pass
