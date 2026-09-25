import json
from typing import Dict, Any, Tuple
from runtimeverify.markov.matrix import TransitionCounter, ProbabilityMatrix


class MarkovPersistence:
    """
    Handles portable serialization and deserialization of Markov Chain models.
    Converts state maps, transition counts, estimation probabilities, and metadata
    to/from a clean JSON representation (no pickle or runtime coupling).
    """

    @staticmethod
    def serialize(counter: TransitionCounter, matrix: ProbabilityMatrix, metadata: Dict[str, Any]) -> str:
        """Serializes the model components into a standard JSON string."""
        payload = {
            "schema_version": "1.0",
            "model_version": metadata.get("model_version", "1.0"),
            "metadata": metadata,
            "states": list(counter.states),
            "state_counts": counter.state_counts,
            "transition_counts": counter.transition_counts,
            "probabilities": matrix.probabilities,
            "smoothing": matrix.smoothing,
        }
        return json.dumps(payload, indent=2)

    @staticmethod
    def deserialize(json_str: str) -> Tuple[TransitionCounter, ProbabilityMatrix, Dict[str, Any]]:
        """
        Deserializes a JSON string back into a TransitionCounter,
        ProbabilityMatrix, and metadata dictionary.
        """
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid model JSON format: {e}")

        # Validate schema version
        schema_version = data.get("schema_version", "1.0")
        if schema_version != "1.0":
            raise ValueError(f"Unsupported model schema version: {schema_version}")

        # Re-construct TransitionCounter
        counter = TransitionCounter()
        counter.states = set(data.get("states", []))
        counter.state_counts = data.get("state_counts", {})
        counter.transition_counts = data.get("transition_counts", {})

        # Re-construct ProbabilityMatrix
        smoothing = float(data.get("smoothing", 0.0))
        matrix = ProbabilityMatrix(smoothing=smoothing)
        matrix.states = counter.states.copy()
        matrix.probabilities = data.get("probabilities", {})

        metadata = data.get("metadata", {})

        return counter, matrix, metadata
