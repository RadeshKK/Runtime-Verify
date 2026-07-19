from typing import List
import random
from runtimeverify.markov.trainer import MarkovTrainer
from runtimeverify.markov.predictor import MarkovPredictor
from runtimeverify.markov.persistence import MarkovPersistence
from runtimeverify.markov.explain import MarkovExplainer, TransitionExplanation

class MarkovModel:
    """
    Core master coordinator representing the first-order Markov Behavior Model.
    Wraps separate components for training, inference, persistence, and explainability.
    """
    
    def __init__(self, smoothing: float = 0.0, model_version: str = "1.0"):
        self.trainer = MarkovTrainer(smoothing=smoothing)
        self.predictor = MarkovPredictor(self.trainer.matrix)
        self.model_version = model_version

    def train(self, training_states: List[List[str]]) -> None:
        """
        Batch fits model state weights.
        
        Args:
            training_states: A list of state sequences (lists of string state names).
        """
        self.trainer.fit(training_states)

    def observe(self, previous: str, current: str) -> float:
        """
        Online streaming update. Returns the transition probability of the step, 
        then increments transition counts streamingly.
        
        Args:
            previous: Source state string.
            current: Target state string.
            
        Returns:
            The estimated probability P(current | previous).
        """
        prob = self.predictor.transition_probability(previous, current)
        self.trainer.update(previous, current)
        return prob

    def transition_probability(self, previous: str, current: str) -> float:
        """Returns the transition probability P(current | previous)."""
        return self.predictor.transition_probability(previous, current)

    def sample(self, previous: str) -> str:
        """Samples a state from the distribution P(. | previous)."""
        probs = self.trainer.matrix.probabilities.get(previous.upper(), {})
        if not probs:
            # If we have no transitions from this state, sample any known state uniformly
            alphabet = list(self.trainer.matrix.states)
            return random.choice(alphabet) if alphabet else "UNKNOWN_STATE"

        options = list(probs.keys())
        weights = list(probs.values())
        return random.choices(options, weights=weights)[0]

    def sequence_probability(self, sequence: List[str]) -> float:
        """Returns joint sequence probability P(S)."""
        return self.predictor.sequence_probability(sequence)

    def sequence_log_probability(self, sequence: List[str]) -> float:
        """Returns joint sequence log-probability ln P(S)."""
        return self.predictor.sequence_log_probability(sequence)

    def save(self, path: str) -> None:
        """Serializes and persists the model structure to disk as JSON."""
        metadata = {
            "model_version": self.model_version,
            "smoothing": self.trainer.matrix.smoothing
        }
        serialized = MarkovPersistence.serialize(
            self.trainer.counter, 
            self.trainer.matrix, 
            metadata
        )
        with open(path, "w") as f:
            f.write(serialized)

    def load(self, path: str) -> None:
        """Loads and instantiates serialized parameters from a JSON model file."""
        with open(path, "r") as f:
            json_str = f.read()
        counter, matrix, metadata = MarkovPersistence.deserialize(json_str)
        self.trainer.counter = counter
        self.trainer.matrix = matrix
        self.predictor = MarkovPredictor(matrix)
        self.model_version = metadata.get("model_version", "1.0")

    def explain(self, previous: str, current: str) -> TransitionExplanation:
        """Computes diagnostic mathematical explanations backing the transition probability."""
        return MarkovExplainer.explain(
            previous, 
            current, 
            self.trainer.counter, 
            self.trainer.matrix
        )
