from typing import List, Optional, Tuple, Union

from runtimeverify.events.base import Event
from runtimeverify.markov.explain import TransitionExplanation
from runtimeverify.markov.model import MarkovModel
from runtimeverify.state.base import StateInterface
from runtimeverify.state.classifier import (
    BaseEventClassifier,
    SecurityClassificationPipeline,
    get_default_pipeline,
)
from runtimeverify.state.security import SecurityState


class MarkovStateAdapter:
    """
    Adapter that integrates the canonical SecurityState taxonomy and classification
    layer with the first-order Markov behavior model.

    Provides frictionless translation between telemetry Events, normalized SecurityStates,
    and Markov state tokens without modifying the core Markov mathematical algorithms.
    """

    def __init__(
        self,
        markov_model: Optional[MarkovModel] = None,
        classifier: Optional[Union[BaseEventClassifier, SecurityClassificationPipeline]] = None,
    ):
        self._model = markov_model or MarkovModel()
        self._classifier = classifier or get_default_pipeline()

    @property
    def model(self) -> MarkovModel:
        """Returns the underlying MarkovModel instance."""
        return self._model

    @property
    def classifier(self) -> Union[BaseEventClassifier, SecurityClassificationPipeline]:
        """Returns the active classifier or pipeline."""
        return self._classifier

    def event_to_state(self, event: Event) -> SecurityState:
        """
        Classifies a raw or canonical Event into a normalized SecurityState.
        """
        return self._classifier.classify(event)

    def state_to_token(self, state: StateInterface) -> str:
        """
        Extracts the Markov token label from any StateInterface instance.
        Defaults to state.name (e.g. 'FILE_READ', 'SHELL_DESTRUCTIVE').
        """
        return state.name.upper()

    def events_to_states(self, events: List[Event]) -> List[SecurityState]:
        """Maps an event sequence to a SecurityState sequence."""
        return [self.event_to_state(ev) for ev in events]

    def events_to_tokens(self, events: List[Event]) -> List[str]:
        """Maps an event sequence to string token labels for Markov processing."""
        return [self.state_to_token(self.event_to_state(ev)) for ev in events]

    def states_to_tokens(self, states: List[StateInterface]) -> List[str]:
        """Maps a sequence of StateInterface instances to string token labels."""
        return [self.state_to_token(s) for s in states]

    def train_events(self, traces: List[List[Event]]) -> None:
        """
        Trains the Markov model from sequences of telemetry events.

        Args:
            traces: List of event sequence traces.
        """
        string_traces = [self.events_to_tokens(trace) for trace in traces]
        self._model.train(string_traces)

    def train_states(self, traces: List[List[StateInterface]]) -> None:
        """
        Trains the Markov model directly from sequences of SecurityState or ExecutionState.

        Args:
            traces: List of StateInterface sequences.
        """
        string_traces = [self.states_to_tokens(trace) for trace in traces]
        self._model.train(string_traces)

    def observe_event(
        self,
        previous: Optional[Union[StateInterface, str]],
        event: Event,
    ) -> Tuple[SecurityState, float]:
        """
        Classifies an event, evaluates the transition probability from the previous state,
        and updates online streaming statistics.

        Args:
            previous: The prior StateInterface or token string (or None for start of session).
            event: The incoming telemetry event.

        Returns:
            Tuple of (current_security_state, transition_probability).
        """
        curr_state = self.event_to_state(event)
        curr_token = self.state_to_token(curr_state)

        if previous is not None:
            prev_token = (
                self.state_to_token(previous) if isinstance(previous, StateInterface) else str(previous).upper()
            )
            prob = self._model.observe(prev_token, curr_token)
        else:
            prob = 1.0

        return curr_state, prob

    def observe_state(
        self,
        previous: Optional[Union[StateInterface, str]],
        current: StateInterface,
    ) -> float:
        """
        Evaluates the transition probability between two states and updates streaming statistics.

        Args:
            previous: The prior StateInterface or token string (or None for start).
            current: The current StateInterface instance.

        Returns:
            Transition probability P(current | previous).
        """
        curr_token = self.state_to_token(current)
        if previous is not None:
            prev_token = (
                self.state_to_token(previous) if isinstance(previous, StateInterface) else str(previous).upper()
            )
            return self._model.observe(prev_token, curr_token)
        return 1.0

    def transition_probability(
        self,
        previous: Union[StateInterface, str],
        current: Union[StateInterface, str],
    ) -> float:
        """
        Computes P(current | previous) without mutating transition counts.
        """
        prev_token = self.state_to_token(previous) if isinstance(previous, StateInterface) else str(previous).upper()
        curr_token = self.state_to_token(current) if isinstance(current, StateInterface) else str(current).upper()
        return self._model.transition_probability(prev_token, curr_token)

    def sequence_probability(self, events: List[Event]) -> float:
        """Computes joint sequence probability P(E_1, ..., E_N)."""
        tokens = self.events_to_tokens(events)
        return self._model.sequence_probability(tokens)

    def sequence_log_probability(self, events: List[Event]) -> float:
        """Computes joint sequence log-probability ln P(E_1, ..., E_N)."""
        tokens = self.events_to_tokens(events)
        return self._model.sequence_log_probability(tokens)

    def explain(
        self,
        previous: Union[StateInterface, str],
        current: Union[StateInterface, str],
    ) -> TransitionExplanation:
        """Provides mathematical explainability backing a transition."""
        prev_token = self.state_to_token(previous) if isinstance(previous, StateInterface) else str(previous).upper()
        curr_token = self.state_to_token(current) if isinstance(current, StateInterface) else str(current).upper()
        return self._model.explain(prev_token, curr_token)
