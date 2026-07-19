from typing import Dict, Set, List

class TransitionCounter:
    """
    Tracks occurrence frequencies of states and state transitions.
    Supports incremental/streaming updates.
    """
    def __init__(self):
        # Maps state_from -> state_to -> frequency_count
        self.transition_counts: Dict[str, Dict[str, int]] = {}
        # Maps state_from -> total_outgoing_count
        self.state_counts: Dict[str, int] = {}
        # The set of all unique states observed
        self.states: Set[str] = set()

    def add_transition(self, prev_state: str, curr_state: str, count: int = 1) -> None:
        """Increment transition count between two states."""
        prev = prev_state.upper()
        curr = curr_state.upper()
        
        self.states.add(prev)
        self.states.add(curr)
        
        if prev not in self.transition_counts:
            self.transition_counts[prev] = {}
        self.transition_counts[prev][curr] = self.transition_counts[prev].get(curr, 0) + count
        
        self.state_counts[prev] = self.state_counts.get(prev, 0) + count

    def add_sequence(self, sequence: List[str]) -> None:
        """Incorporate a sequence of state transitions."""
        if len(sequence) < 2:
            if sequence:
                key = sequence[0].upper()
                self.states.add(key)
                self.state_counts[key] = self.state_counts.get(key, 0) + 1
            return
            
        for i in range(len(sequence) - 1):
            self.add_transition(sequence[i], sequence[i+1])
            
        # Increment occurrence count for the terminating state
        last = sequence[-1].upper()
        self.state_counts[last] = self.state_counts.get(last, 0) + 1


class ProbabilityMatrix:
    """
    Maintains the probability transition table estimated from TransitionCounter counts.
    Supports Maximum Likelihood Estimation (MLE) and Laplace (add-alpha) smoothing.
    """
    def __init__(self, smoothing: float = 0.0):
        self.smoothing = smoothing
        # Maps state_from -> state_to -> probability
        self.probabilities: Dict[str, Dict[str, float]] = {}
        # Saved vocabulary alphabet
        self.states: Set[str] = set()

    def estimate(self, counter: TransitionCounter) -> None:
        """
        Estimates transition probabilities from a TransitionCounter.
        Uses MLE with optional Laplace smoothing.
        """
        self.states = counter.states.copy()
        self.probabilities.clear()
        
        num_states = len(self.states)
        
        for state_from in self.states:
            self.probabilities[state_from] = {}
            total_from_count = counter.state_counts.get(state_from, 0)
            
            for state_to in self.states:
                trans_count = counter.transition_counts.get(state_from, {}).get(state_to, 0)
                
                # Apply Laplace smoothing if smoothing > 0
                if self.smoothing > 0:
                    numerator = trans_count + self.smoothing
                    denominator = total_from_count + (self.smoothing * num_states)
                    prob = numerator / denominator if denominator > 0 else 1.0 / num_states
                else:
                    prob = trans_count / total_from_count if total_from_count > 0 else 0.0
                    
                self.probabilities[state_from][state_to] = prob

    def get_probability(self, prev_state: str, curr_state: str) -> float:
        """Retrieves transition probability P(curr_state | prev_state)."""
        prev = prev_state.upper()
        curr = curr_state.upper()
        
        if prev not in self.states or curr not in self.states:
            # Out of vocabulary transition: handle with smoothing default over a larger state space
            if self.smoothing > 0:
                # We assume a large virtual alphabet size to penalize out-of-vocabulary transitions
                virtual_vocab_size = len(self.states) + 1000
                return self.smoothing / (self.smoothing * virtual_vocab_size)
            return 0.0
            
        return self.probabilities.get(prev, {}).get(curr, 0.0)
