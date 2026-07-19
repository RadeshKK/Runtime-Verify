import random
from typing import List, Tuple, Dict

class TraceGenerator:
    """
    Generates synthetic behavioral traces for testing detectors.
    """
    @staticmethod
    def generate_normal_trace(alphabet: List[str], length: int, transition_matrix: Dict[str, List[str]]) -> List[str]:
        """Generates a trace based on a 'normal' probability distribution."""
        if not alphabet: return []
        
        current_state = random.choice(alphabet)
        trace = [current_state]
        
        for _ in range(length - 1):
            possible_next = transition_matrix.get(current_state, alphabet)
            current_state = random.choice(possible_next)
            trace.append(current_state)
            
        return trace

    @staticmethod
    def inject_anomaly(trace: List[str], start_index: int, anomaly_alphabet: List[str]) -> Tuple[List[str], List[bool]]:
        """
        Injects random states from an anomaly alphabet starting at start_index.
        
        Returns:
            The modified trace and the ground-truth boolean mask.
        """
        modified_trace = list(trace)
        ground_truth = [False] * len(trace)
        
        for i in range(start_index, len(trace)):
            modified_trace[i] = random.choice(anomaly_alphabet)
            ground_truth[i] = True
            
        return modified_trace, ground_truth
