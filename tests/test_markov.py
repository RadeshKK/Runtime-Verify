import os
import tempfile
from runtimeverify.markov import (
    TransitionExtractor,
    MarkovMetrics,
    MarkovModel,
)


def test_transition_extractor():
    seq = ["A", "B", "C"]
    pairs = TransitionExtractor.extract_pairs(seq)
    assert pairs == [("A", "B"), ("B", "C")]

    assert TransitionExtractor.extract_pairs([]) == []
    assert TransitionExtractor.extract_pairs(["A"]) == []


def test_simple_markov_training_probabilities():
    # Model requirement: Train on A -> B -> C -> B -> C
    # Verify P(B|A)=1.0, P(C|B)=1.0, P(B|C)=0.5
    model = MarkovModel(smoothing=0.0)
    model.train([["A", "B", "C", "B", "C"]])

    p_b_a = model.transition_probability("A", "B")
    p_c_b = model.transition_probability("B", "C")
    p_b_c = model.transition_probability("C", "B")

    assert p_b_a == 1.0
    assert p_c_b == 1.0
    assert p_b_c == 0.5

    # Check sequence joint probability
    # P(A -> B -> C) = 1.0 * P(B|A) * P(C|B) = 1.0 * 1.0 * 1.0 = 1.0
    assert model.sequence_probability(["A", "B", "C"]) == 1.0
    # P(B -> C -> B) = 1.0 * P(C|B) * P(B|C) = 1.0 * 1.0 * 0.5 = 0.5
    assert model.sequence_probability(["B", "C", "B"]) == 0.5


def test_streaming_updates():
    model = MarkovModel(smoothing=0.0)

    # Incremental update: B -> C on empty model
    model.observe("B", "C")

    assert model.transition_probability("B", "C") == 1.0


def test_explainability():
    model = MarkovModel(smoothing=0.0)
    model.train([["A", "B", "C", "B", "C"]])

    explanation = model.explain("C", "B")
    assert explanation.prev_state == "C"
    assert explanation.curr_state == "B"
    assert explanation.probability == 0.5
    assert explanation.observed_transition_count == 1
    assert explanation.total_outgoing_count == 2
    assert len(explanation.expected_transitions) > 0
    assert explanation.expected_transitions[0]["state"] == "B"


def test_persistence():
    model = MarkovModel(smoothing=0.0, model_version="2.0-test")
    model.train([["A", "B", "C", "B", "C"]])

    # Save to temp file
    fd, temp_path = tempfile.mkstemp()
    try:
        os.close(fd)
        model.save(temp_path)

        # Load in new model
        loaded_model = MarkovModel(smoothing=0.0)
        loaded_model.load(temp_path)

        assert loaded_model.model_version == "2.0-test"
        assert loaded_model.transition_probability("C", "B") == 0.5
        assert loaded_model.transition_probability("A", "B") == 1.0
    finally:
        os.unlink(temp_path)


def test_metrics():
    model = MarkovModel(smoothing=0.0)
    model.train([["A", "B", "C", "B", "C"]])

    matrix = model.trainer.matrix
    sparsity = MarkovMetrics.calculate_sparsity(matrix)
    # 3 states -> 9 possible transitions.
    # Observed: A->B, B->C, C->B (3 transitions out of 9 are non-zero)
    # Sparsity = 6 / 9 = 0.666...
    assert 0.66 < sparsity < 0.67

    # Entropy of state A (outgoing: B (p=1.0)) -> entropy = 0.0
    assert MarkovMetrics.calculate_state_entropy(matrix, "A") == 0.0
    # Entropy of state C (outgoing: B (p=0.5)) -> - (0.5 * log2(0.5)) = 0.5 * 1 = 0.5 (sub-stochastic, wait, since p=0.5 is only non-zero outgoing: H(C) = -0.5 * log2(0.5) = 0.5)
    assert MarkovMetrics.calculate_state_entropy(matrix, "C") == 0.5
