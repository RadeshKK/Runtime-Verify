import pytest
from runtimeverify.detector.markov import MarkovBehaviorModel

def test_markov_training_basic():
    """Verify that simple sequences are correctly counted."""
    model = MarkovBehaviorModel()
    sequences = [
        ["S1", "S2", "S3"],
        ["S1", "S2", "S1"],
    ]
    model.train(sequences)
    
    # S1 -> S2 happened twice
    # S2 -> S3 happened once
    # S2 -> S1 happened once
    assert model.get_probability("S1", "S2") == 1.0
    assert model.get_probability("S2", "S3") == 0.5
    assert model.get_probability("S2", "S1") == 0.5
    assert model.get_probability("S3", "S1") == 0.0

def test_incremental_updates():
    """Verify that updating the model with new transitions works correctly."""
    model = MarkovBehaviorModel()
    model.update_transition("A", "B")
    model.update_transition("A", "B")
    model.update_transition("A", "C")
    
    assert model.get_probability("A", "B") == pytest.approx(0.6666, 0.01)
    assert model.get_probability("A", "C") == pytest.approx(0.3333, 0.01)

def test_serialization_cycle():
    """Verify that a model can be serialized and restored without loss of data."""
    model = MarkovBehaviorModel()
    model.train([["S1", "S2", "S3"], ["S1", "S2", "S1"]])
    
    snapshot = model.serialize()
    
    new_model = MarkovBehaviorModel()
    new_model.load_snapshot(snapshot)
    
    assert new_model.get_probability("S1", "S2") == 1.0
    assert new_model.get_probability("S2", "S3") == 0.5
    assert new_model.get_probability("S2", "S1") == 0.5

def test_explainability_output():
    """Verify the format of the explainability method."""
    model = MarkovBehaviorModel()
    model.update_transition("START", "READ")
    model.update_transition("START", "WRITE")
    
    explanation = model.explain_transition("START", "READ")
    assert "occurred 1 times out of 2" in explanation
    assert "Prob: 0.5000" in explanation

def test_empty_model_behavior():
    """Verify that queries to an empty model return zero without crashing."""
    model = MarkovBehaviorModel()
    assert model.get_probability("X", "Y") == 0.0
    assert model.get_transition_distribution("X") == {}
