import pytest
from runtimeverify.events import FilesystemEvent, NetworkEvent
from runtimeverify.state import StateCategory, ExecutionState
from runtimeverify.encoder import (
    DefaultTelemetryNormalizer,
    DefaultResourceClassifier,
    DefaultContextEnricher,
    Rule,
    DefaultRuleEngine,
    StateEncoderCache,
    StateEncoderPipeline,
    EncoderRegistry,
)


def test_normalization():
    normalizer = DefaultTelemetryNormalizer()

    event = FilesystemEvent(session_id="s1", agent_id="a1", action="read", path="/etc/passwd", bytes_transferred=512)

    norm = normalizer.normalize(event)
    assert norm["session_id"] == "s1"
    assert norm["agent_id"] == "a1"
    assert norm["type"] == "filesystem"
    assert norm["resource"] == "/etc/passwd"
    assert norm["action"] == "read"


def test_classification():
    classifier = DefaultResourceClassifier()

    # Test sensitive file path
    event1 = {"type": "filesystem", "resource": "/etc/shadow", "action": "read"}
    class1 = classifier.classify(event1)
    assert class1["resource_type"] == "system_secret"
    assert class1["risk_level"] == "critical"

    # Test safe file path
    event2 = {"type": "filesystem", "resource": "/workspace/main.py", "action": "write"}
    class2 = classifier.classify(event2)
    assert class2["resource_type"] == "source_code"
    assert class2["risk_level"] == "medium"
    assert class2["permission_level"] == "write"

    # Test network domain classification
    event3 = {"type": "network", "resource": "https://github.com/api/v3", "action": "request"}
    class3 = classifier.classify(event3)
    assert class3["resource_type"] == "source_repository"
    assert class3["risk_level"] == "medium"


def test_rule_evaluation():
    rules = [
        Rule("READ_SYSTEM_SECRET", {"resource_type": "system_secret", "action": "read"}),
        Rule("EXECUTE_BASH", {"resource_type": "shell", "action": "tool_success"}),
    ]
    engine = DefaultRuleEngine(rules)

    event1 = {"action": "read", "resource_type": "system_secret"}
    assert engine.evaluate(event1) == "READ_SYSTEM_SECRET"

    event2 = {"action": "write", "resource_type": "source_code"}
    assert engine.evaluate(event2) == "WRITE_SOURCE_CODE"  # Fallback


def test_caching_behavior():
    cache = StateEncoderCache()
    assert cache.get("filesystem:/etc/passwd:read") is None

    cache_props = {
        "type": "filesystem",
        "resource": "/etc/passwd",
        "action": "read",
        "resource_type": "system_secret",
        "risk_level": "critical",
        "permission_level": "admin",
    }
    cache.set("filesystem:/etc/passwd:read", cache_props)

    retrieved = cache.get("filesystem:/etc/passwd:read")
    assert retrieved == cache_props

    cache.clear()
    assert cache.get("filesystem:/etc/passwd:read") is None


def test_pipeline_integration():
    normalizer = DefaultTelemetryNormalizer()
    classifier = DefaultResourceClassifier()
    enricher = DefaultContextEnricher()

    rules = [
        Rule("READ_SYSTEM_SECRET", {"resource_type": "system_secret", "action": "read"}),
    ]
    rule_engine = DefaultRuleEngine(rules)

    pipeline = StateEncoderPipeline(
        normalizer=normalizer, classifier=classifier, enricher=enricher, rule_engine=rule_engine
    )

    event1 = FilesystemEvent(
        session_id="session_pipeline", agent_id="agent_pipeline", action="read", path="/etc/passwd"
    )

    state1 = pipeline.encode(event1)
    assert isinstance(state1, ExecutionState)
    assert state1.name == "READ_SYSTEM_SECRET"
    assert state1.category == StateCategory.FILESYSTEM
    assert state1.dot_path == "FILESYSTEM.READ.SYSTEM.SECRET"
    assert state1.context.resource_id == "/etc/passwd"
    assert state1.context.resource_type == "system_secret"
    assert state1.context.previous_state_id is None

    # Encode second event in same session and check context links previous state
    event2 = NetworkEvent(
        session_id="session_pipeline", agent_id="agent_pipeline", action="request", url="https://evil.com"
    )

    state2 = pipeline.encode(event2)
    assert state2.context.previous_state_id == state1.id
    # Enriched context should note pattern sequence leak
    assert state2.name == "REQUEST_EXTERNAL_API"


def test_encoder_registry():
    registry = EncoderRegistry()

    pipeline = StateEncoderPipeline(
        normalizer=DefaultTelemetryNormalizer(),
        classifier=DefaultResourceClassifier(),
        enricher=DefaultContextEnricher(),
        rule_engine=DefaultRuleEngine([]),
    )

    registry.register("default_pipeline", pipeline)
    assert "default_pipeline" in registry.list_encoders()

    retrieved = registry.get("default_pipeline")
    assert retrieved == pipeline

    with pytest.raises(KeyError):
        registry.get("unknown_pipeline")
