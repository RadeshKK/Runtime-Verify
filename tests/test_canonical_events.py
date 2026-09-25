import json
import pytest
from datetime import datetime, timezone, timedelta
from pydantic import ValidationError

from runtimeverify.events import (
    Event,
    CanonicalEvent,
    EventContext,
    EventType,
    EventAction,
    AgentType,
    EventEnvironment,
    EventSource,
    LLMRequestEvent,
    LLMResponseEvent,
    ToolCallEvent,
    ToolResultEvent,
    FilesystemReadEvent,
    FilesystemWriteEvent,
    FilesystemDeleteEvent,
    ShellCommandEvent,
    NetworkRequestEvent,
    GitOperationEvent,
    CredentialAccessEvent,
    ProcessCreationEvent,
    AgentCommunicationEvent,
    HumanApprovalEvent,
    PolicyDecisionEvent,
    ToolEvent,
    LLMEvent,
)
from runtimeverify.telemetry.serializers import EventSerializer
from runtimeverify.encoder.normalizer import DefaultTelemetryNormalizer


def test_canonical_event_defaults_and_validation():
    event = CanonicalEvent(session_id="sess_123", agent_id="agent_abc")
    assert isinstance(event, Event)
    assert event.schema_version == "1.0"
    assert event.session_id == "sess_123"
    assert event.agent_id == "agent_abc"
    assert event.event_type == "generic"
    assert event.type == "generic"
    assert event.action == "unknown"
    assert event.source == "agent"
    assert event.environment == "production"
    assert isinstance(event.event_id, str)
    assert event.id == event.event_id
    assert isinstance(event.timestamp, datetime)
    assert event.timestamp.tzinfo == timezone.utc
    assert isinstance(event.context, EventContext)
    assert event.metadata == {}
    assert event.payload == {}

    typed_event = CanonicalEvent(
        session_id="s_typed",
        agent_id="a_typed",
        agent_type=AgentType.CODER.value,
        environment=EventEnvironment.SANDBOX.value,
    )
    assert typed_event.agent_type == "coder"
    assert typed_event.environment == "sandbox"


def test_canonical_event_immutability():
    event = CanonicalEvent(session_id="sess_123", agent_id="agent_abc")
    with pytest.raises(ValidationError) as exc_info:
        event.session_id = "new_session"
    assert "Instance is frozen" in str(exc_info.value)


def test_canonical_event_missing_required_fields():
    with pytest.raises(ValidationError):
        CanonicalEvent(agent_id="agent_abc")
    with pytest.raises(ValidationError):
        CanonicalEvent(session_id="sess_123")
    with pytest.raises(ValidationError):
        CanonicalEvent(session_id="", agent_id="agent_abc")
    with pytest.raises(ValidationError):
        CanonicalEvent(session_id="sess_123", agent_id="")


def test_utc_timestamp_normalization():
    # 1. Naive datetime gets assigned UTC
    naive_dt = datetime(2026, 7, 19, 12, 0, 0)
    event_naive = CanonicalEvent(session_id="s", agent_id="a", timestamp=naive_dt)
    assert event_naive.timestamp.tzinfo == timezone.utc
    assert event_naive.timestamp.hour == 12

    # 2. Offset datetime gets converted to UTC
    plus_two = timezone(timedelta(hours=2))
    aware_dt = datetime(2026, 7, 19, 14, 0, 0, tzinfo=plus_two)
    event_aware = CanonicalEvent(session_id="s", agent_id="a", timestamp=aware_dt)
    assert event_aware.timestamp.tzinfo == timezone.utc
    assert event_aware.timestamp.hour == 12  # 14:00+02:00 -> 12:00 UTC


def test_correlation_ids():
    event = CanonicalEvent(
        session_id="sess_1",
        agent_id="agent_1",
        trace_id="trace_xyz",
        span_id="span_123",
        parent_event_id="evt_parent_001",
    )
    assert event.trace_id == "trace_xyz"
    assert event.span_id == "span_123"
    assert event.parent_event_id == "evt_parent_001"


def test_event_context_handling():
    # Context with known fields and custom extra fields
    ctx = EventContext(
        current_directory="/workspace/app",
        user="dev_agent",
        hostname="sandbox-node-4",
        platform="linux",
        process_id=4201,
        thread_id="asyncio-thread-1",
        git_branch="feature/audit",
        git_commit="723d4c3",
        tags={"tier": "critical", "region": "us-east-1"},
        custom_env="isolated_container",
    )
    assert ctx.current_directory == "/workspace/app"
    assert ctx.user == "dev_agent"
    assert ctx["git_branch"] == "feature/audit"
    assert ctx["custom_env"] == "isolated_container"
    assert ctx.get("nonexistent", "fallback") == "fallback"

    event = CanonicalEvent(session_id="s", agent_id="a", context=ctx)
    assert event.context.current_directory == "/workspace/app"
    assert event.context["custom_env"] == "isolated_container"

    # Context passed as raw dictionary
    event_dict_ctx = CanonicalEvent(
        session_id="s",
        agent_id="a",
        context={"current_directory": "/tmp", "k8s_pod": "agent-worker-0"},
    )
    assert event_dict_ctx.context.current_directory == "/tmp"
    assert event_dict_ctx.context["k8s_pod"] == "agent-worker-0"


def test_llm_request_event():
    # Direct class instantiation
    evt = LLMRequestEvent(
        session_id="s_llm",
        agent_id="a_llm",
        model="gpt-4o",
        prompt="Explain quantum entanglement",
        temperature=0.2,
        max_tokens=500,
    )
    assert evt.event_type == EventType.LLM_REQUEST.value
    assert evt.action == EventAction.REQUEST.value
    assert evt.target == "gpt-4o"
    assert evt.model_name == "gpt-4o"
    assert evt.prompt == "Explain quantum entanglement"
    assert evt.payload["temperature"] == 0.2
    assert evt.payload["max_tokens"] == 500

    # Factory method
    evt_factory = CanonicalEvent.create_llm_request(
        session_id="s_llm",
        agent_id="a_llm",
        model="claude-3-5-sonnet",
        prompt="Write a test suite",
        temperature=0.0,
    )
    assert isinstance(evt_factory, LLMRequestEvent)
    assert evt_factory.target == "claude-3-5-sonnet"


def test_llm_response_event():
    evt = LLMResponseEvent(
        session_id="s_llm",
        agent_id="a_llm",
        model="gemini-1.5-pro",
        response="Here is the explanation.",
        prompt_tokens=50,
        completion_tokens=25,
        total_tokens=75,
        duration_ms=420.5,
    )
    assert evt.event_type == EventType.LLM_RESPONSE.value
    assert evt.action == EventAction.RESPONSE.value
    assert evt.target == "gemini-1.5-pro"
    assert evt.model_name == "gemini-1.5-pro"
    assert evt.response == "Here is the explanation."
    assert evt.total_tokens == 75

    evt_factory = CanonicalEvent.create_llm_response(
        session_id="s_llm",
        agent_id="a_llm",
        model="gemini-1.5-pro",
        response="Done",
        prompt_tokens=10,
        completion_tokens=5,
    )
    assert isinstance(evt_factory, LLMResponseEvent)
    assert evt_factory.total_tokens == 15


def test_tool_call_event():
    evt = ToolCallEvent(
        session_id="s_tool",
        agent_id="a_tool",
        tool_name="bash",
        arguments={"command": "ls -la"},
        call_id="call_999",
    )
    assert evt.event_type == EventType.TOOL_CALL.value
    assert evt.action == EventAction.CALL.value
    assert evt.target == "bash"
    assert evt.tool_name == "bash"
    assert evt.arguments == {"command": "ls -la"}
    assert evt.payload["call_id"] == "call_999"

    evt_factory = CanonicalEvent.create_tool_call(
        session_id="s_tool",
        agent_id="a_tool",
        tool_name="read_file",
        arguments={"path": "README.md"},
    )
    assert isinstance(evt_factory, ToolCallEvent)
    assert evt_factory.tool_name == "read_file"


def test_tool_result_event():
    evt = ToolResultEvent(
        session_id="s_tool",
        agent_id="a_tool",
        tool_name="bash",
        output="file1.txt\nfile2.txt",
        status="success",
        duration_ms=15.2,
    )
    assert evt.event_type == EventType.TOOL_RESULT.value
    assert evt.action == EventAction.RESULT.value
    assert evt.target == "bash"
    assert evt.tool_name == "bash"
    assert evt.output == "file1.txt\nfile2.txt"
    assert evt.status == "success"

    evt_factory = CanonicalEvent.create_tool_result(
        session_id="s_tool",
        agent_id="a_tool",
        tool_name="bash",
        error_message="Permission denied",
        status="error",
    )
    assert isinstance(evt_factory, ToolResultEvent)
    assert evt_factory.status == "error"
    assert evt_factory.payload["error_message"] == "Permission denied"


def test_filesystem_events():
    # 1. Read
    read_evt = CanonicalEvent.create_filesystem_read(
        session_id="s_fs",
        agent_id="a_fs",
        path="/etc/passwd",
        bytes_read=1024,
    )
    assert isinstance(read_evt, FilesystemReadEvent)
    assert read_evt.event_type == EventType.FILESYSTEM_READ.value
    assert read_evt.action == EventAction.READ.value
    assert read_evt.target == "/etc/passwd"
    assert read_evt.path == "/etc/passwd"
    assert read_evt.payload["bytes_read"] == 1024

    # 2. Write
    write_evt = CanonicalEvent.create_filesystem_write(
        session_id="s_fs",
        agent_id="a_fs",
        path="/workspace/main.py",
        bytes_written=2048,
        content_hash="sha256_abcdef",
    )
    assert isinstance(write_evt, FilesystemWriteEvent)
    assert write_evt.event_type == EventType.FILESYSTEM_WRITE.value
    assert write_evt.action == EventAction.WRITE.value
    assert write_evt.target == "/workspace/main.py"
    assert write_evt.content_hash == "sha256_abcdef"

    # 3. Delete
    delete_evt = CanonicalEvent.create_filesystem_delete(
        session_id="s_fs",
        agent_id="a_fs",
        path="/workspace/temp.log",
    )
    assert isinstance(delete_evt, FilesystemDeleteEvent)
    assert delete_evt.event_type == EventType.FILESYSTEM_DELETE.value
    assert delete_evt.action == EventAction.DELETE.value
    assert delete_evt.target == "/workspace/temp.log"


def test_shell_command_event():
    evt = CanonicalEvent.create_shell_command(
        session_id="s_sh",
        agent_id="a_sh",
        command="git status",
        arguments=["status"],
        working_directory="/repo",
        exit_code=0,
        output="On branch master",
        duration_ms=45.0,
    )
    assert isinstance(evt, ShellCommandEvent)
    assert evt.event_type == EventType.SHELL_COMMAND.value
    assert evt.action == EventAction.EXECUTE.value
    assert evt.target == "git"
    assert evt.command == "git status"
    assert evt.exit_code == 0


def test_network_request_event():
    evt = CanonicalEvent.create_network_request(
        session_id="s_net",
        agent_id="a_net",
        url="https://api.github.com/repos/test",
        method="GET",
        headers={"Accept": "application/json"},
        status_code=200,
        bytes_received=4096,
        duration_ms=180.0,
    )
    assert isinstance(evt, NetworkRequestEvent)
    assert evt.event_type == EventType.NETWORK_REQUEST.value
    assert evt.action == EventAction.REQUEST.value
    assert evt.target == "https://api.github.com/repos/test"
    assert evt.url == "https://api.github.com/repos/test"
    assert evt.method == "GET"
    assert evt.status_code == 200


def test_git_operation_event():
    evt = CanonicalEvent.create_git_operation(
        session_id="s_git",
        agent_id="a_git",
        operation="commit",
        repository="Runtime-Verify",
        branch="main",
        commit_hash="abc1234",
        message="feat: canonical event model",
        files_changed=["src/runtimeverify/events/canonical.py"],
    )
    assert isinstance(evt, GitOperationEvent)
    assert evt.event_type == EventType.GIT_OPERATION.value
    assert evt.action == "commit"
    assert evt.operation == "commit"
    assert evt.repository == "Runtime-Verify"
    assert evt.commit_hash == "abc1234"


def test_credential_access_event():
    evt = CanonicalEvent.create_credential_access(
        session_id="s_cred",
        agent_id="a_cred",
        resource_name="ANTHROPIC_API_KEY",
        secret_type="api_key",
        access_mode="read",
    )
    assert isinstance(evt, CredentialAccessEvent)
    assert evt.event_type == EventType.CREDENTIAL_ACCESS.value
    assert evt.action == EventAction.ACCESS.value
    assert evt.target == "ANTHROPIC_API_KEY"
    assert evt.resource_name == "ANTHROPIC_API_KEY"
    assert evt.secret_type == "api_key"
    assert evt.payload["sanitized"] is True


def test_process_creation_event():
    evt = CanonicalEvent.create_process_creation(
        session_id="s_proc",
        agent_id="a_proc",
        command="python -m pytest",
        pid=12345,
        parent_pid=1000,
        environment_variables=["PATH", "PYTHONPATH"],
    )
    assert isinstance(evt, ProcessCreationEvent)
    assert evt.event_type == EventType.PROCESS_CREATION.value
    assert evt.action == EventAction.SPAWN.value
    assert evt.target == "python"
    assert evt.command == "python -m pytest"
    assert evt.pid == 12345


def test_agent_communication_event():
    evt = CanonicalEvent.create_agent_communication(
        session_id="s_comm",
        agent_id="orchestrator_agent",
        recipient_agent_id="worker_agent_01",
        message_type="task_delegation",
        content_summary="Execute unit tests",
    )
    assert isinstance(evt, AgentCommunicationEvent)
    assert evt.event_type == EventType.AGENT_COMMUNICATION.value
    assert evt.action == EventAction.SEND.value
    assert evt.target == "worker_agent_01"
    assert evt.recipient_agent_id == "worker_agent_01"
    assert evt.message_type == "task_delegation"


def test_human_approval_event():
    evt = CanonicalEvent.create_human_approval(
        session_id="s_hitl",
        agent_id="security_verifier",
        ticket_id="ticket_auth_42",
        decision="approved",
        approver_id="security_officer_bob",
        reason="Verified production deployment intent",
    )
    assert isinstance(evt, HumanApprovalEvent)
    assert evt.event_type == EventType.HUMAN_APPROVAL.value
    assert evt.source == EventSource.HUMAN.value
    assert evt.target == "ticket_auth_42"
    assert evt.ticket_id == "ticket_auth_42"
    assert evt.decision == "approved"
    assert evt.approver_id == "security_officer_bob"


def test_policy_decision_event():
    evt = CanonicalEvent.create_policy_decision(
        session_id="s_pol",
        agent_id="safety_guard",
        policy_name="restricted_write_policy",
        decision="BLOCK",
        deviation_score=15.4,
        triggered_rules=["path_deny_list:etc"],
        evidence={"target_path": "/etc/shadow"},
    )
    assert isinstance(evt, PolicyDecisionEvent)
    assert evt.event_type == EventType.POLICY_DECISION.value
    assert evt.source == EventSource.VERIFIER.value
    assert evt.target == "restricted_write_policy"
    assert evt.policy_name == "restricted_write_policy"
    assert evt.decision == "BLOCK"
    assert evt.deviation_score == 15.4


def test_event_serialization_and_deserialization():
    original = CanonicalEvent.create_tool_call(
        session_id="sess_ser",
        agent_id="agent_ser",
        tool_name="calculator",
        arguments={"a": 10, "b": 20},
        trace_id="tr_100",
    )
    # 1. to_dict / from_dict
    as_dict = original.to_dict()
    assert as_dict["schema_version"] == "1.0"
    assert as_dict["event_type"] == EventType.TOOL_CALL.value
    assert as_dict["target"] == "calculator"
    assert as_dict["id"] == original.event_id

    reconstructed_dict = ToolCallEvent.from_dict(as_dict)
    assert reconstructed_dict.event_id == original.event_id
    assert reconstructed_dict.target == "calculator"
    assert reconstructed_dict.arguments == {"a": 10, "b": 20}

    # 2. to_json / from_json
    as_json = original.to_json()
    reconstructed_json = ToolCallEvent.from_json(as_json)
    assert reconstructed_json.event_id == original.event_id
    assert reconstructed_json.trace_id == "tr_100"

    # 3. Polymorphic EventSerializer round-trip
    serialized_str = EventSerializer.serialize(original)
    polymorphic_obj = EventSerializer.deserialize(serialized_str)
    assert isinstance(polymorphic_obj, ToolCallEvent)
    assert polymorphic_obj.event_id == original.event_id
    assert polymorphic_obj.tool_name == "calculator"


def test_forward_compatibility_extra_fields():
    # Simulates an event received from a future v1.1 client with new unknown fields
    raw_payload = {
        "schema_version": "1.1",
        "event_id": "future-evt-001",
        "timestamp": "2026-09-25T12:00:00Z",
        "session_id": "sess_future",
        "agent_id": "agent_future",
        "event_type": "tool.call",
        "action": "call",
        "target": "future_quantum_tool",
        "future_field_alpha": 42,
        "quantum_state_vector": [0.707, 0.707],
        "payload": {
            "tool_name": "future_quantum_tool",
            "arguments": {},
            "future_nested_flag": True,
        },
    }
    json_str = json.dumps(raw_payload)
    event = EventSerializer.deserialize(json_str)

    assert isinstance(event, ToolCallEvent)
    assert event.event_id == "future-evt-001"
    assert event.target == "future_quantum_tool"
    # Extra unknown fields are preserved rather than failing validation
    assert event.future_field_alpha == 42
    assert event.quantum_state_vector == [0.707, 0.707]


def test_backward_compatibility_with_legacy_events():
    legacy_tool = ToolEvent(
        session_id="s_leg",
        agent_id="a_leg",
        tool_name="legacy_bash",
        arguments={"x": 1},
    )
    assert legacy_tool.schema_version == "1.0"
    assert legacy_tool.type == "tool"
    assert legacy_tool.event_type == "tool"
    assert legacy_tool.id == legacy_tool.event_id
    assert isinstance(legacy_tool.timestamp, datetime)
    assert legacy_tool.environment == "production"

    serialized = EventSerializer.serialize(legacy_tool)
    deserialized = EventSerializer.deserialize(serialized)
    assert isinstance(deserialized, ToolEvent)
    assert deserialized.tool_name == "legacy_bash"

    legacy_llm = LLMEvent(
        session_id="s_llm_leg",
        agent_id="a_llm_leg",
        model="gpt-3.5-turbo",
        prompt="hello",
        response="world",
    )
    assert legacy_llm.type == "llm"
    assert legacy_llm.model == "gpt-3.5-turbo"
    assert legacy_llm.schema_version == "1.0"
    serialized_llm = EventSerializer.serialize(legacy_llm)
    deserialized_llm = EventSerializer.deserialize(serialized_llm)
    assert isinstance(deserialized_llm, LLMEvent)
    assert deserialized_llm.prompt == "hello"


def test_encoder_normalizer_with_canonical_event():
    normalizer = DefaultTelemetryNormalizer()
    canonical_evt = CanonicalEvent.create_filesystem_write(
        session_id="s_norm",
        agent_id="a_norm",
        path="/etc/hosts",
        bytes_written=512,
        content_hash="h123",
    )
    norm = normalizer.normalize(canonical_evt)
    assert norm["event_id"] == canonical_evt.event_id
    assert norm["session_id"] == "s_norm"
    assert norm["agent_id"] == "a_norm"
    assert norm["type"] == EventType.FILESYSTEM_WRITE.value
    assert norm["resource"] == "/etc/hosts"
    assert norm["action"] == EventAction.WRITE.value
    assert norm["metadata"]["content_hash"] == "h123"
    assert norm["metadata"]["bytes_written"] == 512
