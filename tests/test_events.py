import pytest
from datetime import datetime, timezone
from pydantic import ValidationError
from runtimeverify.events import (
    Event,
    ToolEvent,
    LLMEvent,
    MemoryEvent,
    FilesystemEvent,
    NetworkEvent,
)

def test_base_event_defaults_and_validation():
    # Test valid initialization
    event = Event(session_id="sess_123", agent_id="agent_abc")
    assert event.session_id == "sess_123"
    assert event.agent_id == "agent_abc"
    assert event.type == "generic"
    assert isinstance(event.id, str)
    assert isinstance(event.timestamp, datetime)
    assert event.metadata == {}

    # Test missing required field
    with pytest.raises(ValidationError):
        Event(agent_id="agent_abc")

def test_event_immutability():
    event = Event(session_id="sess_123", agent_id="agent_abc")
    
    # Attempt to change a field should raise ValidationError (Pydantic frozen model)
    with pytest.raises(ValidationError) as exc_info:
        event.session_id = "new_sess"
    assert "Instance is frozen" in str(exc_info.value)

def test_tool_event():
    tool_evt = ToolEvent(
        session_id="sess_123",
        agent_id="agent_abc",
        tool_name="execute_python",
        arguments={"code": "print(42)"},
        output="42",
        status="success",
        duration_ms=12.5
    )
    assert tool_evt.type == "tool"
    assert tool_evt.tool_name == "execute_python"
    assert tool_evt.arguments == {"code": "print(42)"}
    assert tool_evt.output == "42"
    assert tool_evt.status == "success"
    assert tool_evt.duration_ms == 12.5

    # Check immutability
    with pytest.raises(ValidationError):
        tool_evt.tool_name = "other_tool"

def test_llm_event():
    llm_evt = LLMEvent(
        session_id="sess_123",
        agent_id="agent_abc",
        model="gemini-1.5-pro",
        prompt="What is 2+2?",
        response="4",
        prompt_tokens=10,
        completion_tokens=5,
        total_tokens=15,
        temperature=0.0,
        duration_ms=250.0
    )
    assert llm_evt.type == "llm"
    assert llm_evt.model == "gemini-1.5-pro"
    assert llm_evt.prompt == "What is 2+2?"
    assert llm_evt.response == "4"
    assert llm_evt.prompt_tokens == 10
    assert llm_evt.completion_tokens == 5
    assert llm_evt.total_tokens == 15
    assert llm_evt.temperature == 0.0
    assert llm_evt.duration_ms == 250.0

def test_memory_event():
    mem_evt = MemoryEvent(
        session_id="sess_123",
        agent_id="agent_abc",
        action="write",
        key="user_name",
        value="Alice",
        previous_value="Bob",
        store_name="short_term"
    )
    assert mem_evt.type == "memory"
    assert mem_evt.action == "write"
    assert mem_evt.key == "user_name"
    assert mem_evt.value == "Alice"
    assert mem_evt.previous_value == "Bob"
    assert mem_evt.store_name == "short_term"

def test_filesystem_event():
    fs_evt = FilesystemEvent(
        session_id="sess_123",
        agent_id="agent_abc",
        action="write",
        path="/workspace/notes.md",
        content_hash="e3b0c442",
        bytes_transferred=1024,
        status="success"
    )
    assert fs_evt.type == "filesystem"
    assert fs_evt.action == "write"
    assert fs_evt.path == "/workspace/notes.md"
    assert fs_evt.content_hash == "e3b0c442"
    assert fs_evt.bytes_transferred == 1024
    assert fs_evt.status == "success"

def test_network_event():
    net_evt = NetworkEvent(
        session_id="sess_123",
        agent_id="agent_abc",
        action="request",
        url="https://api.github.com/users",
        method="GET",
        headers={"Authorization": "Bearer token"},
        status_code=200,
        bytes_sent=0,
        bytes_received=4096,
        duration_ms=120.0
    )
    assert net_evt.type == "network"
    assert net_evt.action == "request"
    assert net_evt.url == "https://api.github.com/users"
    assert net_evt.method == "GET"
    assert net_evt.headers == {"Authorization": "Bearer token"}
    assert net_evt.status_code == 200
    assert net_evt.bytes_sent == 0
    assert net_evt.bytes_received == 4096
    assert net_evt.duration_ms == 120.0
