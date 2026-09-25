import pytest
from pydantic import ValidationError
from runtimeverify.state import (
    StateCategory,
    StateHierarchy,
    StateMetadata,
    StateContext,
    StateInterface,
    ExecutionState,
    StateRegistry,
)


def test_state_hierarchy_traversal():
    h = StateHierarchy(path=["FILE", "READ", "SOURCE_CODE", "PYTHON", "LOCAL"])
    assert h.dot_path == "FILE.READ.SOURCE_CODE.PYTHON.LOCAL"

    parent = h.parent()
    assert parent is not None
    assert parent.dot_path == "FILE.READ.SOURCE_CODE.PYTHON"

    grandparent = parent.parent()
    assert grandparent is not None
    assert grandparent.dot_path == "FILE.READ.SOURCE_CODE"

    root = StateHierarchy(path=["FILE"])
    assert root.parent() is None

    # Test levels
    lvl2 = h.level(2)
    assert lvl2.dot_path == "FILE.READ"

    lvl99 = h.level(99)
    assert lvl99.dot_path == h.dot_path

    # Test descendants
    h_other = StateHierarchy(path=["FILE", "READ"])
    assert h.is_descendant_of(h_other)
    assert not h_other.is_descendant_of(h)
    assert not h.is_descendant_of(h)


def test_execution_state_immutability():
    hierarchy = StateHierarchy(path=["FILE", "READ", "SOURCE"])
    context = StateContext(
        agent_id="agent_1", session_id="session_1", resource_id="/workspace/main.py", resource_type="source"
    )
    meta = StateMetadata(permission_level="read", risk_level="low")

    state = ExecutionState(
        name="READ_SOURCE", category=StateCategory.FILESYSTEM, hierarchy=hierarchy, context=context, metadata=meta
    )

    # Verify properties
    assert state.name == "READ_SOURCE"
    assert state.category == StateCategory.FILESYSTEM
    assert state.dot_path == "FILE.READ.SOURCE"
    assert isinstance(state.id, str)

    # Check that modification raises ValidationError (frozen model)
    with pytest.raises(ValidationError):
        state.name = "WRITE_SOURCE"


def test_execution_state_equality_and_serialization():
    hierarchy = StateHierarchy(path=["NET", "CONNECT", "EXTERNAL"])
    context = StateContext(
        agent_id="agent_1", session_id="session_1", resource_id="https://api.github.com", resource_type="api"
    )
    state1 = ExecutionState(name="CONNECT_OUT", category=StateCategory.NETWORK, hierarchy=hierarchy, context=context)

    # Serialization
    json_str = state1.model_dump_json()
    assert isinstance(json_str, str)
    assert "CONNECT_OUT" in json_str

    # Deserialization
    state2 = ExecutionState.model_validate_json(json_str)
    assert state1 == state2  # Pydantic equality based on fields
    assert state2.dot_path == "NET.CONNECT.EXTERNAL"
    assert state2.context.agent_id == "agent_1"


def test_state_registry():
    registry = StateRegistry()
    h = StateHierarchy(path=["MEM", "WRITE", "SHORT_TERM"])

    registry.register("WRITE_MEM", h, StateCategory.MEMORY)

    assert registry.is_registered("WRITE_MEM")
    assert registry.is_registered("write_mem")  # Case insensitive
    assert not registry.is_registered("UNKNOWN_STATE")

    assert registry.get_hierarchy("WRITE_MEM") == h
    assert registry.get_category("WRITE_MEM") == StateCategory.MEMORY

    assert registry.list_registered_states() == {"WRITE_MEM"}

    registry.clear()
    assert not registry.is_registered("WRITE_MEM")


def test_state_interface_compliance():
    hierarchy = StateHierarchy(path=["TOOL", "EXECUTE", "SYS_CMD"])
    context = StateContext(agent_id="agent_x", session_id="session_y")
    state = ExecutionState(name="SYS_EXEC", category=StateCategory.TOOL, hierarchy=hierarchy, context=context)

    # ExecutionState should comply structurally with StateInterface Protocol
    assert isinstance(state, StateInterface)
