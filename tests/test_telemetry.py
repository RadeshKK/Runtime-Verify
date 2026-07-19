import pytest
import asyncio
from typing import List
from runtimeverify.events import Event, ToolEvent, LLMEvent
from runtimeverify.telemetry import (
    EventBus,
    TelemetryContext,
    active_context,
    get_current_context,
    TelemetryManager,
    set_global_manager,
    observe_tool,
    observe_llm,
    span,
    EventSerializer,
    TelemetryMiddleware,
)

def test_telemetry_context_propagation():
    assert get_current_context() is None
    
    ctx = TelemetryContext(session_id="session_foo", agent_id="agent_bar")
    with active_context(ctx):
        current = get_current_context()
        assert current is not None
        assert current.session_id == "session_foo"
        assert current.agent_id == "agent_bar"
        assert len(current.trace_id) > 0
        
    assert get_current_context() is None

def test_event_bus_subscription():
    bus = EventBus()
    received_events: List[Event] = []
    
    def listener(event: Event):
        received_events.append(event)
        
    bus.subscribe(listener)
    
    event = Event(session_id="s1", agent_id="a1", type="generic")
    bus.publish(event)
    
    assert len(received_events) == 1
    assert received_events[0].session_id == "s1"
    
    bus.unsubscribe(listener)
    bus.publish(event)
    assert len(received_events) == 1  # No new event received

def test_tool_decorator_sync():
    bus = EventBus()
    manager = TelemetryManager(event_bus=bus)
    set_global_manager(manager)
    
    received_events: List[ToolEvent] = []
    bus.subscribe(lambda e: received_events.append(e) if isinstance(e, ToolEvent) else None)
    
    ctx = TelemetryContext(session_id="session_tool_test", agent_id="agent_tool_test")
    
    @observe_tool(name="addition_tool")
    def add(x: int, y: int) -> int:
        return x + y
        
    with active_context(ctx):
        res = add(3, 5)
        assert res == 8
        
    assert len(received_events) == 1
    event = received_events[0]
    assert event.session_id == "session_tool_test"
    assert event.agent_id == "agent_tool_test"
    assert event.tool_name == "addition_tool"
    assert event.arguments == {"x": 3, "y": 5}
    assert event.output == 8
    assert event.status == "success"
    assert event.duration_ms is not None
    assert event.duration_ms >= 0

def test_tool_decorator_error():
    bus = EventBus()
    manager = TelemetryManager(event_bus=bus)
    set_global_manager(manager)
    
    received_events: List[ToolEvent] = []
    bus.subscribe(lambda e: received_events.append(e) if isinstance(e, ToolEvent) else None)
    
    ctx = TelemetryContext(session_id="session_error_test", agent_id="agent_error_test")
    
    @observe_tool
    def divide(x: int, y: int) -> float:
        return x / y
        
    with active_context(ctx):
        with pytest.raises(ZeroDivisionError):
            divide(4, 0)
            
    assert len(received_events) == 1
    event = received_events[0]
    assert event.session_id == "session_error_test"
    assert event.agent_id == "agent_error_test"
    assert event.tool_name == "divide"
    assert event.status == "error"
    assert "division by zero" in event.error_message
    assert event.duration_ms is not None

@pytest.mark.anyio
async def test_tool_decorator_async():
    bus = EventBus()
    manager = TelemetryManager(event_bus=bus)
    set_global_manager(manager)
    
    received_events: List[ToolEvent] = []
    bus.subscribe(lambda e: received_events.append(e) if isinstance(e, ToolEvent) else None)
    
    ctx = TelemetryContext(session_id="session_async_test", agent_id="agent_async_test")
    
    @observe_tool(name="async_multiply")
    async def multiply(x: int, y: int) -> int:
        await asyncio.sleep(0.01)
        return x * y
        
    with active_context(ctx):
        res = await multiply(4, 5)
        assert res == 20
        
    assert len(received_events) == 1
    event = received_events[0]
    assert event.tool_name == "async_multiply"
    assert event.arguments == {"x": 4, "y": 5}
    assert event.output == 20
    assert event.status == "success"
    assert event.duration_ms >= 10.0  # sleep was 10ms

def test_llm_decorator():
    bus = EventBus()
    manager = TelemetryManager(event_bus=bus)
    set_global_manager(manager)
    
    received_events: List[LLMEvent] = []
    bus.subscribe(lambda e: received_events.append(e) if isinstance(e, LLMEvent) else None)
    
    ctx = TelemetryContext(session_id="session_llm_test", agent_id="agent_llm_test")
    
    @observe_llm(model="mock-gpt")
    def call_model(prompt: str) -> dict:
        return {
            "response": "Hello World",
            "prompt_tokens": 12,
            "completion_tokens": 8
        }
        
    with active_context(ctx):
        call_model("Hi")
        
    assert len(received_events) == 1
    event = received_events[0]
    assert event.model == "mock-gpt"
    assert event.prompt == "Hi"
    assert event.response == "Hello World"
    assert event.prompt_tokens == 12
    assert event.completion_tokens == 8
    assert event.total_tokens == 20
    assert event.duration_ms is not None

def test_span_context_manager():
    bus = EventBus()
    manager = TelemetryManager(event_bus=bus)
    set_global_manager(manager)
    
    received_events: List[Event] = []
    bus.subscribe(received_events.append)
    
    ctx = TelemetryContext(session_id="session_span_test", agent_id="agent_span_test")
    
    with active_context(ctx):
        with span("db_query"):
            # run mock work
            pass
            
    assert len(received_events) == 1
    event = received_events[0]
    assert event.type == "span"
    assert event.metadata["span_name"] == "db_query"
    assert event.metadata["status"] == "success"
    assert event.metadata["duration_ms"] is not None

def test_event_serializer():
    event = ToolEvent(
        session_id="s_ser",
        agent_id="a_ser",
        tool_name="test_tool",
        arguments={"arg": 1},
        status="success"
    )
    serialized = EventSerializer.serialize(event)
    assert isinstance(serialized, str)
    assert '"type":"tool"' in serialized
    
    deserialized = EventSerializer.deserialize(serialized)
    assert isinstance(deserialized, ToolEvent)
    assert deserialized.session_id == "s_ser"
    assert deserialized.tool_name == "test_tool"

def test_middleware():
    bus = EventBus()
    manager = TelemetryManager(event_bus=bus)
    set_global_manager(manager)
    
    received_events: List[Event] = []
    bus.subscribe(received_events.append)
    
    middleware = TelemetryMiddleware(session_id="sess_mid", agent_id="agent_mid")
    
    @middleware
    def my_agent_loop(input_val: int) -> int:
        return input_val * 2
        
    res = my_agent_loop(5)
    assert res == 10
    
    # We expect 2 events: "agent_start" and "agent_end"
    assert len(received_events) == 2
    assert received_events[0].type == "agent_start"
    assert received_events[1].type == "agent_end"
    assert received_events[0].session_id == "sess_mid"
    assert received_events[1].session_id == "sess_mid"
