from typing import Any, Optional
from pydantic import Field
from runtimeverify.events.base import Event

class MemoryEvent(Event):
    """
    Event representing a memory operation (read, write, update, clear) within the agent's context.
    """
    type: str = Field("memory", description="Event type discriminator")
    action: str = Field(..., description="The memory operation performed (e.g., read, write, update, delete, clear)")
    key: str = Field(..., description="The key or memory slot identifier accessed")
    value: Optional[Any] = Field(None, description="The value stored or retrieved during the operation")
    previous_value: Optional[Any] = Field(None, description="The prior value of the key (for write/update operations)")
    store_name: Optional[str] = Field("default", description="The name of the memory store (e.g., short_term, long_term, vector_db)")
