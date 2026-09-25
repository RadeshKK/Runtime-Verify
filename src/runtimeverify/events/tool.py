from typing import Dict, Any, Optional
from pydantic import Field
from runtimeverify.events.base import Event


class ToolEvent(Event):
    """
    Event representing a tool invocation by an agent, containing inputs, outputs, and execution metrics.
    """

    type: str = Field("tool", description="Event type discriminator")
    tool_name: str = Field(..., description="The name of the tool invoked")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Arguments passed to the tool invocation")
    output: Optional[Any] = Field(None, description="The response or output from the tool execution")
    status: str = Field("success", description="The status of the tool call (e.g., success, error, pending)")
    error_message: Optional[str] = Field(None, description="Detailed error message if the status is error")
    duration_ms: Optional[float] = Field(None, description="Execution duration of the tool call in milliseconds")
