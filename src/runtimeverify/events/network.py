from typing import Optional, Dict
from pydantic import Field
from runtimeverify.events.base import Event


class NetworkEvent(Event):
    """
    Event representing a network call or connection attempt by the agent, such as an HTTP request or database socket call.
    """

    type: str = Field("network", description="Event type discriminator")
    action: str = Field(..., description="The network action (e.g., request, response, connect, listen)")
    url: str = Field(..., description="The target URL or network endpoint address")
    method: Optional[str] = Field(None, description="The request method (e.g., GET, POST, PUT, DELETE, socket)")
    headers: Optional[Dict[str, str]] = Field(None, description="HTTP or metadata headers associated with the call")
    status_code: Optional[int] = Field(None, description="HTTP status code or connection code returned")
    bytes_sent: Optional[int] = Field(None, description="Outgoing payload size in bytes")
    bytes_received: Optional[int] = Field(None, description="Incoming payload size in bytes")
    duration_ms: Optional[float] = Field(None, description="Latency of the network transaction in milliseconds")
    error_message: Optional[str] = Field(None, description="Error message if the network request failed")
