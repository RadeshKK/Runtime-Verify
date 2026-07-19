from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from runtimeverify.events import (
    ToolEvent,
    LLMEvent,
    MemoryEvent,
    FilesystemEvent,
    NetworkEvent,
)
from runtimeverify.telemetry.emitter import TelemetryEmitter
from runtimeverify.telemetry.context import get_current_context

class TelemetryCollector(ABC):
    """Abstract interface defining the collector for normalizing telemetry measurements into Events."""

    @abstractmethod
    def collect_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        output: Optional[Any] = None,
        status: str = "success",
        error_message: Optional[str] = None,
        duration_ms: Optional[float] = None,
    ) -> ToolEvent:
        pass

    @abstractmethod
    def collect_llm(
        self,
        model: str,
        prompt: Optional[Any] = None,
        response: Optional[str] = None,
        prompt_tokens: Optional[int] = None,
        completion_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        duration_ms: Optional[float] = None,
    ) -> LLMEvent:
        pass

    @abstractmethod
    def collect_memory(
        self,
        action: str,
        key: str,
        value: Optional[Any] = None,
        previous_value: Optional[Any] = None,
        store_name: Optional[str] = "default",
    ) -> MemoryEvent:
        pass

    @abstractmethod
    def collect_filesystem(
        self,
        action: str,
        path: str,
        content_hash: Optional[str] = None,
        bytes_transferred: Optional[int] = None,
        status: str = "success",
        error_message: Optional[str] = None,
    ) -> FilesystemEvent:
        pass

    @abstractmethod
    def collect_network(
        self,
        action: str,
        url: str,
        method: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        status_code: Optional[int] = None,
        bytes_sent: Optional[int] = None,
        bytes_received: Optional[int] = None,
        duration_ms: Optional[float] = None,
        error_message: Optional[str] = None,
    ) -> NetworkEvent:
        pass


class DefaultTelemetryCollector(TelemetryCollector):
    """
    Default collector implementation. Reads the active TelemetryContext 
    to automatically populate session and agent parameters, then fires events via the emitter.
    """

    def __init__(self, emitter: TelemetryEmitter):
        self._emitter = emitter

    def _get_context_parameters(self) -> tuple[str, str, Optional[str]]:
        ctx = get_current_context()
        if ctx is not None:
            return ctx.session_id, ctx.agent_id, ctx.trace_id
        return "unknown_session", "unknown_agent", None

    def collect_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        output: Optional[Any] = None,
        status: str = "success",
        error_message: Optional[str] = None,
        duration_ms: Optional[float] = None,
    ) -> ToolEvent:
        sess_id, agent_id, parent_id = self._get_context_parameters()
        event = ToolEvent(
            session_id=sess_id,
            agent_id=agent_id,
            tool_name=tool_name,
            arguments=arguments,
            output=output,
            status=status,
            error_message=error_message,
            duration_ms=duration_ms,
        )
        self._emitter.emit(event)
        return event

    def collect_llm(
        self,
        model: str,
        prompt: Optional[Any] = None,
        response: Optional[str] = None,
        prompt_tokens: Optional[int] = None,
        completion_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        duration_ms: Optional[float] = None,
    ) -> LLMEvent:
        sess_id, agent_id, parent_id = self._get_context_parameters()
        total_tok = None
        if prompt_tokens is not None and completion_tokens is not None:
            total_tok = prompt_tokens + completion_tokens

        event = LLMEvent(
            session_id=sess_id,
            agent_id=agent_id,
            model=model,
            prompt=prompt,
            response=response,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tok,
            temperature=temperature,
            duration_ms=duration_ms,
        )
        self._emitter.emit(event)
        return event

    def collect_memory(
        self,
        action: str,
        key: str,
        value: Optional[Any] = None,
        previous_value: Optional[Any] = None,
        store_name: Optional[str] = "default",
    ) -> MemoryEvent:
        sess_id, agent_id, parent_id = self._get_context_parameters()
        event = MemoryEvent(
            session_id=sess_id,
            agent_id=agent_id,
            action=action,
            key=key,
            value=value,
            previous_value=previous_value,
            store_name=store_name,
        )
        self._emitter.emit(event)
        return event

    def collect_filesystem(
        self,
        action: str,
        path: str,
        content_hash: Optional[str] = None,
        bytes_transferred: Optional[int] = None,
        status: str = "success",
        error_message: Optional[str] = None,
    ) -> FilesystemEvent:
        sess_id, agent_id, parent_id = self._get_context_parameters()
        event = FilesystemEvent(
            session_id=sess_id,
            agent_id=agent_id,
            action=action,
            path=path,
            content_hash=content_hash,
            bytes_transferred=bytes_transferred,
            status=status,
            error_message=error_message,
        )
        self._emitter.emit(event)
        return event

    def collect_network(
        self,
        action: str,
        url: str,
        method: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        status_code: Optional[int] = None,
        bytes_sent: Optional[int] = None,
        bytes_received: Optional[int] = None,
        duration_ms: Optional[float] = None,
        error_message: Optional[str] = None,
    ) -> NetworkEvent:
        sess_id, agent_id, parent_id = self._get_context_parameters()
        event = NetworkEvent(
            session_id=sess_id,
            agent_id=agent_id,
            action=action,
            url=url,
            method=method,
            headers=headers,
            status_code=status_code,
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            duration_ms=duration_ms,
            error_message=error_message,
        )
        self._emitter.emit(event)
        return event
