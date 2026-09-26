"""
Trace loader and parser for the RuntimeVerify Attack / Agent Replay Engine.
Supports JSON arrays, JSON Lines (NDJSON), envelope dictionaries,
and LLM agent tool call transcripts.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from runtimeverify.events.base import Event
from runtimeverify.interception.models import Action, ActionType, ExecutionContext


class TraceLoader:
    """
    Ingests recorded agent execution traces across heterogeneous formats and converts
    them into standardized RuntimeVerify Actions for multi-tier verification.
    """

    @classmethod
    def load(
        cls,
        source: Union[str, Path, List[Dict[str, Any]], Dict[str, Any]],
        default_session_id: str = "replay-session",
        default_agent_id: str = "replay-agent",
    ) -> Tuple[List[Action], Dict[str, Any]]:
        """
        Parses an agent trace source into a sequence of Action instances and metadata.

        Args:
            source: File path, JSON string, or Python dictionary/list.
            default_session_id: Fallback session ID if not present in trace.
            default_agent_id: Fallback agent ID if not present in trace.

        Returns:
            Tuple of (List of normalized Actions, trace metadata dict).
        """
        raw_items: List[Any] = []
        metadata: Dict[str, Any] = {
            "session_id": default_session_id,
            "agent_id": default_agent_id,
            "source": str(source) if isinstance(source, (str, Path)) else "in-memory",
        }

        # 1. Resolve source to raw python structures
        if isinstance(source, (str, Path)):
            path = Path(source)
            if path.is_file():
                content = path.read_text(encoding="utf-8").strip()
                raw_items, file_meta = cls._parse_text_content(content)
                metadata.update(file_meta)
            else:
                # Attempt to parse raw string content directly as JSON
                raw_items, str_meta = cls._parse_text_content(str(source).strip())
                metadata.update(str_meta)
        elif isinstance(source, list):
            raw_items = source
        elif isinstance(source, dict):
            raw_items, dict_meta = cls._extract_from_envelope(source)
            metadata.update(dict_meta)
        else:
            raise ValueError(f"Unsupported trace source type: {type(source).__name__}")

        # 2. Normalize raw items into Action objects
        actions: List[Action] = []
        for idx, item in enumerate(raw_items, 1):
            if isinstance(item, Action):
                actions.append(item)
                continue
            if isinstance(item, Event):
                act = cls._event_to_action(item, metadata["session_id"], metadata["agent_id"])
                actions.append(act)
                continue
            if isinstance(item, dict):
                act = cls._dict_to_action(
                    item,
                    step_index=idx,
                    session_id=metadata.get("session_id", default_session_id),
                    agent_id=metadata.get("agent_id", default_agent_id),
                )
                if act:
                    actions.append(act)
                    continue

        return actions, metadata

    @classmethod
    def _parse_text_content(cls, content: str) -> Tuple[List[Any], Dict[str, Any]]:
        """Parses raw text content as either single JSON or NDJSON."""
        meta: Dict[str, Any] = {}
        # Try full JSON parse first
        try:
            parsed = json.loads(content)
            if isinstance(parsed, list):
                return parsed, meta
            if isinstance(parsed, dict):
                return cls._extract_from_envelope(parsed)
        except json.JSONDecodeError:
            pass

        # Try JSON Lines / NDJSON parse
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        items: List[Any] = []
        for line in lines:
            try:
                item = json.loads(line)
                items.append(item)
            except json.JSONDecodeError:
                continue

        if items:
            return items, meta

        raise ValueError("Failed to parse trace: content is neither valid JSON nor valid JSON Lines (NDJSON).")

    @classmethod
    def _extract_from_envelope(cls, data: Dict[str, Any]) -> Tuple[List[Any], Dict[str, Any]]:
        """Extracts event array from standard wrapper schemas."""
        meta: Dict[str, Any] = {
            "session_id": data.get("session_id") or data.get("session", "replay-session"),
            "agent_id": data.get("agent_id") or data.get("agent", "replay-agent"),
        }
        for candidate_key in ("events", "actions", "trace", "steps", "records", "history"):
            if candidate_key in data and isinstance(data[candidate_key], list):
                return data[candidate_key], meta

        # If data is a single event dictionary, treat as 1-element list
        return [data], meta

    @classmethod
    def _dict_to_action(
        cls,
        data: Dict[str, Any],
        step_index: int,
        session_id: str,
        agent_id: str,
    ) -> Optional[Action]:
        """Maps an arbitrary agent dictionary or tool-call representation into an Action."""
        sid = data.get("session_id") or session_id
        aid = data.get("agent_id") or agent_id
        ctx = ExecutionContext(session_id=sid, agent_id=aid, step_index=step_index)

        # A. Handle OpenAI / Anthropic tool-call structure
        # e.g. {"tool_calls": [{"function": {"name": "run_command", "arguments": "{\"command\": \"cat .env\"}"}}]}
        if "tool_calls" in data and isinstance(data["tool_calls"], list) and data["tool_calls"]:
            tc = data["tool_calls"][0]
            func = tc.get("function", {})
            func_name = func.get("name", "unknown_tool")
            args = func.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {"raw_args": args}
            return cls._tool_call_to_action(func_name, args, sid, aid, ctx)

        # B. Handle generic Tool Event {"tool": "...", "arguments": {...}}
        tool_name = data.get("tool") or data.get("tool_name")
        if tool_name:
            args = data.get("arguments") or data.get("args") or data.get("params") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {"raw_args": args}
            return cls._tool_call_to_action(str(tool_name), args, sid, aid, ctx)

        # C. Direct Action/Event attributes
        raw_type = (
            data.get("action_type")
            or data.get("type")
            or data.get("event_type")
            or data.get("action")
            or "shell"
        )
        raw_type_str = str(raw_type).lower()

        command = data.get("command") or data.get("cmd")
        path = data.get("path") or data.get("file") or data.get("filepath")
        url = data.get("url") or data.get("endpoint")
        target = data.get("target") or command or path or url or "unknown"
        op = data.get("operation") or data.get("op") or data.get("name") or "execute"

        # Deduce type if generic
        if command or "sh" in raw_type_str or "cmd" in raw_type_str or "bash" in raw_type_str:
            return Action.shell(
                command=str(command or target),
                session_id=sid,
                agent_id=aid,
                context=ctx,
                working_directory=data.get("working_directory") or data.get("cwd"),
            )

        if path or "file" in raw_type_str or "fs" in raw_type_str:
            return Action.filesystem(
                operation=str(op),
                path=str(path or target),
                session_id=sid,
                agent_id=aid,
                content=data.get("content"),
                context=ctx,
            )

        if url or "net" in raw_type_str or "http" in raw_type_str or "request" in raw_type_str:
            return Action.network(
                url=str(url or target),
                method=str(data.get("method", "GET")),
                headers=data.get("headers"),
                body=data.get("body"),
                session_id=sid,
                agent_id=aid,
                context=ctx,
            )

        if "git" in raw_type_str:
            return Action.git(
                operation=str(op),
                branch=str(target),
                commit_message=data.get("commit_message"),
                session_id=sid,
                agent_id=aid,
                context=ctx,
            )

        if "proc" in raw_type_str or "spawn" in raw_type_str:
            return Action.process(
                command_line=str(command or target),
                session_id=sid,
                agent_id=aid,
                context=ctx,
            )

        # Fallback to Custom Action
        return Action(
            action_type=ActionType.CUSTOM,
            name=str(op),
            target=str(target),
            params=data.get("params") or data,
            context=ctx,
            session_id=sid,
            agent_id=aid,
        )

    @classmethod
    def _tool_call_to_action(
        cls,
        tool_name: str,
        arguments: Dict[str, Any],
        session_id: str,
        agent_id: str,
        context: ExecutionContext,
    ) -> Action:
        """Converts an agent tool call into a domain-specific Action."""
        t_lower = tool_name.lower()

        # Shell command tool
        if any(k in t_lower for k in ("bash", "sh", "exec", "terminal", "command", "run_cmd")):
            cmd = arguments.get("command") or arguments.get("cmd") or arguments.get("input") or str(arguments)
            return Action.shell(
                command=str(cmd),
                session_id=session_id,
                agent_id=agent_id,
                context=context,
                working_directory=arguments.get("working_directory") or arguments.get("cwd"),
            )

        # Filesystem tools
        if any(k in t_lower for k in ("file", "read", "write", "edit", "patch", "view")):
            op = "write" if any(w in t_lower for w in ("write", "edit", "patch", "create")) else "read"
            path = arguments.get("path") or arguments.get("file") or arguments.get("filename") or "unknown_file"
            return Action.filesystem(
                operation=op,
                path=str(path),
                content=arguments.get("content"),
                session_id=session_id,
                agent_id=agent_id,
                context=context,
            )

        # Network / Web tools
        if any(k in t_lower for k in ("http", "curl", "fetch", "web", "api", "request", "browser")):
            url = arguments.get("url") or arguments.get("endpoint") or arguments.get("uri") or "http://unknown"
            return Action.network(
                url=str(url),
                method=str(arguments.get("method", "GET")),
                headers=arguments.get("headers"),
                body=arguments.get("body") or arguments.get("data"),
                session_id=session_id,
                agent_id=agent_id,
                context=context,
            )

        # Git tools
        if "git" in t_lower:
            op = arguments.get("operation") or "commit"
            branch = arguments.get("branch") or arguments.get("target") or "main"
            return Action.git(
                operation=str(op),
                branch=str(branch),
                commit_message=arguments.get("message") or arguments.get("commit_message"),
                session_id=session_id,
                agent_id=agent_id,
                context=context,
            )

        # Generic / Custom tool call
        return Action(
            action_type=ActionType.CUSTOM,
            name=tool_name,
            target=str(arguments.get("target") or arguments.get("name") or tool_name),
            params=arguments,
            context=context,
            session_id=session_id,
            agent_id=agent_id,
        )

    @classmethod
    def _event_to_action(cls, event: Event, session_id: str, agent_id: str) -> Action:
        """Adapts an existing Event model to Action."""
        sid = event.session_id or session_id
        aid = event.agent_id or agent_id
        ctx = ExecutionContext(session_id=sid, agent_id=aid)

        ev_type = str(getattr(event, "type", getattr(event, "event_type", "generic"))).lower()

        if "shell" in ev_type:
            cmd = getattr(event, "command", "") or getattr(event, "target", "")
            return Action.shell(command=cmd, session_id=sid, agent_id=aid, context=ctx)
        if "file" in ev_type:
            path = getattr(event, "path", "") or getattr(event, "target", "")
            op = getattr(event, "action", "read")
            return Action.filesystem(operation=op, path=path, session_id=sid, agent_id=aid, context=ctx)
        if "net" in ev_type:
            url = getattr(event, "url", "") or getattr(event, "target", "")
            method = getattr(event, "method", "GET")
            return Action.network(url=url, method=method, session_id=sid, agent_id=aid, context=ctx)

        return Action(
            action_type=ActionType.CUSTOM,
            name=ev_type,
            target=str(getattr(event, "target", "unknown")),
            params=getattr(event, "payload", {}) or {},
            context=ctx,
            session_id=sid,
            agent_id=aid,
        )
