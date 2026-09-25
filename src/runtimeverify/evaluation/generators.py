from typing import List
from runtimeverify.events import (
    Event,
    ToolEvent,
    LLMEvent,
    MemoryEvent,
    FilesystemEvent,
    NetworkEvent,
)


class TraceGenerator:
    """
    Generates representative synthetic agent trace sequences (events).
    Provides methods to inject specific anomalies (rare transitions, escalations, loops).
    """

    @staticmethod
    def generate_coding_session(session_id: str, agent_id: str = "coder_agent") -> List[Event]:
        """Generates a standard normal coding session trace of Event objects."""
        return [
            Event(session_id=session_id, agent_id=agent_id, type="agent_start"),
            FilesystemEvent(session_id=session_id, agent_id=agent_id, action="read", path="/workspace/src/main.py"),
            LLMEvent(
                session_id=session_id, agent_id=agent_id, model="mock-gpt", prompt="fix bug", response="fixed code"
            ),
            FilesystemEvent(session_id=session_id, agent_id=agent_id, action="write", path="/workspace/src/main.py"),
            ToolEvent(
                session_id=session_id,
                agent_id=agent_id,
                tool_name="run_pytest",
                arguments={"path": "tests/"},
                status="success",
            ),
            Event(session_id=session_id, agent_id=agent_id, type="agent_end"),
        ]

    @staticmethod
    def generate_research_session(session_id: str, agent_id: str = "research_agent") -> List[Event]:
        """Generates a standard normal web research session trace."""
        return [
            Event(session_id=session_id, agent_id=agent_id, type="agent_start"),
            NetworkEvent(
                session_id=session_id, agent_id=agent_id, action="request", url="https://example.com/search?q=agents"
            ),
            LLMEvent(
                session_id=session_id,
                agent_id=agent_id,
                model="mock-gpt",
                prompt="summarize search",
                response="summary text",
            ),
            MemoryEvent(
                session_id=session_id, agent_id=agent_id, action="write", key="research_summary", value="summary text"
            ),
            Event(session_id=session_id, agent_id=agent_id, type="agent_end"),
        ]

    # --- Anomaly Injectors ---

    @staticmethod
    def inject_rare_transition(events: List[Event]) -> List[Event]:
        """
        Injects a rare transition: e.g. starting and immediately ending or
        calling run_pytest without reading code first.
        """
        if len(events) < 3:
            return events

        modified = list(events)
        # Swap start to commit/end directly
        start = modified[0]
        end = modified[-1]

        # Inject jump directly from start to end (illegal skip of execution logic)
        return [start, end]

    @staticmethod
    def inject_permission_escalation(events: List[Event]) -> List[Event]:
        """Modifies a filesystem event to target a sensitive root location instead of workspace."""
        modified: List[Event] = []
        injected = False

        for event in events:
            if isinstance(event, FilesystemEvent) and not injected:
                # Alter to sensitive path
                altered = FilesystemEvent(
                    id=event.id,
                    timestamp=event.timestamp,
                    session_id=event.session_id,
                    agent_id=event.agent_id,
                    action=event.action,
                    path="/etc/shadow",
                    content_hash=event.content_hash,
                    bytes_transferred=event.bytes_transferred,
                    status=event.status,
                )
                modified.append(altered)
                injected = True
            else:
                modified.append(event)

        return modified

    @staticmethod
    def inject_tool_misuse(events: List[Event]) -> List[Event]:
        """Inserts a tool event invoking a dangerous command never seen in training."""
        if len(events) < 3:
            return events

        modified = list(events)
        session_id = events[0].session_id
        agent_id = events[0].agent_id

        # Inject untrusted tool call midway
        dangerous_tool = ToolEvent(
            session_id=session_id,
            agent_id=agent_id,
            tool_name="execute_command",
            arguments={"cmd": "rm -rf /"},
            status="success",
        )
        modified.insert(len(modified) // 2, dangerous_tool)
        return modified

    @staticmethod
    def inject_infinite_loop(events: List[Event]) -> List[Event]:
        """Repeats a subsequence of events multiple times to simulate an execution loop."""
        if len(events) < 4:
            return events

        # Repeat the middle steps 10 times
        loop_section = events[1:-1]
        modified = [events[0]]
        for _ in range(10):
            modified.extend(loop_section)
        modified.append(events[-1])
        return modified
