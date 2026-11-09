from typing import Any, Callable, Optional
import uuid

from runtimeverify.events import LLMEvent
from runtimeverify.interception.contract import InterceptionFailureMode, UnifiedInterceptionContract
from runtimeverify.interception.models import Action, ActionType, ExecutionContext
from runtimeverify.telemetry.manager import get_global_manager


class PydanticAIAdapter:
    """
    Adapter for PydanticAI. Enforces pre-execution tool gating,
    and captures prompt runs, token usage, and responses to emit standard LLMEvents.
    """

    @staticmethod
    def instrument_tool(
        tool_fn: Callable[..., Any],
        tool_name: Optional[str] = None,
        session: Optional[Any] = None,
        fail_closed: bool = True,
    ) -> Callable[..., Any]:
        """
        Wraps a PydanticAI tool with pre-execution gating.
        """
        contract = UnifiedInterceptionContract(
            session=session,
            failure_mode=InterceptionFailureMode.FAIL_CLOSED if fail_closed else InterceptionFailureMode.FAIL_OPEN,
        )
        return contract.wrap_tool(tool_fn, tool_name=tool_name, action_type=ActionType.TOOL)

    @staticmethod
    def instrument_agent(agent: Any, session: Optional[Any] = None, fail_closed: bool = True) -> None:
        """
        Instruments a PydanticAI agent instance using its native event hooks
        to capture prompt runs and outputs with pre-execution gating.
        """
        contract = (
            UnifiedInterceptionContract(
                session=session,
                failure_mode=InterceptionFailureMode.FAIL_CLOSED if fail_closed else InterceptionFailureMode.FAIL_OPEN,
            )
            if session is not None
            else None
        )

        original_run = getattr(agent, "run", None)
        if original_run:

            def run_wrapper(prompt: str, *args: Any, **kwargs: Any) -> Any:
                session_id = kwargs.get("session_id", "pydanticai_session")
                agent_id = getattr(agent, "name", "pydanticai_agent")

                if contract is not None:
                    ctx = ExecutionContext(session_id=session_id, agent_id=agent_id)
                    action = Action(
                        action_id=f"act_pai_{uuid.uuid4().hex[:10]}",
                        action_type=ActionType.CUSTOM,
                        name="llm_request",
                        target=getattr(agent, "name", "pydanticai_model"),
                        params={"prompt": prompt, "kwargs": kwargs},
                        context=ctx,
                        agent_id=agent_id,
                        session_id=session_id,
                    )
                    contract.gate_action(action)

                try:
                    result = original_run(prompt, *args, **kwargs)

                    prompt_tokens = getattr(getattr(result, "usage", None), "prompt_tokens", 0)
                    comp_tokens = getattr(getattr(result, "usage", None), "completion_tokens", 0)
                    total_tokens = getattr(getattr(result, "usage", None), "total_tokens", 0)

                    event = LLMEvent(
                        session_id=session_id,
                        agent_id=agent_id,
                        model=getattr(result, "model_name", "unknown_model"),
                        prompt_tokens=prompt_tokens,
                        completion_tokens=comp_tokens,
                        total_tokens=total_tokens,
                        metadata={"prompt": prompt, "response": str(getattr(result, "data", ""))},
                    )
                    get_global_manager().bus.publish(event)
                    return result
                except Exception as e:
                    raise e

            agent.run = run_wrapper
