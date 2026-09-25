from typing import Any
from runtimeverify.telemetry.manager import get_global_manager
from runtimeverify.events import LLMEvent


class PydanticAIAdapter:
    """
    Adapter for PydanticAI. Captures run inputs, token usage,
    and model responses to emit standard LLMEvents.
    """

    @staticmethod
    def instrument_agent(agent: Any) -> None:
        """
        Instruments a PydanticAI agent instance using its native event hooks
        to capture prompt runs and outputs.
        """
        # We check if the agent has a run middleware or run hook interface.
        # Since we avoid importing PydanticAI directly, we use dynamic proxying.
        if not hasattr(agent, "on_run_start") and not hasattr(agent, "on_run_end"):
            # Fallback decorator wrapper approach if hooks are unavailable
            original_run = getattr(agent, "run", None)
            if original_run:

                def run_wrapper(prompt: str, *args, **kwargs) -> Any:
                    session_id = kwargs.get("session_id", "pydanticai_session")
                    agent_id = getattr(agent, "name", "pydanticai_agent")

                    try:
                        result = original_run(prompt, *args, **kwargs)

                        # Extract token counts dynamically if result object contains them
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
                            metadata={"prompt": prompt, "response": str(result.data)},
                        )
                        get_global_manager().bus.publish(event)
                        return result
                    except Exception as e:
                        raise e

                agent.run = run_wrapper
