from abc import ABC, abstractmethod
import logging
import time
from typing import Any, Callable, Dict

from runtimeverify.interception.exceptions import ActionExecutionError
from runtimeverify.interception.models import Action, ActionResult, ActionType

logger = logging.getLogger(__name__)


class ActionExecutor(ABC):
    """
    Abstract interface defining the execution boundary for approved agent actions.
    Separates verification and policy logic from physical execution.
    """

    @abstractmethod
    def execute(self, action: Action) -> ActionResult:
        """
        Executes an approved action and returns an ActionResult.

        Args:
            action: The verified Action instance to execute.

        Returns:
            ActionResult containing output, success status, and duration.

        Raises:
            ActionExecutionError: If execution fails.
        """
        pass

    @abstractmethod
    def can_execute(self, action: Action) -> bool:
        """Checks whether this executor supports executing the specified action."""
        pass


class SafeActionExecutor(ActionExecutor):
    """
    Safe action executor implementing controlled execution and sandboxed callbacks.

    Security design:
    - Never invokes arbitrary OS shell commands blindly unless an explicit vetted handler is provided.
    - Allows registering custom handlers per ActionType.
    - Default behavior simulates dry-run execution safely for verification environments.
    """

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self._handlers: Dict[ActionType, Callable[[Action], Any]] = {}

    def register_handler(
        self,
        action_type: ActionType,
        handler: Callable[[Action], Any],
    ) -> None:
        """Registers a custom execution callable for a specific action category."""
        self._handlers[action_type] = handler

    def can_execute(self, action: Action) -> bool:
        """Returns True if a custom handler is registered or dry-run mode is active."""
        return action.action_type in self._handlers or self.dry_run

    def execute(self, action: Action) -> ActionResult:
        """
        Safely executes an approved action via its registered handler or dry-run simulator.
        """
        start_time = time.perf_counter()

        try:
            handler = self._handlers.get(action.action_type)
            if handler is not None:
                output = handler(action)
            elif self.dry_run:
                # Safe dry-run execution
                output = {
                    "status": "simulated_success",
                    "action_type": action.action_type.value,
                    "target": action.target,
                    "params": action.params,
                }
            else:
                raise RuntimeError(
                    f"No execution handler registered for action type '{action.action_type.value}' "
                    "and dry-run mode is disabled."
                )

            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ActionResult(
                action_id=action.action_id,
                success=True,
                output=output,
                duration_ms=round(duration_ms, 3),
                metadata={"dry_run": self.dry_run and action.action_type not in self._handlers},
            )

        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error("Execution failed for action '%s': %s", action.action_id, e)
            raise ActionExecutionError(
                action_id=action.action_id,
                executor_name=self.__class__.__name__,
                cause=e,
            ) from e
