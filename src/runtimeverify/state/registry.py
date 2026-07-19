from typing import Dict, Optional, Set
from runtimeverify.state.hierarchy import StateHierarchy
from runtimeverify.state.categories import StateCategory

class StateRegistry:
    """
    Central registry for known or allowed semantic states within the framework.
    Helps validate states during encoding and prevents runtime spelling drift.
    """
    def __init__(self):
        self._states: Dict[str, StateHierarchy] = {}
        self._categories: Dict[str, StateCategory] = {}

    def register(self, name: str, hierarchy: StateHierarchy, category: StateCategory) -> None:
        """
        Registers a semantic state template.
        
        Args:
            name: The lookup name (e.g. 'WRITE_SOURCE')
            hierarchy: The StateHierarchy instance describing its taxonomy path
            category: The StateCategory enum value grouping this state
        """
        state_key = name.upper()
        self._states[state_key] = hierarchy
        self._categories[state_key] = category

    def is_registered(self, name: str) -> bool:
        """Checks if a state name is present in the registry."""
        return name.upper() in self._states

    def get_hierarchy(self, name: str) -> Optional[StateHierarchy]:
        """Retrieves the hierarchy for a registered state name, or None."""
        return self._states.get(name.upper())

    def get_category(self, name: str) -> Optional[StateCategory]:
        """Retrieves the category for a registered state name, or None."""
        return self._categories.get(name.upper())

    def list_registered_states(self) -> Set[str]:
        """Returns a set of all registered state names."""
        return set(self._states.keys())

    def clear(self) -> None:
        """Clears all registrations."""
        self._states.clear()
        self._categories.clear()
