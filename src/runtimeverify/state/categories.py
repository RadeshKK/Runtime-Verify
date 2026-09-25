from enum import Enum


class StateCategory(str, Enum):
    """
    Enum representing high-level operational categories for semantic states.
    Helps group states for downstream policy logic and metric aggregation.
    """

    FILESYSTEM = "filesystem"
    LLM = "llm"
    TOOL = "tool"
    MEMORY = "memory"
    NETWORK = "network"
    DATABASE = "database"
    EXECUTION = "execution"
    SECURITY = "security"
    HUMAN = "human"
    POLICY = "policy"
    SYSTEM = "system"
