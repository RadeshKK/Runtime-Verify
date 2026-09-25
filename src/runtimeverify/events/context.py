from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class EventContext(BaseModel):
    """
    Environmental and system execution context attached to an event.
    Provides diagnostic provenance (working directory, host, process, thread, user).

    Configured with extra='allow' so callers and future versions can attach
    custom contextual properties without breaking schema validation.
    """

    model_config = ConfigDict(frozen=True, extra="allow")

    current_directory: Optional[str] = Field(default=None, description="Working directory of the agent process")
    user: Optional[str] = Field(default=None, description="OS or runtime user identity under which the agent executes")
    hostname: Optional[str] = Field(default=None, description="Host system name or container identifier")
    platform: Optional[str] = Field(default=None, description="Operating system platform (e.g. linux, win32, darwin)")
    process_id: Optional[int] = Field(default=None, description="OS process identifier (PID)")
    thread_id: Optional[str] = Field(default=None, description="OS thread or asyncio task identifier")
    git_branch: Optional[str] = Field(default=None, description="Active git branch in the workspace, if applicable")
    git_commit: Optional[str] = Field(default=None, description="Active git commit SHA in the workspace, if applicable")
    tags: Dict[str, str] = Field(default_factory=dict, description="Arbitrary string tag labels")

    def __getitem__(self, item: str) -> Any:
        if hasattr(self, item):
            return getattr(self, item)
        extra = getattr(self, "__pydantic_extra__", None)
        if extra and item in extra:
            return extra[item]
        raise KeyError(f"Context key '{item}' not found.")

    def get(self, item: str, default: Any = None) -> Any:
        try:
            return self[item]
        except KeyError:
            return default
