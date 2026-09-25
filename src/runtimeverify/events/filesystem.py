from typing import Optional
from pydantic import Field
from runtimeverify.events.base import Event


class FilesystemEvent(Event):
    """
    Event representing a file system interaction, such as reading, writing, or deleting files.
    """

    type: str = Field("filesystem", description="Event type discriminator")
    action: str = Field(..., description="The filesystem operation (e.g., read, write, delete, create, list, move)")
    path: str = Field(..., description="The path of the target file or directory")
    content_hash: Optional[str] = Field(None, description="SHA-256 hash of the file contents (especially for writes)")
    bytes_transferred: Optional[int] = Field(None, description="The size of read/write operations in bytes")
    status: str = Field("success", description="The status of the file operation (e.g., success, error)")
    error_message: Optional[str] = Field(None, description="Detailed error message if the operation failed")
