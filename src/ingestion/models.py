from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional


class RequestRecord(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.now)
    method: str
    path: str
    query_params: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    status_code: Optional[int] = None
    session_id: Optional[str] = None
    source_ip: Optional[str] = None
    response_body: Optional[str] = None

    def normalized_endpoint(self) -> str:
        return f"{self.method} {self.path}"

    def __hash__(self):
        return hash((self.timestamp, self.method, self.path))
