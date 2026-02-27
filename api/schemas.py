"""Pydantic schemas for WAF API."""

from pydantic import BaseModel, Field


class ScoreRequest(BaseModel):
    request_text: str = Field(..., description="Serialized request string")


class ScoreResponse(BaseModel):
    score: float = Field(..., description="ML risk score 0-1")
    label: str = Field(..., description="benign or malicious")
    confidence: float = Field(..., description="Confidence of prediction")


class BatchScoreRequest(BaseModel):
    requests: list[str] = Field(..., description="List of serialized request strings")


class BatchScoreResponse(BaseModel):
    results: list[ScoreResponse] = Field(..., description="List of score results")
