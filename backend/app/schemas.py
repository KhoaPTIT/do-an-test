"""Pydantic schema cho request/response — field snake_case theo docs/api-contract.md."""

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1)


class LoginResponse(BaseModel):
    success: bool
    message: str
