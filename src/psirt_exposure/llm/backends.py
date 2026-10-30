"""Pluggable LLM backends that return JSON constrained by a JSON Schema.

* ``ollama`` (default): a local Ollama server; the schema goes in the ``format`` field, so
  advisory text and configs never leave the host.
* ``openai``: any OpenAI-compatible ``/chat/completions`` endpoint (vLLM, LM Studio, llama.cpp
  server, hosted APIs) using ``response_format: json_schema``. The API key is read from an
  environment variable and is never logged.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "foundation-sec-8b-instruct"  # see ollama/*.Modelfile
DEFAULT_OPENAI_URL = "https://api.openai.com/v1"
DEFAULT_TIMEOUT = 600.0


class BackendError(RuntimeError):
    """The LLM endpoint failed or returned an unexpected response."""


class Backend(Protocol):
    @property
    def name(self) -> str: ...

    def generate(self, system: str, user: str, schema: dict[str, Any]) -> str:
        """Return the model's reply (a JSON document as text)."""
        ...


def _post(client: httpx.Client, url: str, payload: dict[str, Any], **kw: Any) -> Any:
    try:
        response = client.post(url, json=payload, **kw)
    except httpx.HTTPError as exc:
        raise BackendError(f"request to {url} failed: {exc}") from exc
    if response.status_code != 200:
        raise BackendError(f"{url} returned HTTP {response.status_code}: {response.text[:300]}")
    try:
        return response.json()
    except ValueError as exc:
        raise BackendError(f"{url} returned non-JSON: {response.text[:300]}") from exc


@dataclass
class OllamaBackend:
    model: str = DEFAULT_OLLAMA_MODEL
    base_url: str = DEFAULT_OLLAMA_URL
    temperature: float = 0.0
    num_ctx: int = 8192
    client: httpx.Client = field(default_factory=lambda: httpx.Client(timeout=DEFAULT_TIMEOUT))

    @property
    def name(self) -> str:
        return f"ollama:{self.model}"

    def generate(self, system: str, user: str, schema: dict[str, Any]) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "format": schema,
            "stream": False,
            "options": {"temperature": self.temperature, "num_ctx": self.num_ctx, "seed": 0},
        }
        data = _post(self.client, f"{self.base_url.rstrip('/')}/api/chat", payload)
        try:
            return str(data["message"]["content"])
        except (KeyError, TypeError) as exc:
            raise BackendError(f"unexpected Ollama response: {str(data)[:300]}") from exc


@dataclass
class OpenAICompatibleBackend:
    model: str
    base_url: str = DEFAULT_OPENAI_URL
    api_key_env: str = "OPENAI_API_KEY"
    temperature: float = 0.0
    client: httpx.Client = field(default_factory=lambda: httpx.Client(timeout=DEFAULT_TIMEOUT))

    @property
    def name(self) -> str:
        return f"openai:{self.model}"

    def generate(self, system: str, user: str, schema: dict[str, Any]) -> str:
        payload = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "rule", "schema": schema, "strict": False},
            },
        }
        headers = {}
        key = os.environ.get(self.api_key_env)
        if key:
            headers["Authorization"] = f"Bearer {key}"
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        data = _post(self.client, url, payload, headers=headers)
        try:
            return str(data["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise BackendError(f"unexpected response: {str(data)[:300]}") from exc


def make_backend(kind: str, model: str | None = None, base_url: str | None = None) -> Backend:
    if kind == "ollama":
        return OllamaBackend(
            model=model or DEFAULT_OLLAMA_MODEL, base_url=base_url or DEFAULT_OLLAMA_URL
        )
    if kind == "openai":
        if not model:
            raise ValueError("the openai backend needs --model")
        return OpenAICompatibleBackend(model=model, base_url=base_url or DEFAULT_OPENAI_URL)
    raise ValueError(f"unknown backend {kind!r} (expected 'ollama' or 'openai')")
