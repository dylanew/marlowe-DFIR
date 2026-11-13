"""Minimal client for a local Ollama server's chat API.

Why not the ``ollama`` Python package? Two endpoints is all we need, and the
standard library's ``urllib`` covers them. That means no extra dependency,
nothing hidden, and an easy client to read and test.

Everything stays on the machine: the default URL is ``localhost``.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Protocol

DEFAULT_URL = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_MODEL = os.environ.get("MARLOWE_MODEL", "llama3.1:8b")


class OllamaError(RuntimeError):
    pass


class ChatClient(Protocol):
    """Anything that can answer a chat request. Tests use a scripted fake."""

    model: str

    def chat(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]: ...


class OllamaClient:
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_URL,
        timeout: float = 300,
        temperature: float = 0.0,
        num_ctx: int = 8192,
        max_tokens: int = 1024,
    ):
        if not base_url.startswith("http"):
            base_url = f"http://{base_url}"
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        # temperature 0: the same question should give the same answer, which
        # matters for reproducibility. num_ctx: context window in tokens; 8k is
        # enough for our bounded tool outputs and modest on memory.
        # max_tokens (Ollama's num_predict) caps one reply. A real answer is a
        # few hundred tokens; without a cap, a model stuck repeating itself at
        # temperature 0 runs until the request times out, every time.
        self.options = {"temperature": temperature, "num_ctx": num_ctx, "num_predict": max_tokens}

    def _request(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST" if data is not None else "GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            raise OllamaError(f"Ollama returned HTTP {exc.code}: {body}") from exc
        except TimeoutError as exc:
            raise OllamaError(
                f"timed out: no reply from Ollama within {self.timeout:g} s. The model may be "
                "stuck repeating itself; lower max_tokens or raise the timeout."
            ) from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise OllamaError(
                    f"timed out: no reply from Ollama within {self.timeout:g} s"
                ) from exc
            raise OllamaError(
                f"Cannot reach Ollama at {self.base_url} ({exc.reason}). "
                "Is it running? Try `ollama serve` or open the Ollama app."
            ) from exc

    def list_models(self) -> list[str]:
        return [m["name"] for m in self._request("/api/tags").get("models", [])]

    def chat(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        """Send one non-streaming chat request and return the assistant message."""
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": self.options,
        }
        if tools:
            payload["tools"] = tools
        response = self._request("/api/chat", payload)
        if "message" not in response:
            raise OllamaError(f"Unexpected response from Ollama: {response}")
        message = response["message"]
        message["_metrics"] = {
            k: response.get(k)
            for k in ("total_duration", "prompt_eval_count", "eval_count", "eval_duration")
        }
        return message
