import time
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from argo.config import OLLAMA_URL

_NOT_RUNNING = (
    "Ollama non raggiungibile: avvia `ollama serve` (oppure `brew services start ollama`)."
)


class OllamaError(RuntimeError):
    pass


@dataclass(frozen=True)
class ChatResult:
    content: str
    tokens_in: int
    tokens_out: int
    latency_s: float


class LLMClient(Protocol):
    def chat(
        self,
        model: str,
        system: str,
        user: str,
        schema: dict[str, Any] | None,
        options: dict[str, Any],
        think: bool | None = None,
    ) -> ChatResult: ...

    def model_digest(self, model: str) -> str: ...

    def embed(self, model: str, texts: list[str]) -> list[list[float]]: ...


def _missing(model: str) -> OllamaError:
    return OllamaError(f"Modello mancante: esegui `ollama pull {model}`.")


class OllamaClient:
    def __init__(
        self,
        base_url: str = OLLAMA_URL,
        timeout: float = 600.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.http = httpx.Client(base_url=base_url, timeout=timeout, transport=transport)

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        try:
            r = self.http.request(method, path, json=payload)
        except httpx.ConnectError as e:
            raise OllamaError(_NOT_RUNNING) from e
        if r.status_code == 404 and payload and "not found" in r.text:
            raise _missing(str(payload.get("model")))
        if r.status_code >= 400:
            raise OllamaError(f"Errore Ollama {r.status_code}: {r.text[:300]}")
        return r.json()

    def chat(
        self,
        model: str,
        system: str,
        user: str,
        schema: dict[str, Any] | None,
        options: dict[str, Any],
        think: bool | None = None,
    ) -> ChatResult:
        payload: dict[str, Any] = {
            "model": model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "options": options,
        }
        if schema is not None:
            payload["format"] = schema
        if think is not None:
            payload["think"] = think
        t0 = time.perf_counter()
        data = self._request("POST", "/api/chat", payload)
        return ChatResult(
            content=data["message"]["content"],
            tokens_in=int(data.get("prompt_eval_count", 0)),
            tokens_out=int(data.get("eval_count", 0)),
            latency_s=round(time.perf_counter() - t0, 3),
        )

    def model_digest(self, model: str) -> str:
        data = self._request("GET", "/api/tags")
        names = {model, f"{model}:latest"}
        for m in data.get("models", []):
            if m.get("name") in names or m.get("model") in names:
                return str(m.get("digest", ""))
        raise _missing(model)

    def embed(self, model: str, texts: list[str]) -> list[list[float]]:
        data = self._request("POST", "/api/embed", {"model": model, "input": texts})
        embeddings: list[list[float]] = data["embeddings"]
        return embeddings
