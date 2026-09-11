import json

import httpx
import pytest

from argo.llm.ollama import OllamaClient, OllamaError


def _client(handler) -> OllamaClient:
    return OllamaClient(base_url="http://ollama", transport=httpx.MockTransport(handler))


def test_chat_payload_and_result():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "message": {"content": '{"ok": true}'},
                "prompt_eval_count": 120,
                "eval_count": 9,
            },
        )

    res = _client(handler).chat(
        "qwen3:4b", "sys", "usr", {"type": "object"}, {"temperature": 0.0, "seed": 1}, think=False
    )
    assert res.content == '{"ok": true}' and (res.tokens_in, res.tokens_out) == (120, 9)
    assert (
        seen["stream"] is False and seen["think"] is False and seen["format"] == {"type": "object"}
    )
    assert [m["role"] for m in seen["messages"]] == ["system", "user"]
    assert seen["options"] == {"temperature": 0.0, "seed": 1}


def test_think_omitted_when_none():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return httpx.Response(200, json={"message": {"content": "{}"}})

    _client(handler).chat("llama3.2:3b", "s", "u", None, {})
    assert "think" not in seen and "format" not in seen


def test_connection_refused_message():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with pytest.raises(OllamaError, match="ollama serve"):
        _client(handler).chat("m", "s", "u", None, {})


def test_missing_model_message():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "model 'x:1b' not found"})

    with pytest.raises(OllamaError, match="ollama pull x:1b"):
        _client(handler).chat("x:1b", "s", "u", None, {})


def test_digest_matches_latest_tag():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "models": [
                    {"name": "nomic-embed-text:latest", "digest": "abc"},
                    {"name": "qwen3:4b", "digest": "def"},
                ]
            },
        )

    c = _client(handler)
    assert c.model_digest("nomic-embed-text") == "abc" and c.model_digest("qwen3:4b") == "def"
    with pytest.raises(OllamaError, match="ollama pull"):
        c.model_digest("gemma3:4b")


def test_embed():
    def handler(request: httpx.Request) -> httpx.Response:
        assert json.loads(request.content)["input"] == ["a", "b"]
        return httpx.Response(200, json={"embeddings": [[1.0, 0.0], [0.0, 1.0]]})

    assert _client(handler).embed("e", ["a", "b"]) == [[1.0, 0.0], [0.0, 1.0]]


def test_timeout_message():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    with pytest.raises(OllamaError, match="Ollama non ha risposto in tempo"):
        _client(handler).chat("m", "s", "u", None, {})


def test_other_transport_errors_are_wrapped():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.RemoteProtocolError("server disconnected")

    with pytest.raises(OllamaError, match="Errore di comunicazione con Ollama"):
        _client(handler).embed("e", ["a"])


def test_version():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/version"
        return httpx.Response(200, json={"version": "0.12.3"})

    assert _client(handler).version() == "0.12.3"
