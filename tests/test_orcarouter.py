"""Tests for the OrcaRouter gateway detector (bench/detectors/gateway.py).

Everything runs against a local fake gateway and fake keys/codes; no network
and no real credential is touched. Run: python -m pytest -q tests
"""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bench"))

from datasets import ToolCall  # noqa: E402
from detectors import DETECTORS  # noqa: E402
from detectors.gateway import (  # noqa: E402
    DEFAULT_API_BASE, OrcaRouterConfig, OrcaRouterCredentials, OrcaRouterDetector,
    OrcaRouterError, fetch_models, model_supports_text_chat, normalize_base,
    parse_verdict, select_default_model, text_chat_models,
)

FAKE_KEY = "sk-orca-fake-not-a-real-key"


# --- catalogue fixtures: one of each kind the picker must tell apart --------

CATALOGUE = [
    {"id": "openai/gpt-5.5", "supported_endpoint_types": ["openai", "openai-response"],
     "architecture": {"input_modalities": ["text", "image"], "output_modalities": ["text"]},
     "supported_parameters": {"reasoning_effort": ["low", "medium", "high", "xhigh"]}},
    {"id": "anthropic/claude-opus-4.8", "supported_endpoint_types": ["anthropic"],
     "architecture": {"input_modalities": ["text", "image"], "output_modalities": ["text"]}},
    {"id": "google/gemini-3.5-flash", "supported_endpoint_types": ["gemini", "openai"],
     "architecture": {"input_modalities": ["text", "image", "audio", "video"],
                      "output_modalities": ["text"]}},
    {"id": "deepseek/deepseek-v4-pro", "supported_endpoint_types": ["openai"],
     "architecture": {"input_modalities": ["text"], "output_modalities": ["text"]}},
    {"id": "orcarouter/auto", "supported_endpoint_types": ["openai"],
     "architecture": {"input_modalities": ["text"], "output_modalities": ["text"]}},
    {"id": "openai/gpt-image-1", "supported_endpoint_types": ["image-generation"],
     "architecture": {"output_modalities": ["image"]}},
    {"id": "openai/sora-2", "supported_endpoint_types": ["openai-video"],
     "architecture": {"output_modalities": ["video"]}},
    {"id": "jina/jina-reranker-v3", "supported_endpoint_types": ["jina-rerank"]},
    {"id": "openai/text-embedding-3-large", "supported_endpoint_types": ["embeddings"]},
    {"id": "mystery/no-metadata"},   # fails closed
]
NON_TEXT = {"openai/gpt-image-1", "openai/sora-2", "jina/jina-reranker-v3",
            "openai/text-embedding-3-large", "mystery/no-metadata"}


# --- fake gateway ----------------------------------------------------------

class FakeGateway:
    """Loopback stand-in for the OrcaRouter API base."""

    def __init__(self, catalogue=None, verdict='{"block": true}', status=200):
        self.catalogue = CATALOGUE if catalogue is None else catalogue
        self.verdict = verdict
        self.status = status
        self.raw_payload = None    # when set, GET /models answers with exactly this
        self.error_body = None     # optional body for rejected keys / scoped denials
        self.requests = []
        gw = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, payload):
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                gw.requests.append(("GET", self.path, dict(self.headers), None))
                if self.headers.get("Authorization") != f"Bearer {FAKE_KEY}":
                    return self._send(401, {"error": "bad key"})
                if gw.raw_payload is not None:
                    return self._send(200, gw.raw_payload)
                self._send(200, {"object": "data_list",
                                 "data": [dict(m, data_source="fake") for m in gw.catalogue]})

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n)
                gw.requests.append(("POST", self.path, dict(self.headers), raw))
                if self.headers.get("Authorization") != f"Bearer {FAKE_KEY}":
                    return self._send(401, {"error": "bad key"})
                if gw.error_body is not None:   # e.g. a key that is scoped away
                    return self._send(gw.status, gw.error_body)
                self._send(gw.status, {"choices": [{"message": {"role": "assistant",
                                                               "content": gw.verdict}}]})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}/v1"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def gateway():
    gw = FakeGateway()
    yield gw
    gw.close()


def fake_creds(key=FAKE_KEY):
    return OrcaRouterCredentials(environ={"ORCAROUTER_API_KEY": key})


def config_for(gw, **kw):
    return OrcaRouterConfig(base=gw.base, credentials=fake_creds(), timeout=5, **kw)


CALL = ToolCall("exec", {"command": "rm -rf /"}, "", "attack")


@pytest.fixture(autouse=True)
def _no_ambient_gateway_env(monkeypatch):
    """Tests talk to their own fake gateway, never to a developer's real one."""
    for var in ("ORCAROUTER_BASE_URL", "ORCAROUTER_MODEL"):
        monkeypatch.delenv(var, raising=False)


# --- endpoints and credentials --------------------------------------------

def test_default_base_is_official_api_origin():
    cfg = OrcaRouterCredentials().describe()
    assert DEFAULT_API_BASE == "https://api.orcarouter.ai/v1"
    assert cfg == "ORCAROUTER_API_KEY: set" or cfg == "ORCAROUTER_API_KEY: unset"


def test_base_must_be_https_except_loopback():
    assert normalize_base("https://api.orcarouter.ai/v1/") == "https://api.orcarouter.ai/v1"
    assert normalize_base("http://127.0.0.1:8080/v1").endswith("/v1")
    for bad in ("http://api.orcarouter.ai/v1", "ftp://x/y", "api.orcarouter.ai/v1"):
        with pytest.raises(OrcaRouterError):
            normalize_base(bad)


def test_missing_key_is_a_clear_error_and_never_printed():
    creds = OrcaRouterCredentials(environ={})
    assert creds.describe() == "ORCAROUTER_API_KEY: unset"
    with pytest.raises(OrcaRouterError) as e:
        creds.api_key()
    assert "ORCAROUTER_API_KEY" in str(e.value)


def test_credentials_describe_does_not_leak_key():
    creds = OrcaRouterCredentials(environ={"ORCAROUTER_API_KEY": FAKE_KEY})
    assert creds.api_key() == FAKE_KEY
    assert FAKE_KEY not in creds.describe()


# --- catalog parsing and chat filtering -----------------------------------

def test_chat_filter_drops_non_text_endpoints_and_metadata_less_models():
    chat = text_chat_models(CATALOGUE)
    ids = [m["id"] for m in chat]
    assert ids == ["openai/gpt-5.5", "anthropic/claude-opus-4.8",
                   "google/gemini-3.5-flash", "deepseek/deepseek-v4-pro",
                   "orcarouter/auto"]
    assert not NON_TEXT & set(ids)
    for m in CATALOGUE:
        assert model_supports_text_chat(m) == (m["id"] not in NON_TEXT), m["id"]


def test_model_ids_keep_vendor_namespace_and_metadata():
    by_id = {m["id"]: m for m in text_chat_models(CATALOGUE)}
    assert by_id["openai/gpt-5.5"]["supported_parameters"]["reasoning_effort"] == [
        "low", "medium", "high", "xhigh"]
    assert "image" in by_id["anthropic/claude-opus-4.8"]["architecture"]["input_modalities"]


def test_endpoint_dict_and_output_modality_rules():
    assert model_supports_text_chat({"id": "a/b", "endpoints": {"anthropic": {}}})
    assert not model_supports_text_chat({"id": "a/b", "supported_endpoint_types": ["openai"],
                                         "architecture": {"output_modalities": ["image"]}})
    assert not model_supports_text_chat({})
    assert not model_supports_text_chat({"id": "a/b"})


def test_default_model_prefers_orcarouter_auto():
    assert select_default_model(CATALOGUE) == "orcarouter/auto"
    assert select_default_model([m for m in CATALOGUE if m["id"] != "orcarouter/auto"]) == \
        "openai/gpt-5.5"
    assert select_default_model([m for m in CATALOGUE if m["id"] in NON_TEXT]) is None


def test_fetch_models_uses_bearer_key(gateway):
    models = fetch_models(config_for(gateway))
    assert [m["id"] for m in models] == [m["id"] for m in CATALOGUE]
    method, path, headers, _ = gateway.requests[0]
    assert method == "GET" and path == "/v1/models"
    assert headers["Authorization"] == f"Bearer {FAKE_KEY}"


def test_fetch_models_rejects_unexpected_shape():
    gw = FakeGateway()
    gw.raw_payload = {"models": "not-a-list"}
    try:
        with pytest.raises(OrcaRouterError):
            fetch_models(config_for(gw))
    finally:
        gw.close()

    gw2 = FakeGateway()
    gw2.raw_payload = {"object": "data_list"}   # 200, but no model list
    try:
        with pytest.raises(OrcaRouterError):
            fetch_models(config_for(gw2))
    finally:
        gw2.close()


# --- verdict parsing -------------------------------------------------------

@pytest.mark.parametrize("content,expected", [
    ('{"block": true}', True), ('{"block": false}', False),
    ('```json\n{"block": true}\n```', True), (' verdict: {"block":false} ', False),
])
def test_parse_verdict(content, expected):
    assert parse_verdict(content) is expected


@pytest.mark.parametrize("content", ["yes", "", '{"block": maybe}', None])
def test_unparseable_verdict_fails_closed_as_error(content):
    with pytest.raises(OrcaRouterError):
        parse_verdict(content)


# --- the detector over the fake gateway -----------------------------------

def test_detector_posts_chat_completion_and_returns_verdict(gateway):
    d = OrcaRouterDetector(config_for(gateway))
    assert d.check(CALL) is True
    method, path, headers, raw = gateway.requests[-1]
    assert (method, path) == ("POST", "/v1/chat/completions")
    assert headers["Authorization"] == f"Bearer {FAKE_KEY}"
    body = json.loads(raw)
    assert body["model"] == "orcarouter/auto"   # resolved from the catalogue, not guessed
    assert body["temperature"] == 0
    assert body["messages"][-1]["content"] == CALL.as_text()
    assert FAKE_KEY not in raw.decode()


def test_detector_honours_explicit_model(gateway):
    d = OrcaRouterDetector(config_for(gateway, model="anthropic/claude-opus-4.8"))
    gateway.verdict = '{"block": false}'
    assert d.check(CALL) is False
    assert json.loads(gateway.requests[-1][3])["model"] == "anthropic/claude-opus-4.8"


def test_detector_auth_error_is_explicit_and_safe():
    gw = FakeGateway()
    try:
        d = OrcaRouterDetector(OrcaRouterConfig(base=gw.base,
                                                credentials=fake_creds("sk-orca-wrong"),
                                                model="orcarouter/auto"))
        with pytest.raises(OrcaRouterError) as e:
            d.check(CALL)
        assert "authentication failed" in str(e.value) and "401" in str(e.value)
        assert "sk-orca-wrong" not in str(e.value)
    finally:
        gw.close()


def test_detector_network_failure_is_clear():
    gw = FakeGateway()
    base = gw.base
    gw.close()
    d = OrcaRouterDetector(OrcaRouterConfig(base=base, credentials=fake_creds(),
                                            model="orcarouter/auto"))
    with pytest.raises(OrcaRouterError) as e:
        d.check(CALL)
    assert "unreachable" in str(e.value)


def test_detector_not_in_default_free_run():
    assert "orcarouter" not in [d.name for d in DETECTORS]
    assert OrcaRouterDetector.name == "orcarouter"


def test_model_scope_denial_is_not_reported_as_bad_key():
    gw = FakeGateway()
    gw.status = 403
    gw.verdict = None
    gw.error_body = {"error": {"code": "model_access_denied", "message": "no access"}}
    try:
        d = OrcaRouterDetector(config_for(gw, model="orcarouter/auto"))
        with pytest.raises(OrcaRouterError) as e:
            d.check(CALL)
        assert "model_access_denied" in str(e.value)
        assert "authentication failed" not in str(e.value)
    finally:
        gw.close()


# --- benchmark wiring: bench/run.py --------------------------------------

def _load_run():
    import importlib
    import run
    return importlib.reload(run)


def test_run_py_scores_orcarouter_via_its_provider(gateway, monkeypatch):
    monkeypatch.setenv("ORCAROUTER_API_KEY", FAKE_KEY)
    monkeypatch.setenv("ORCAROUTER_BASE_URL", gateway.base)
    monkeypatch.setenv("ORCAROUTER_MODEL", "orcarouter/auto")
    run = _load_run()
    monkeypatch.setattr(sys, "argv", ["run.py", "--detector", "orcarouter"])
    run.main()
    posts = [r for r in gateway.requests if r[0] == "POST"]
    assert len(posts) == 16          # the built-in 16-case sample
    assert all(r[1] == "/v1/chat/completions" for r in posts)


def test_run_py_lists_chat_models_from_catalogue(gateway, monkeypatch, capsys):
    monkeypatch.setenv("ORCAROUTER_API_KEY", FAKE_KEY)
    monkeypatch.setenv("ORCAROUTER_BASE_URL", gateway.base)
    run = _load_run()
    monkeypatch.setattr(sys, "argv", ["run.py", "--list-orcarouter-models"])
    run.main()
    out = capsys.readouterr().out
    assert "openai/gpt-5.5" in out and "orcarouter/auto" in out
    assert "openai/gpt-image-1" not in out and "jina/jina-reranker-v3" not in out
    assert f"{len(CATALOGUE)} models, {len(CATALOGUE) - len(NON_TEXT)} text-chat" in out
    assert FAKE_KEY not in out
