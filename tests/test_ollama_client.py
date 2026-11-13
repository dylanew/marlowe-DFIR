import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from marlowe.assistant import OllamaClient, OllamaError


class _Handler(BaseHTTPRequestHandler):
    received = []

    def log_message(self, *args):
        pass

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/tags":
            self._send(200, {"models": [{"name": "llama3.1:8b"}]})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _Handler.received.append(body)
        if body["model"] == "slow":
            time.sleep(1)
        if body["model"] == "missing":
            self._send(404, {"error": "model 'missing' not found"})
            return
        self._send(
            200,
            {
                "model": body["model"],
                "message": {"role": "assistant", "content": "hello"},
                "done": True,
                "eval_count": 3,
            },
        )


@pytest.fixture
def server():
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()


def test_list_models(server):
    assert OllamaClient(base_url=server).list_models() == ["llama3.1:8b"]


def test_chat_request_shape(server):
    client = OllamaClient(model="llama3.1:8b", base_url=server)
    tools = [{"type": "function", "function": {"name": "x", "parameters": {}}}]
    msg = client.chat([{"role": "user", "content": "hi"}], tools=tools)
    assert msg["content"] == "hello"
    assert msg["_metrics"]["eval_count"] == 3
    sent = _Handler.received[-1]
    assert sent["stream"] is False
    assert sent["tools"] == tools
    assert sent["options"]["temperature"] == 0.0
    assert sent["options"]["num_predict"] == 1024  # a runaway reply ends instead of hanging


def test_timeout_is_a_readable_ollama_error(server):
    with pytest.raises(OllamaError, match="timed out.*0.2 s"):
        OllamaClient(model="slow", base_url=server, timeout=0.2).chat([])


def test_http_error_is_readable(server):
    with pytest.raises(OllamaError, match="not found"):
        OllamaClient(model="missing", base_url=server).chat([])


def test_unreachable_server():
    with pytest.raises(OllamaError, match="Is it running"):
        OllamaClient(base_url="http://127.0.0.1:9", timeout=2).list_models()


def test_host_without_scheme():
    assert OllamaClient(base_url="localhost:11434").base_url == "http://localhost:11434"


class _ScriptedOllama(BaseHTTPRequestHandler):
    """A fake Ollama that first asks for a tool, then answers citing a line it was given."""

    def log_message(self, *args):
        pass

    def _send(self, payload):
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send({"models": [{"name": "fake:1b"}]})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        tool_msgs = [m for m in body["messages"] if m["role"] == "tool"]
        if not tool_msgs:
            message = {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"function": {"name": "get_log_lines", "arguments": {"start_line": 3}}}
                ],
            }
        else:
            message = {"role": "assistant", "content": "The backup account logged in [line 3]."}
        self._send({"model": body["model"], "message": message, "done": True})


def test_cli_chat_end_to_end(tmp_path, capsys):
    from marlowe.cli import main

    httpd = HTTPServer(("127.0.0.1", 0), _ScriptedOllama)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        main(["generate", "--out", str(tmp_path)])
        main(
            [
                "chat",
                str(tmp_path / "auth.log"),
                "--year",
                "2026",
                "--model",
                "fake:1b",
                "--ollama-url",
                f"http://127.0.0.1:{httpd.server_port}",
                "--manifest",
                str(tmp_path / "m.jsonl"),
                "--audit",
                str(tmp_path / "audit.jsonl"),
                "-q",
                "Who logged in first?",
            ]
        )
    finally:
        httpd.shutdown()
    out = capsys.readouterr().out
    assert "The backup account logged in [line 3]." in out
    assert "get_log_lines" in out
    assert "Grounding check passed" in out
    assert (tmp_path / "audit.jsonl").exists()


def test_cli_chat_reports_missing_model(tmp_path):
    from marlowe.cli import main

    httpd = HTTPServer(("127.0.0.1", 0), _ScriptedOllama)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with pytest.raises(SystemExit, match="ollama pull nope"):
            main(
                [
                    "chat",
                    "unused.log",
                    "--year",
                    "2026",
                    "--model",
                    "nope",
                    "--ollama-url",
                    f"http://127.0.0.1:{httpd.server_port}",
                ]
            )
    finally:
        httpd.shutdown()
