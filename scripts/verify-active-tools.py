"""Opt-in installed-Burp checks. Requires Python 3.11+ and websockets 16; sends only loopback traffic."""
import argparse
import base64
import contextlib
import http.client
import http.server
import json
import os
from pathlib import Path
import threading
import time
import urllib.parse

from websockets.sync.server import serve
from websockets.exceptions import ConnectionClosed


class McpClient:
    def __init__(self, port):
        self.port = port
        self.counter = 0
        self.stream = http.client.HTTPConnection("127.0.0.1", port, timeout=35)
        self.stream.request("GET", "/sse", headers={"Accept": "text/event-stream"})
        self.response = self.stream.getresponse()
        if self.response.status != 200:
            raise RuntimeError(f"Local MCP SSE HTTP {self.response.status}; enable local-mode MCP first")
        kind, endpoint = self.event()
        parsed = urllib.parse.urlsplit(endpoint)
        if kind != "endpoint" or parsed.netloc or not parsed.path.startswith("/message"):
            raise RuntimeError("Unexpected local MCP session endpoint")
        self.endpoint = endpoint
        self.info = self.rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "isolated-active-tools-check", "version": "1"}})
        self.rpc("notifications/initialized", {}, notification=True)

    def event(self):
        kind, data = "", []
        for _ in range(10000):
            raw = self.response.readline()
            if not raw:
                raise RuntimeError("MCP stream closed")
            line = raw.decode("utf-8").rstrip("\r\n")
            if not line:
                if data:
                    return kind, "\n".join(data)
                continue
            if line.startswith("event:"):
                kind = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].lstrip())
        raise RuntimeError("MCP event limit reached")

    def rpc(self, method, params, notification=False):
        self.counter += 1
        value = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notification:
            value["id"] = self.counter
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=35)
        try:
            connection.request("POST", self.endpoint, body=json.dumps(value).encode(), headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            response.read()
            if response.status not in (200, 202, 204):
                raise RuntimeError(f"MCP post HTTP {response.status}")
        finally:
            connection.close()
        if notification:
            return None
        for _ in range(100):
            _, data = self.event()
            reply = json.loads(data)
            if reply.get("id") == self.counter:
                if "error" in reply:
                    raise RuntimeError(str(reply["error"]))
                return reply["result"]
        raise RuntimeError("MCP reply missing")

    def call(self, name, arguments, expect_error=False):
        result = self.rpc("tools/call", {"name": name, "arguments": arguments})
        text = "\n".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
        failed = result.get("isError") is True
        if failed != expect_error:
            raise AssertionError(f"{name}: unexpected error={failed}: {text[:300]}")
        return text if expect_error else json.loads(text)

    def close(self):
        self.stream.close()


@contextlib.contextmanager
def fixtures():
    captured = {"http": [], "wsText": [], "wsBinary": [], "wsHeaders": [], "postBodies": []}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            captured["http"].append(self.path)
            body = json.dumps({"path": self.path}, ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            captured["http"].append(self.path)
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            captured["postBodies"].append(body.decode("utf-8"))
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    def echo(connection):
        captured["wsHeaders"].append(connection.request.headers.get("X-Nim-Fixture"))
        try:
            for message in connection:
                captured["wsBinary" if isinstance(message, bytes) else "wsText"].append(message)
                connection.send(message)
        except ConnectionClosed:
            # Montoya may close TCP directly without a WebSocket close frame.
            pass

    http_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    websocket_server = serve(echo, "127.0.0.1", 0, compression=None, ping_interval=None)
    threads = [threading.Thread(target=http_server.serve_forever, daemon=True), threading.Thread(target=websocket_server.serve_forever, daemon=True)]
    for thread in threads:
        thread.start()
    try:
        yield {"httpPort": http_server.server_port, "webSocketPort": websocket_server.socket.getsockname()[1], "pid": os.getpid()}, captured
    finally:
        websocket_server.shutdown()
        http_server.shutdown()
        http_server.server_close()
        for thread in threads:
            thread.join(timeout=3)


def verify(client, ports, captured):
    required = {"intruder_attack_start", "intruder_attack_status", "intruder_attack_results", "intruder_attack_cancel", "websocket_open", "websocket_send", "websocket_receive", "websocket_close", "websocket_connections"}
    tools = client.rpc("tools/list", {}).get("tools", [])
    assert required <= {t["name"] for t in tools}
    cases = []
    for mode, expected in [("SNIPER", 5), ("PITCHFORK", 3), ("CLUSTER_BOMB", 5), ("BATTERING_RAM", 3)]:
        arguments = {
            "content": "GET /case?a={{a}}&b={{b}} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            "targetHostname": "127.0.0.1", "targetPort": ports["httpPort"], "usesHttps": False,
            "positions": [{"marker": "{{a}}", "baseValue": "base-a", "payloads": ["one", "two"]}, {"marker": "{{b}}", "baseValue": "base-b", "payloads": ["red", "blue"]}],
            "mode": mode, "maxRequests": 10, "concurrency": 2, "intervalMs": 20,
        }
        if mode == "BATTERING_RAM":
            arguments["positions"][1]["payloads"] = ["one", "two"]
        before = len(captured["http"])
        identifier = client.call("intruder_attack_start", arguments)["attackId"]
        until = time.monotonic() + 20
        while True:
            status = client.call("intruder_attack_status", {"attackId": identifier})
            if status["inFlightWorkers"] == 0:
                break
            assert time.monotonic() < until
            time.sleep(0.05)
        assert status["completed"] == expected and status["failed"] == 0, status
        assert len(captured["http"]) - before == expected
        result = client.call("intruder_attack_results", {"attackId": identifier, "count": 100, "includeMessages": True})
        assert len(result["results"]) == expected and not result["pendingIndices"]
        assert all(row["statusCode"] == 200 and len(row["responseSha256"]) == 64 for row in result["results"])
        assert len({row["responseSha256"] for row in result["results"]}) == expected
        client.call("intruder_attack_cancel", {"attackId": identifier})
        cases.append({"mode": mode, "observedRequests": expected, "state": status["state"]})
    invalid = dict(arguments, maxRequests=1)
    before = len(captured["http"])
    client.call("intruder_attack_start", invalid, expect_error=True)
    assert len(captured["http"]) == before
    malformed = dict(arguments, content=arguments["content"].replace("\r\n", "\\r\\n"))
    error = client.call("intruder_attack_start", malformed, expect_error=True)
    assert "real line breaks" in error and len(captured["http"]) == before
    header_only = dict(arguments, content=arguments["content"].rstrip("\r\n"))
    header_id = client.call("intruder_attack_start", header_only)["attackId"]
    until = time.monotonic() + 10
    while client.call("intruder_attack_status", {"attackId": header_id})["inFlightWorkers"]:
        assert time.monotonic() < until
        time.sleep(0.05)
    assert len(captured["http"]) - before == 3
    assert client.call("intruder_attack_status", {"attackId": header_id})["failed"] == 0
    identifier = client.call("intruder_attack_start", dict(arguments, intervalMs=1000))["attackId"]
    client.call("intruder_attack_cancel", {"attackId": identifier})
    until = time.monotonic() + 5
    while client.call("intruder_attack_status", {"attackId": identifier})["inFlightWorkers"]:
        assert time.monotonic() < until
        time.sleep(0.05)
    post_args = {
        "content": "POST /unicode HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: 999\r\n\r\n{\"value\":\"{{value}}\"}",
        "targetHostname": "127.0.0.1", "targetPort": ports["httpPort"], "usesHttps": False,
        "positions": [{"marker": "{{value}}", "baseValue": "base", "payloads": ["ёж", "plain"]}], "maxRequests": 3, "intervalMs": 0,
    }
    post_id = client.call("intruder_attack_start", post_args)["attackId"]
    until = time.monotonic() + 10
    while client.call("intruder_attack_status", {"attackId": post_id})["inFlightWorkers"]:
        assert time.monotonic() < until
        time.sleep(0.05)
    assert '{"value":"ёж"}' in captured["postBodies"]
    connection_id = client.call("websocket_open", {"targetHostname": "127.0.0.1", "targetPort": ports["webSocketPort"], "usesHttps": False, "path": "/echo"})["connectionId"]
    try:
        client.call("websocket_send", {"connectionId": connection_id, "text": "nim18-local-echo-ёж"})
        client.call("websocket_send", {"connectionId": connection_id, "base64": base64.b64encode(b"\x00\x01\xff").decode()})
        frames, cursor, until = [], 0, time.monotonic() + 10
        while len([f for f in frames if f["direction"] == "INBOUND"]) < 2:
            page = client.call("websocket_receive", {"connectionId": connection_id, "afterSequence": cursor, "count": 20, "waitMs": 1000})
            frames.extend(page["messages"])
            cursor = page["nextSequence"]
            assert time.monotonic() < until
        assert captured["wsText"] == ["nim18-local-echo-ёж"] and captured["wsBinary"] == [b"\x00\x01\xff"], {"text":captured["wsText"], "binary":[v.hex() for v in captured["wsBinary"]], "frames":frames}
        assert any(f.get("text") == "nim18-local-echo-ёж" and f["direction"] == "INBOUND" for f in frames)
        assert any(c["connectionId"] == connection_id for c in client.call("websocket_connections", {}))
        client.call("websocket_send", {"connectionId": connection_id, "text": "x", "base64": "eA=="}, expect_error=True)
    finally:
        client.call("websocket_close", {"connectionId": connection_id})
    state = client.call("websocket_receive", {"connectionId": connection_id})["connection"]["state"]
    assert state == "CLOSED"
    custom_request = f"GET /echo HTTP/1.1\r\nHost: 127.0.0.1:{ports['webSocketPort']}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nX-Nim-Fixture: custom-upgrade\r\n\r\n"
    custom_id = client.call("websocket_open", {"targetHostname": "127.0.0.1", "targetPort": ports["webSocketPort"], "usesHttps": False, "content": custom_request})["connectionId"]
    client.call("websocket_close", {"connectionId": custom_id})
    assert "custom-upgrade" in captured["wsHeaders"]
    client.call("websocket_open", {"targetHostname": "127.0.0.1", "targetPort": ports["httpPort"], "usesHttps": False, "path": "/not-an-upgrade"}, expect_error=True)
    client.call("websocket_send", {"connectionId": connection_id, "text": "after-close"}, expect_error=True)
    return {"server": client.info["serverInfo"], "discoveredTools": len(tools), "newToolsCovered": sorted(required), "payloadCases": cases, "invalidPlanSentNoTraffic": True, "malformedTemplateSentNoTraffic": True, "headerOnlyTemplateRepaired": True, "cancellationCompleted": True, "webSocketTextEcho": True, "webSocketBinaryEcho": True, "webSocketClosed": True, "webSocketCustomHandshake": True, "nonUpgradeRejected": True, "sendAfterCloseRejected": True, "utf8PostBody": True, "targets": "isolated loopback fixtures only"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mcp-port", type=int, default=9876)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--serve-only", action="store_true")
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    with fixtures() as (ports, captured):
        if args.manifest:
            args.manifest.write_text(json.dumps(ports, indent=2) + "\n", encoding="utf-8")
        if args.serve_only:
            print(json.dumps(ports), flush=True)
            while True:
                time.sleep(1)
        client = McpClient(args.mcp_port)
        try:
            report = verify(client, ports, captured)
        finally:
            client.close()
        if args.report:
            args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
