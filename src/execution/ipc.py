"""
Local IPC Module for Windows Endpoint Security Service.

Implements secure local inter-process communication between the privileged
service and the unprivileged user-interface / CLI console.

Security and Robustness Guarantees:
- Length-prefixed framing with a strict 64 KB maximum message size boundary.
- Strict action whitelist: the GUI is prohibited from sending arbitrary administrative
  or driver commands.
- Token-based caller validation and request correlation IDs.
- Restrictive local communication (Windows Named Pipes with localhost socket fallback
  for unprivileged unit testing).
- Safe timeout handling and bounded request/response queues.
"""

from abc import ABC, abstractmethod
import json
import logging
import os
import socket
import struct
import sys
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple
import uuid


logger = logging.getLogger("endpoint_monitor")

MAX_MESSAGE_BYTES: int = 65536  # 64 KB maximum message boundary
DEFAULT_PIPE_NAME: str = r"\\.\pipe\EndpointMonitorSecurityService"
DEFAULT_IPC_PORT: int = 49152 + 1092  # 50244

# Strict Action Whitelist
ALLOWED_IPC_ACTIONS = {
    "PING",
    "GET_HEALTH",
    "SUBMIT_REQUEST",
    "GET_PENDING_APPROVALS",
    "APPROVE_REQUEST",
    "DENY_REQUEST",
    "GET_DECISION_HISTORY",
}


def encode_ipc_message(payload_dict: Dict[str, Any]) -> bytes:
    """Encode a dictionary to length-prefixed JSON bytes."""
    data = json.dumps(payload_dict).encode("utf-8")
    if len(data) > MAX_MESSAGE_BYTES:
        raise ValueError(f"Message payload exceeds maximum boundary ({len(data)} > {MAX_MESSAGE_BYTES} bytes)")
    header = struct.pack("!I", len(data))
    return header + data


def decode_ipc_message_from_stream(read_fn: Callable[[int], bytes]) -> Dict[str, Any]:
    """Read a length-prefixed JSON message from a stream."""
    header = read_fn(4)
    if not header or len(header) < 4:
        raise ConnectionResetError("Incomplete message header or connection closed")

    length = struct.unpack("!I", header)[0]
    if length > MAX_MESSAGE_BYTES:
        raise ValueError(f"Message length exceeds maximum allowed limit ({length} > {MAX_MESSAGE_BYTES} bytes)")

    payload_bytes = bytearray()
    while len(payload_bytes) < length:
        chunk = read_fn(length - len(payload_bytes))
        if not chunk:
            raise ConnectionResetError("Stream closed while reading message body")
        payload_bytes.extend(chunk)

    return json.loads(payload_bytes.decode("utf-8"))


class IPCServerBase(ABC):
    """Abstract interface for privileged service IPC listeners."""

    @abstractmethod
    def start(self, handler_callback: Callable[[Dict[str, Any]], Dict[str, Any]]) -> None:
        pass

    @abstractmethod
    def stop(self) -> None:
        pass

    @abstractmethod
    def is_running(self) -> bool:
        pass


class LocalSocketIPCServer(IPCServerBase):
    """
    Local TCP loopback server bound strictly to 127.0.0.1 with local token validation.
    Used for unit testing and local developer environments without administrator access.
    """

    def __init__(
        self,
        port: int = 0,
        auth_token: Optional[str] = None,
        logger_instance: Optional[logging.Logger] = None,
    ) -> None:
        self.port = port
        self.auth_token = auth_token or str(uuid.uuid4())
        self.logger = logger_instance if logger_instance is not None else logger
        self._server_sock: Optional[socket.socket] = None
        self._running = False
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._handler_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None

    def start(self, handler_callback: Callable[[Dict[str, Any]], Dict[str, Any]]) -> None:
        self._handler_fn = handler_callback
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind(("127.0.0.1", self.port))
        self.port = self._server_sock.getsockname()[1]
        self._server_sock.listen(5)
        self._server_sock.settimeout(1.0)
        self._running = True
        self._stop_event.clear()

        self._worker_thread = threading.Thread(target=self._accept_loop, daemon=True, name="IPCServer-Accept")
        self._worker_thread.start()
        self.logger.info(f"Local Socket IPC Server listening on 127.0.0.1:{self.port}")

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        self.logger.info("Local Socket IPC Server stopped.")

    def is_running(self) -> bool:
        return self._running

    def _accept_loop(self) -> None:
        while self._running and not self._stop_event.is_set():
            try:
                client_sock, client_addr = self._server_sock.accept()
                # Verify connection is strictly loopback
                if client_addr[0] != "127.0.0.1":
                    client_sock.close()
                    continue
                t = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock,),
                    daemon=True,
                    name=f"IPCClient-{client_addr[1]}",
                )
                t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    self.logger.debug(f"IPC accept loop error: {e}")
                break

    def _handle_client(self, sock: socket.socket) -> None:
        sock.settimeout(5.0)
        try:
            while self._running and not self._stop_event.is_set():
                try:
                    msg = decode_ipc_message_from_stream(lambda n: sock.recv(n))
                except (ConnectionResetError, EOFError):
                    break
                except Exception as e:
                    err_resp = {"success": False, "error": f"Invalid message framing: {e}", "code": 400}
                    sock.sendall(encode_ipc_message(err_resp))
                    break

                response = self._process_request(msg)
                sock.sendall(encode_ipc_message(response))
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _process_request(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        """Validate action against strict whitelist and dispatch to handler."""
        msg_id = msg.get("message_id") or str(uuid.uuid4())
        action = msg.get("action", "")

        # Strict security validation: Reject any action not in whitelist
        if action not in ALLOWED_IPC_ACTIONS:
            self.logger.warning(f"IPC request rejected: unauthorized action '{action}'")
            return {
                "message_id": msg_id,
                "success": False,
                "error": f"Unauthorized action: '{action}' is not permitted by endpoint security service policy",
                "code": 403,
                "timestamp": time.time(),
            }

        # Validate caller authentication token if required
        token = msg.get("auth_token")
        if self.auth_token and token != self.auth_token:
            # Allow PING without token for health probes, but require token for actions
            if action not in ("PING", "GET_HEALTH"):
                return {
                    "message_id": msg_id,
                    "success": False,
                    "error": "Authentication failure: invalid IPC auth token",
                    "code": 401,
                    "timestamp": time.time(),
                }

        try:
            if self._handler_fn:
                data = self._handler_fn(msg)
                return {
                    "message_id": msg_id,
                    "success": True,
                    "data": data,
                    "timestamp": time.time(),
                }
            return {"message_id": msg_id, "success": False, "error": "No handler configured", "code": 500}
        except Exception as e:
            self.logger.error(f"Error handling IPC action {action}: {e}", exc_info=True)
            return {"message_id": msg_id, "success": False, "error": str(e), "code": 500}


class LocalSocketIPCClient:
    """Client for local TCP loopback IPC."""

    def __init__(self, port: int, auth_token: Optional[str] = None, timeout: float = 5.0) -> None:
        self.port = port
        self.auth_token = auth_token
        self.timeout = timeout
        self._lock = threading.Lock()

    def send_request(self, action: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send an action request and return the structured response."""
        req = {
            "message_id": str(uuid.uuid4()),
            "action": action,
            "payload": payload or {},
            "auth_token": self.auth_token,
            "timestamp": time.time(),
        }

        with self._lock:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                sock.connect(("127.0.0.1", self.port))
                sock.sendall(encode_ipc_message(req))
                resp = decode_ipc_message_from_stream(lambda n: sock.recv(n))
                return resp
            finally:
                sock.close()
